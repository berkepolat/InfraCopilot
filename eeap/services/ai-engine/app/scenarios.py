"""Persistence of correlated risk scenarios (ai.risk_scenarios, ai.scenario_findings, scenario scores)."""
from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from .correlation import AssetContext, ExposureFact, FindingFact, GraphFact, Scenario, evaluate
from .remediation import ActiveScenario, OpenFinding, Template, build_roadmap
from .scoring import ScoreResult, ScoringModel, network_exposure


@dataclass(frozen=True)
class CorrelationStats:
    active: int
    new: int
    mitigated: int
    scores_changed: int

    @property
    def changed(self) -> bool:
        return bool(self.new or self.mitigated or self.scores_changed)


def _is_dn(subject_key: str) -> bool:
    return "dc=" in (subject_key or "").lower()


async def _load(conn: AsyncConnection, controls: list[str], gating_status, gating_lifecycle):
    findings = [FindingFact(r.finding_id, r.control_id, r.asset_id, r.subject_key, int(r.score),
                            float(r.exploitability), bool(r.known_exploited))
                for r in await conn.execute(text("""
        SELECT f.finding_id::text AS finding_id, f.control_id, f.asset_id, f.subject_key,
               coalesce(s.score, 0) AS score, f.exploitability, f.known_exploited
        FROM ai.finding_facts f
        LEFT JOIN ai.risk_scores s ON s.subject_type = 'finding' AND s.subject_id = f.finding_id::text AND s.is_current
        WHERE f.status = ANY(:gs) AND f.lifecycle_state = ANY(:gl) AND f.control_id = ANY(:controls)"""),
        {"gs": list(gating_status), "gl": list(gating_lifecycle), "controls": controls})]
    facts: dict[tuple[str, str], GraphFact] = {}
    for r in await conn.execute(text(
            "SELECT subject_kind, subject_key, propagation_score::float AS p, tier0_reachable, min_hops, is_tier0, "
            "is_privileged FROM ai.graph_facts")):
        facts[(r.subject_kind, r.subject_key)] = GraphFact(r.p, r.tier0_reachable, r.min_hops, r.is_tier0,
                                                           r.is_privileged)
    return findings, facts


def _exposure_fact(services: list[dict]) -> ExposureFact:
    score, classes = network_exposure(services)
    ordered = sorted(services, key=lambda s: s.get("port") or 0)
    labels = tuple(f"{s.get('port')}/{s.get('service') or '?'}" for s in ordered)
    return ExposureFact(score, tuple(classes), labels)


async def _asset_contexts(conn: AsyncConnection, asset_ids: list[str],
                          facts: dict[tuple[str, str], GraphFact]) -> dict[str, AssetContext]:
    rows = await conn.execute(text("""
        SELECT a.asset_id, coalesce(af.hostname, host(x.ip), a.asset_id) AS label, x.services
        FROM unnest(CAST(:ids AS text[])) AS a(asset_id)
        LEFT JOIN ai.asset_facts af ON af.asset_id = a.asset_id
        LEFT JOIN ai.exposure_facts x ON x.asset_id = a.asset_id"""), {"ids": asset_ids})
    contexts = {}
    for r in rows:
        services = json.loads(r.services) if isinstance(r.services, str) else r.services
        contexts[r.asset_id] = AssetContext(r.label, facts.get(("asset", r.asset_id)),
                                            _exposure_fact(services) if services is not None else None)
    return contexts


async def correlate(conn: AsyncConnection, model: ScoringModel, gating_status, gating_lifecycle) -> CorrelationStats:
    from .engine import store_scores  # engine imports this module

    rules = {r.rule_id: r.definition for r in await conn.execute(text(
        "SELECT rule_id, definition FROM ai.correlation_rules WHERE enabled"))}
    rules = {k: (json.loads(v) if isinstance(v, str) else v) for k, v in rules.items()}
    controls = sorted({c for d in rules.values() for s in d["stages"] for c in s.get("any_failed_controls") or []})
    findings, facts = await _load(conn, controls, gating_status, gating_lifecycle)

    def graph_of(finding: FindingFact) -> GraphFact | None:
        if _is_dn(finding.subject_key):
            return facts.get(("dn", finding.subject_key.lower()))
        return facts.get(("asset", finding.asset_id))

    def subject_graph(subject_key: str) -> GraphFact | None:
        return facts.get(("dn", subject_key.lower())) if _is_dn(subject_key) else None

    contexts: dict[str, AssetContext] = {}
    if any(d.get("scope") == "asset" for d in rules.values()):
        contexts = await _asset_contexts(conn, sorted({f.asset_id for f in findings}), facts)

    def asset_context(asset_id: str) -> AssetContext | None:
        return contexts.get(asset_id)

    scenarios = evaluate(rules, findings, graph_of, subject_graph, asset_context)
    scores: dict[str, ScoreResult] = {}
    detected: list[str] = []
    active: list[ActiveScenario] = []
    new = 0
    for scenario in scenarios:
        scenario_id, status, inserted = await _upsert(conn, scenario, model.version)
        detected.append(scenario_id)
        new += int(inserted)
        scores[scenario_id] = ScoreResult(scenario.score, model.rating(scenario.score),
                                          {**scenario.factors, "status": status})
        if status == "active":
            active.append(ActiveScenario(scenario_id, (scenario.rule_id, scenario.scope_key), scenario.score,
                                         scenario.title))

    rule_controls = set(controls)
    current_keys = {(s.rule_id, s.scope_key) for s in scenarios}

    def still_matching(control_id: str) -> set[tuple[str, str]]:
        if control_id not in rule_controls:
            return current_keys
        remaining = [f for f in findings if f.control_id != control_id]
        return {(s.rule_id, s.scope_key) for s in evaluate(rules, remaining, graph_of, subject_graph, asset_context)}

    await _store_roadmap(conn, gating_status, gating_lifecycle, active, still_matching)

    mitigated = [r[0] for r in await conn.execute(text(
        "UPDATE ai.risk_scenarios SET status = 'mitigated', last_evaluated_at = now() "
        "WHERE status = 'active' AND NOT (scenario_id = ANY(CAST(:ids AS uuid[]))) RETURNING scenario_id::text"),
        {"ids": detected})]
    for scenario_id in mitigated:
        scores[scenario_id] = ScoreResult(0, model.rating(0), {"status": "mitigated"})
    changed = await store_scores(conn, "scenario", scores, model, "correlation")
    return CorrelationStats(active=len(detected), new=new, mitigated=len(mitigated), scores_changed=changed)


async def _store_roadmap(conn: AsyncConnection, gating_status, gating_lifecycle, active: list[ActiveScenario],
                         still_matching) -> None:
    findings = [OpenFinding(r.finding_id, r.control_id, int(r.score)) for r in await conn.execute(text("""
        SELECT f.finding_id::text AS finding_id, f.control_id, s.score
        FROM ai.finding_facts f
        JOIN ai.risk_scores s ON s.subject_type = 'finding' AND s.subject_id = f.finding_id::text AND s.is_current
        WHERE f.status = ANY(:gs) AND f.lifecycle_state = ANY(:gl) AND s.score > 0"""),
        {"gs": list(gating_status), "gl": list(gating_lifecycle)})]
    templates = {r.control_id: Template(r.title, r.guidance, r.effort) for r in await conn.execute(text(
        "SELECT control_id, title, guidance, effort FROM ai.remediation_templates"))}
    items = build_roadmap(findings, active, templates, still_matching)
    if items:
        await conn.execute(text("""
            INSERT INTO ai.remediation_items (control_id, title, guidance, effort, expected_risk_reduction, priority,
                                              roadmap_phase, generated_by, finding_ids, scenario_ids, rationale)
            VALUES (:control_id, :title, :guidance, :effort, :reduction, :priority, :phase, 'template',
                    CAST(:finding_ids AS uuid[]), CAST(:scenario_ids AS uuid[]), CAST(:rationale AS jsonb))
            ON CONFLICT (control_id) WHERE generated_by = 'template' AND control_id IS NOT NULL DO UPDATE SET
                title = EXCLUDED.title, guidance = EXCLUDED.guidance, effort = EXCLUDED.effort,
                expected_risk_reduction = EXCLUDED.expected_risk_reduction, priority = EXCLUDED.priority,
                roadmap_phase = EXCLUDED.roadmap_phase, finding_ids = EXCLUDED.finding_ids,
                scenario_ids = EXCLUDED.scenario_ids, rationale = EXCLUDED.rationale,
                status = CASE WHEN ai.remediation_items.status = 'done' THEN 'proposed'
                              ELSE ai.remediation_items.status END"""),
            [{"control_id": i.control_id, "title": i.title, "guidance": i.guidance, "effort": i.effort,
              "reduction": i.expected_risk_reduction, "priority": i.priority, "phase": i.roadmap_phase,
              "finding_ids": i.finding_ids, "scenario_ids": i.scenario_ids, "rationale": json.dumps(i.rationale)}
             for i in items])
    # Controls without open risk are done; user decisions (rejected) are kept.
    await conn.execute(text(
        "UPDATE ai.remediation_items SET status = CASE WHEN status = 'rejected' THEN status ELSE 'done' END, "
        "expected_risk_reduction = 0, finding_ids = '{}', scenario_ids = '{}' "
        "WHERE generated_by = 'template' AND control_id IS NOT NULL AND NOT (control_id = ANY(:controls)) "
        "AND cardinality(finding_ids) > 0"),
        {"controls": [i.control_id for i in items]})


async def _upsert(conn: AsyncConnection, scenario: Scenario, model_version: str) -> tuple[str, str, bool]:
    row = (await conn.execute(text("""
        INSERT INTO ai.risk_scenarios (rule_id, scope_key, title, summary, stages, affected_asset_ids, model_version)
        VALUES (:rule_id, :scope_key, :title, :summary, CAST(:stages AS jsonb), :assets, :model)
        ON CONFLICT (rule_id, scope_key) DO UPDATE SET
            title = EXCLUDED.title, summary = EXCLUDED.summary, stages = EXCLUDED.stages,
            affected_asset_ids = EXCLUDED.affected_asset_ids, model_version = EXCLUDED.model_version,
            status = CASE WHEN ai.risk_scenarios.status = 'dismissed' THEN 'dismissed' ELSE 'active' END,
            first_detected_at = CASE WHEN ai.risk_scenarios.status = 'mitigated' THEN now()
                                     ELSE ai.risk_scenarios.first_detected_at END,
            last_evaluated_at = now()
        RETURNING scenario_id::text, status, (xmax = 0) AS inserted"""),
        {"rule_id": scenario.rule_id, "scope_key": scenario.scope_key, "title": scenario.title,
         "summary": scenario.summary, "stages": json.dumps([s.as_dict() for s in scenario.stages]),
         "assets": scenario.affected_asset_ids, "model": model_version})).one()
    await conn.execute(text("DELETE FROM ai.scenario_findings WHERE scenario_id = CAST(:id AS uuid)"),
                       {"id": row.scenario_id})
    pairs = scenario.finding_stages
    if pairs:
        await conn.execute(text(
            "INSERT INTO ai.scenario_findings (scenario_id, finding_id, stage_order) "
            "VALUES (CAST(:id AS uuid), CAST(:finding AS uuid), :stage)"),
            [{"id": row.scenario_id, "finding": f, "stage": s} for f, s in pairs.items()])
    return row.scenario_id, row.status, bool(row.inserted)
