"""Persistence of correlated risk scenarios (ai.risk_scenarios, ai.scenario_findings, scenario scores)."""
from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from .correlation import FindingFact, GraphFact, Scenario, evaluate
from .scoring import ScoreResult, ScoringModel


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
    findings = [FindingFact(r.finding_id, r.control_id, r.asset_id, r.subject_key, int(r.score))
                for r in await conn.execute(text("""
        SELECT f.finding_id::text AS finding_id, f.control_id, f.asset_id, f.subject_key,
               coalesce(s.score, 0) AS score
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

    scenarios = evaluate(rules, findings, graph_of, subject_graph)
    scores: dict[str, ScoreResult] = {}
    detected: list[str] = []
    new = 0
    for scenario in scenarios:
        scenario_id, status, inserted = await _upsert(conn, scenario, model.version)
        detected.append(scenario_id)
        new += int(inserted)
        scores[scenario_id] = ScoreResult(scenario.score, model.rating(scenario.score),
                                          {**scenario.factors, "status": status})

    mitigated = [r[0] for r in await conn.execute(text(
        "UPDATE ai.risk_scenarios SET status = 'mitigated', last_evaluated_at = now() "
        "WHERE status = 'active' AND NOT (scenario_id = ANY(CAST(:ids AS uuid[]))) RETURNING scenario_id::text"),
        {"ids": detected})]
    for scenario_id in mitigated:
        scores[scenario_id] = ScoreResult(0, model.rating(0), {"status": "mitigated"})
    changed = await store_scores(conn, "scenario", scores, model, "correlation")
    return CorrelationStats(active=len(detected), new=new, mitigated=len(mitigated), scores_changed=changed)


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
