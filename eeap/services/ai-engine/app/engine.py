"""Read-model maintenance and score recomputation for the AI Engine."""
from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from eeap_shared.utils.events import enqueue_event, new_envelope

from .config import SCHEMA, settings
from .scenarios import correlate
from .scoring import AssetScore, FindingInputs, ScoreResult, ScoringModel, score_asset, score_finding, \
    score_organization

logger = logging.getLogger("eeap.ai.engine")

DIRTY_CONTROLS = "ai:dirty:controls"
DIRTY_ASSETS = "ai:dirty:assets"
DIRTY_ORG = "ai:dirty:org"
DIRTY_FULL = "ai:dirty:full"
GATING_LIFECYCLE = ("open", "acknowledged", "in_remediation")
GATING_STATUS = ("FAIL", "WARNING")


# ------------------------------------------------------------------------------------------- read model

async def upsert_finding_fact(conn: AsyncConnection, data: dict, occurred_at: datetime) -> bool:
    result = await conn.execute(text("""
        INSERT INTO ai.finding_facts (finding_id, asset_id, control_id, category, severity, status, lifecycle_state,
                                      subject_key, exploitability, privilege_impact, source_occurred_at)
        VALUES (CAST(:finding_id AS uuid), :asset_id, :control_id, :category, :severity, :status, :lifecycle_state,
                :subject_key, :exploitability, :privilege_impact, :occurred_at)
        ON CONFLICT (finding_id) DO UPDATE SET
            severity = EXCLUDED.severity, status = EXCLUDED.status, lifecycle_state = EXCLUDED.lifecycle_state,
            category = EXCLUDED.category, exploitability = EXCLUDED.exploitability,
            privilege_impact = EXCLUDED.privilege_impact, source_occurred_at = EXCLUDED.source_occurred_at,
            updated_at = now()
        WHERE ai.finding_facts.source_occurred_at <= EXCLUDED.source_occurred_at
        RETURNING finding_id"""),
        {**{k: data.get(k) for k in ("finding_id", "asset_id", "control_id", "category", "severity", "status",
                                     "lifecycle_state", "exploitability", "privilege_impact")},
         "subject_key": data.get("subject_key") or "", "occurred_at": occurred_at})
    return result.first() is not None


async def upsert_asset_fact(conn: AsyncConnection, event_type: str, data: dict, occurred_at: datetime) -> bool:
    if event_type == "asset.criticality_changed":
        result = await conn.execute(text(
            "UPDATE ai.asset_facts SET criticality = :c, source_occurred_at = :t, "
            "updated_at = now() WHERE asset_id = :id AND source_occurred_at <= :t "
            "RETURNING asset_id"), {"c": data["new"], "t": occurred_at, "id": data["asset_id"]})
        return result.first() is not None
    if not data.get("criticality") or not data.get("tier"):
        return False
    result = await conn.execute(text("""
        INSERT INTO ai.asset_facts (asset_id, hostname, criticality, tier, environment, owner, source_occurred_at)
        VALUES (:asset_id, :hostname, :criticality, :tier, :environment, :owner, :t)
        ON CONFLICT (asset_id) DO UPDATE SET hostname = EXCLUDED.hostname, criticality = EXCLUDED.criticality,
            tier = EXCLUDED.tier, environment = EXCLUDED.environment, owner = EXCLUDED.owner,
            source_occurred_at = EXCLUDED.source_occurred_at, updated_at = now()
        WHERE ai.asset_facts.source_occurred_at <= EXCLUDED.source_occurred_at
        RETURNING asset_id"""),
        {**{k: data.get(k) for k in ("asset_id", "hostname", "criticality", "tier", "environment", "owner")},
         "t": occurred_at})
    return result.first() is not None


async def replace_graph_facts(conn: AsyncConnection, data: dict) -> bool:
    """Swaps in the graph context of a completed analysis (each analysis covers the whole graph)."""
    await conn.execute(text("DELETE FROM ai.graph_facts"))
    facts = {(f["kind"], f["key"]): f for f in data.get("facts") or [] if f.get("kind") in ("asset", "dn")}
    if facts:
        await conn.execute(text(
            "INSERT INTO ai.graph_facts (subject_kind, subject_key, propagation_score, tier0_reachable, min_hops, "
            "is_tier0, is_privileged, analysis_id) VALUES (:kind, :key, :propagation, :reachable, :hops, :tier0, "
            ":privileged, CAST(:analysis_id AS uuid))"),
            [{"kind": kind, "key": key, "propagation": min(1.0, max(0.0, float(f["propagation_score"]))),
              "reachable": bool(f["tier0_reachable"]), "hops": f.get("min_hops"), "tier0": bool(f["is_tier0"]),
              "privileged": bool(f["is_privileged"]), "analysis_id": data["analysis_id"]}
             for (kind, key), f in facts.items()])
    return True


async def mark_dirty(redis: Redis, *, controls: Iterable[str] = (), assets: Iterable[str] = (),
                     org: bool = True, full: bool = False) -> None:
    pipe = redis.pipeline()
    if full:
        pipe.set(DIRTY_FULL, "1")
    if controls := list(controls):
        pipe.sadd(DIRTY_CONTROLS, *controls)
    if assets := list(assets):
        pipe.sadd(DIRTY_ASSETS, *assets)
    if org:
        pipe.set(DIRTY_ORG, "1")
    await pipe.execute()


# ------------------------------------------------------------------------------------------- persistence

async def active_model(conn: AsyncConnection) -> ScoringModel:
    row = (await conn.execute(text(
        "SELECT model_version, weights FROM ai.scoring_models WHERE is_active"))).first()
    if row is None:
        raise RuntimeError("no active scoring model")
    return ScoringModel(row.model_version, row.weights)


async def store_scores(conn: AsyncConnection, subject_type: str, results: dict[str, ScoreResult],
                       model: ScoringModel, trigger: str) -> int:
    """Writes new current scores where score, rating or factors changed; keeps history rows."""
    if not results:
        return 0
    current = {r.subject_id: (r.score, r.rating, r.factors, r.model_version) for r in await conn.execute(
        text("SELECT subject_id, score, rating, factors, model_version FROM ai.risk_scores "
             "WHERE is_current AND subject_type = :t AND subject_id = ANY(:ids)"),
        {"t": subject_type, "ids": list(results)})}
    changed = [sid for sid, res in results.items()
               if current.get(sid) != (res.score, res.rating, res.factors, model.version)]
    if not changed:
        return 0
    await conn.execute(
        text("UPDATE ai.risk_scores SET is_current = false "
             "WHERE is_current AND subject_type = :t AND subject_id = ANY(:ids)"),
        {"t": subject_type, "ids": changed})
    await conn.execute(
        text("INSERT INTO ai.risk_scores (subject_type, subject_id, score, rating, factors, model_version, "
             "trigger_event) VALUES (:t, :sid, :score, :rating, CAST(:factors AS jsonb), :model, :trigger)"),
        [{"t": subject_type, "sid": sid, "score": results[sid].score, "rating": results[sid].rating,
          "factors": json.dumps(results[sid].factors), "model": model.version, "trigger": trigger}
         for sid in changed])
    return len(changed)


# ------------------------------------------------------------------------------------------- recomputation

@dataclass
class RecomputeStats:
    findings: int = 0
    assets: int = 0
    organization: int | None = None
    scenarios: int | None = None
    changed: dict[str, int] = field(default_factory=dict)


async def _score_findings(conn: AsyncConnection, model: ScoringModel, where: str, params: dict) -> dict:
    # A finding about a directory object (DN subject) takes that object's graph context; anything else takes
    # its asset's. Once an analysis exists, a subject without a fact has no path to Tier 0 (R = 0).
    graph_available = (await conn.execute(text("SELECT EXISTS (SELECT 1 FROM ai.graph_facts)"))).scalar_one()
    rows = (await conn.execute(text(f"""
        WITH breadth AS (
            SELECT control_id, count(*) AS affected FROM ai.finding_facts
            WHERE status = ANY(:gs) AND lifecycle_state = ANY(:gl) GROUP BY control_id)
        SELECT f.finding_id::text AS finding_id, f.asset_id, f.control_id, f.severity, f.status, f.lifecycle_state,
               f.exploitability::float AS exploitability, f.privilege_impact::float AS privilege_impact,
               a.criticality, a.tier, coalesce(b.affected, 0) AS affected,
               CASE WHEN position('dc=' in lower(f.subject_key)) > 0 THEN gd.propagation_score
                    ELSE ga.propagation_score END::float AS propagation,
               coalesce(CASE WHEN position('dc=' in lower(f.subject_key)) > 0 THEN gd.is_tier0 OR gd.is_privileged
                             ELSE ga.is_tier0 OR ga.is_privileged END, false) AS graph_tier0
        FROM ai.finding_facts f
        LEFT JOIN ai.asset_facts a ON a.asset_id = f.asset_id
        LEFT JOIN breadth b ON b.control_id = f.control_id
        LEFT JOIN ai.graph_facts gd ON gd.subject_kind = 'dn' AND gd.subject_key = lower(f.subject_key)
        LEFT JOIN ai.graph_facts ga ON ga.subject_kind = 'asset' AND ga.subject_key = f.asset_id
        WHERE {where}"""), {**params, "gs": list(GATING_STATUS), "gl": list(GATING_LIFECYCLE)})).mappings().all()
    results = {
        r["finding_id"]: score_finding(model, FindingInputs(
            severity=r["severity"], status=r["status"], lifecycle_state=r["lifecycle_state"],
            criticality=r["criticality"], exploitability=r["exploitability"],
            privilege_impact=r["privilege_impact"], affected_count=int(r["affected"]),
            propagation=(r["propagation"] or 0.0) if graph_available else None,
            is_tier0=r["tier"] == "Tier0" or r["graph_tier0"]))
        for r in rows
    }
    return {"results": results, "assets": {r["asset_id"] for r in rows}}


async def recompute(engine: AsyncEngine, redis: Redis, *, full: bool = False, trigger: str = "event") -> RecomputeStats:
    if await redis.getdel(DIRTY_FULL):
        full, trigger = True, "graph"
    controls = [] if full else list(await redis.spop(DIRTY_CONTROLS, 10_000) or [])
    assets = [] if full else list(await redis.spop(DIRTY_ASSETS, 10_000) or [])
    org_dirty = full or bool(await redis.getdel(DIRTY_ORG))
    if not (full or controls or assets or org_dirty):
        return RecomputeStats()
    try:
        return await _recompute(engine, controls, assets, org_dirty, full, trigger)
    except Exception:
        await mark_dirty(redis, controls=controls, assets=assets, org=org_dirty, full=full)
        raise


async def _recompute(engine: AsyncEngine, controls: list[str], assets: list[str], org_dirty: bool, full: bool,
                     trigger: str) -> RecomputeStats:
    stats = RecomputeStats()
    async with engine.begin() as conn:
        model = await active_model(conn)
        if full:
            scored = await _score_findings(conn, model, "TRUE", {})
        else:
            scored = await _score_findings(conn, model, "f.control_id = ANY(:controls) OR f.asset_id = ANY(:assets)",
                                           {"controls": controls, "assets": assets})
        stats.findings = len(scored["results"])
        stats.changed["finding"] = await store_scores(conn, "finding", scored["results"], model, trigger)

        affected_assets = scored["assets"] | set(assets)
        if full:
            affected_assets |= set((await conn.execute(text("SELECT asset_id FROM ai.asset_facts"))).scalars())
        if affected_assets:
            rows = await conn.execute(text("""
                SELECT f.asset_id, s.score FROM ai.finding_facts f
                JOIN ai.risk_scores s ON s.subject_type = 'finding' AND s.subject_id = f.finding_id::text
                     AND s.is_current
                WHERE f.asset_id = ANY(:ids)"""), {"ids": list(affected_assets)})
            per_asset: dict[str, list[int]] = {a: [] for a in affected_assets}
            for r in rows:
                per_asset[r.asset_id].append(r.score)
            asset_results = {a: score_asset(model, s) for a, s in per_asset.items()}
            stats.assets = len(asset_results)
            stats.changed["asset"] = await store_scores(conn, "asset", asset_results, model, trigger)
            org_dirty = org_dirty or bool(stats.changed["asset"])

        if full or org_dirty or stats.changed.get("finding"):
            correlation = await correlate(conn, model, GATING_STATUS, GATING_LIFECYCLE)
            stats.scenarios = correlation.active
            stats.changed["scenario"] = correlation.scores_changed
            org_dirty = True
            if correlation.new or correlation.mitigated:
                await enqueue_event(conn, SCHEMA, "eeap.risk", new_envelope(
                    event_type="correlation.completed", source=settings.service_name, subject="org",
                    data={"active": correlation.active, "new": correlation.new,
                          "mitigated": correlation.mitigated, "trigger": trigger}))

        if org_dirty:
            rows = await conn.execute(text("""
                WITH ids AS (SELECT asset_id FROM ai.asset_facts UNION SELECT DISTINCT asset_id FROM ai.finding_facts)
                SELECT ids.asset_id, coalesce(s.score, 0) AS score, a.criticality, a.tier FROM ids
                LEFT JOIN ai.asset_facts a ON a.asset_id = ids.asset_id
                LEFT JOIN ai.risk_scores s ON s.subject_type = 'asset' AND s.subject_id = ids.asset_id
                     AND s.is_current"""))
            asset_scores = [AssetScore(r.asset_id, r.score, r.criticality, r.tier) for r in rows]
            max_scenario = (await conn.execute(text(
                "SELECT coalesce(max(s.score), 0) FROM ai.risk_scores s JOIN ai.risk_scenarios r "
                "ON s.subject_type = 'scenario' AND s.subject_id = r.scenario_id::text AND s.is_current "
                "WHERE r.status = 'active'"))).scalar_one()
            org = score_organization(model, asset_scores, int(max_scenario))
            stats.organization = org.score
            stats.changed["organization"] = await store_scores(conn, "organization", {"org": org}, model, trigger)

        if any(stats.changed.values()):
            await enqueue_event(conn, SCHEMA, "eeap.risk", new_envelope(
                event_type="risk.scores_updated", source=settings.service_name, subject="org",
                data={"model_version": model.version, "changed": stats.changed,
                      "organization_score": stats.organization, "trigger": trigger}))
    return stats
