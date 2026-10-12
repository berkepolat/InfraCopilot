from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.service import get_engine

from .config import settings
from .engine import GATING_LIFECYCLE, GATING_STATUS, mark_dirty

router = APIRouter(tags=["Risk"])

SubjectType = Literal["finding", "asset", "scenario", "owner", "organization"]


@router.get("/risk/scoring-models")
async def scoring_models(_: Principal = Depends(require_permission("risk:read")),
                         engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT model_version, description, weights, is_active, created_at "
                                       "FROM ai.scoring_models ORDER BY created_at"))
        return [dict(r) for r in rows.mappings()]


@router.get("/risk/scores")
async def scores(
    subject_type: SubjectType,
    limit: int = Query(50, ge=1, le=500),
    _: Principal = Depends(require_permission("risk:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT subject_type, subject_id, score, rating, factors, model_version, computed_at "
                 "FROM ai.risk_scores WHERE is_current AND subject_type = :t ORDER BY score DESC LIMIT :limit"),
            {"t": subject_type, "limit": limit},
        )
        return {"items": [dict(r) for r in rows.mappings()], "next_cursor": None}


@router.get("/risk/scores/{subject_type}/{subject_id}/history")
async def score_history(subject_type: SubjectType, subject_id: str, limit: int = Query(50, ge=1, le=500),
                        _: Principal = Depends(require_permission("risk:read")),
                        engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT score, rating, factors, model_version, trigger_event, is_current, computed_at "
                 "FROM ai.risk_scores WHERE subject_type = :t AND subject_id = :id "
                 "ORDER BY computed_at DESC LIMIT :limit"), {"t": subject_type, "id": subject_id, "limit": limit})
        items = [dict(r) for r in rows.mappings()]
    if not items:
        raise HTTPException(404, detail="no scores for this subject")
    return {"items": items}


@router.get("/risk/top-findings")
async def top_findings(limit: int = Query(20, ge=1, le=200), min_score: int = Query(1, ge=0, le=100),
                       _: Principal = Depends(require_permission("risk:read")),
                       engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(text("""
            SELECT s.subject_id AS finding_id, s.score, s.rating, s.factors, s.computed_at,
                   f.asset_id, f.control_id, f.category, f.severity, f.status, f.lifecycle_state, f.subject_key,
                   a.hostname, a.criticality, a.tier
            FROM ai.risk_scores s
            JOIN ai.finding_facts f ON f.finding_id::text = s.subject_id
            LEFT JOIN ai.asset_facts a ON a.asset_id = f.asset_id
            WHERE s.is_current AND s.subject_type = 'finding' AND s.score >= :min
            ORDER BY s.score DESC, s.computed_at DESC LIMIT :limit"""), {"min": min_score, "limit": limit})
        return {"items": [dict(r) for r in rows.mappings()]}


@router.get("/risk/top-assets")
async def top_assets(limit: int = Query(20, ge=1, le=200),
                     _: Principal = Depends(require_permission("risk:read")),
                     engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(text("""
            SELECT s.subject_id AS asset_id, s.score, s.rating, s.factors, s.computed_at,
                   a.hostname, a.criticality, a.tier, a.environment, a.owner
            FROM ai.risk_scores s LEFT JOIN ai.asset_facts a ON a.asset_id = s.subject_id
            WHERE s.is_current AND s.subject_type = 'asset'
            ORDER BY s.score DESC, s.subject_id LIMIT :limit"""), {"limit": limit})
        return {"items": [dict(r) for r in rows.mappings()]}


@router.get("/risk/summary")
async def summary(_: Principal = Depends(require_permission("risk:read")),
                  engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        org = (await conn.execute(
            text("SELECT score, rating, factors, model_version, computed_at FROM ai.risk_scores "
                 "WHERE is_current AND subject_type = 'organization' AND subject_id = 'org'"))).mappings().first()
        distribution = await conn.execute(text(
            "SELECT subject_type, rating, count(*) AS n FROM ai.risk_scores WHERE is_current "
            "AND subject_type IN ('finding', 'asset') AND score > 0 GROUP BY subject_type, rating"))
        by_rating: dict[str, dict[str, int]] = {"finding": {}, "asset": {}}
        for r in distribution:
            by_rating[r.subject_type][r.rating] = r.n
        scenarios = (await conn.execute(
            text("SELECT count(*) FROM ai.risk_scenarios WHERE status = 'active'"))).scalar()
        top = await _scenarios(conn, "active", 5)
    return {"exposure_score": dict(org) if org else None, "open_by_rating": by_rating,
            "active_scenarios": scenarios, "top_scenarios": top,
            "scoring_model": settings.scoring_model_version, "llm_provider": settings.ai_llm_provider}


ScenarioStatus = Literal["active", "mitigated", "dismissed"]

_SCENARIO_COLUMNS = (
    "SELECT r.scenario_id::text AS scenario_id, r.rule_id, r.scope_key, r.title, r.summary, r.stages, "
    "r.affected_asset_ids, r.status, r.first_detected_at, r.last_evaluated_at, "
    "coalesce(s.score, 0) AS score, coalesce(s.rating, 'Low') AS rating, s.factors "
    "FROM ai.risk_scenarios r LEFT JOIN ai.risk_scores s ON s.subject_type = 'scenario' "
    "AND s.subject_id = r.scenario_id::text AND s.is_current ")


async def _scenarios(conn, status: str | None, limit: int) -> list[dict]:
    where = "WHERE r.status = :status " if status else ""
    rows = await conn.execute(text(f"{_SCENARIO_COLUMNS}{where}ORDER BY score DESC, r.first_detected_at LIMIT :limit"),
                              {"status": status, "limit": limit})
    return [dict(r) for r in rows.mappings()]


@router.get("/risk/scenarios")
async def list_scenarios(status: ScenarioStatus | None = "active", limit: int = Query(100, ge=1, le=500),
                         _: Principal = Depends(require_permission("risk:read")),
                         engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        return await _scenarios(conn, status, limit)


async def _scenario(conn, scenario_id: uuid.UUID) -> dict:
    row = (await conn.execute(text(f"{_SCENARIO_COLUMNS}WHERE r.scenario_id = :id"),
                              {"id": scenario_id})).mappings().first()
    if row is None:
        raise HTTPException(404, detail="scenario not found")
    findings = await conn.execute(text("""
        SELECT sf.finding_id::text AS finding_id, sf.stage_order, f.control_id, f.asset_id, f.subject_key,
               f.severity, f.status, f.lifecycle_state, coalesce(s.score, 0) AS score
        FROM ai.scenario_findings sf
        LEFT JOIN ai.finding_facts f ON f.finding_id = sf.finding_id
        LEFT JOIN ai.risk_scores s ON s.subject_type = 'finding' AND s.subject_id = sf.finding_id::text AND s.is_current
        WHERE sf.scenario_id = :id ORDER BY sf.stage_order, score DESC"""), {"id": scenario_id})
    return {**row, "findings": [dict(f) for f in findings.mappings()]}


@router.get("/risk/scenarios/{scenario_id}")
async def get_scenario(scenario_id: uuid.UUID, _: Principal = Depends(require_permission("risk:read")),
                       engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        return await _scenario(conn, scenario_id)


class ScenarioUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["active", "dismissed"]


@router.patch("/risk/scenarios/{scenario_id}")
async def update_scenario(scenario_id: uuid.UUID, payload: ScenarioUpdate, request: Request,
                          _: Principal = Depends(require_permission("risk:manage")),
                          engine: AsyncEngine = Depends(get_engine)):
    async with engine.begin() as conn:
        row = (await conn.execute(text(
            "UPDATE ai.risk_scenarios SET status = :status WHERE scenario_id = :id AND status <> 'mitigated' "
            "RETURNING scenario_id"), {"status": payload.status, "id": scenario_id})).first()
        if row is None:
            exists = (await conn.execute(text("SELECT 1 FROM ai.risk_scenarios WHERE scenario_id = :id"),
                                         {"id": scenario_id})).first()
            raise HTTPException(409 if exists else 404,
                                detail="mitigated scenarios cannot be changed" if exists else "scenario not found")
    # The organization score only counts active scenarios.
    await mark_dirty(request.app.state.redis)
    async with engine.connect() as conn:
        return await _scenario(conn, scenario_id)


RemediationStatus = Literal["proposed", "accepted", "done", "rejected"]

_REMEDIATION_COLUMNS = (
    "SELECT i.item_id::text AS item_id, i.control_id, i.title, i.guidance, i.effort, i.expected_risk_reduction, "
    "i.priority, i.roadmap_phase, i.status, i.generated_by, cardinality(i.finding_ids) AS open_findings, "
    "i.finding_ids::text[] AS finding_ids, i.rationale, i.updated_at, "
    "coalesce((SELECT json_agg(json_build_object('scenario_id', r.scenario_id, 'title', r.title)) "
    "          FROM ai.risk_scenarios r WHERE r.scenario_id = ANY(i.scenario_ids)), '[]'::json) AS scenarios, "
    "coalesce((SELECT json_agg(json_build_object('technique_id', t.technique_id, 'name', t.name) "
    "                          ORDER BY t.technique_id) "
    "          FROM ai.control_technique_map m JOIN ai.mitre_techniques t USING (technique_id) "
    "          WHERE m.control_id = i.control_id), '[]'::json) AS techniques "
    "FROM ai.remediation_items i ")


@router.get("/risk/remediation")
async def remediation_roadmap(status: list[RemediationStatus] | None = Query(None),
                              limit: int = Query(100, ge=1, le=500),
                              _: Principal = Depends(require_permission("risk:read")),
                              engine: AsyncEngine = Depends(get_engine)):
    statuses = status or ["proposed", "accepted"]
    async with engine.connect() as conn:
        rows = await conn.execute(text(
            f"{_REMEDIATION_COLUMNS}WHERE i.status = ANY(:statuses) ORDER BY i.status = 'done', i.priority, "
            "i.control_id LIMIT :limit"), {"statuses": statuses, "limit": limit})
        return {"items": [dict(r) for r in rows.mappings()]}


class RemediationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: RemediationStatus


@router.patch("/risk/remediation/{item_id}")
async def update_remediation(item_id: uuid.UUID, payload: RemediationUpdate,
                             _: Principal = Depends(require_permission("risk:manage")),
                             engine: AsyncEngine = Depends(get_engine)):
    async with engine.begin() as conn:
        row = (await conn.execute(text(
            "UPDATE ai.remediation_items SET status = :status WHERE item_id = :id RETURNING item_id"),
            {"status": payload.status, "id": item_id})).first()
        if row is None:
            raise HTTPException(404, detail="remediation item not found")
        return dict((await conn.execute(text(f"{_REMEDIATION_COLUMNS}WHERE i.item_id = :id"),
                                        {"id": item_id})).mappings().one())


@router.get("/risk/mitre")
async def mitre_coverage(_: Principal = Depends(require_permission("risk:read")),
                         engine: AsyncEngine = Depends(get_engine)):
    """Techniques that open weaknesses may enable (defensive context), with finding counts and top score."""
    async with engine.connect() as conn:
        rows = await conn.execute(text("""
            SELECT t.technique_id, t.name, t.tactics, t.attack_version, t.url,
                   array_agg(DISTINCT m.control_id ORDER BY m.control_id) AS controls,
                   count(DISTINCT f.finding_id) AS open_findings, coalesce(max(s.score), 0) AS max_score
            FROM ai.mitre_techniques t
            JOIN ai.control_technique_map m ON m.technique_id = t.technique_id
            JOIN ai.finding_facts f ON f.control_id = m.control_id
                 AND f.status = ANY(:gs) AND f.lifecycle_state = ANY(:gl)
            JOIN ai.risk_scores s ON s.subject_type = 'finding' AND s.subject_id = f.finding_id::text
                 AND s.is_current AND s.score > 0
            GROUP BY t.technique_id ORDER BY max_score DESC, open_findings DESC, t.technique_id"""),
            {"gs": list(GATING_STATUS), "gl": list(GATING_LIFECYCLE)})
        techniques = [dict(r) for r in rows.mappings()]
    tactics: dict[str, dict] = {}
    for t in techniques:
        for tactic in t["tactics"]:
            entry = tactics.setdefault(tactic, {"tactic": tactic, "techniques": 0, "open_findings": 0, "max_score": 0})
            entry["techniques"] += 1
            entry["open_findings"] += t["open_findings"]
            entry["max_score"] = max(entry["max_score"], t["max_score"])
    return {"techniques": techniques,
            "tactics": sorted(tactics.values(), key=lambda e: (-e["max_score"], e["tactic"]))}
