from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.service import get_engine

from .config import settings

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
    return {"exposure_score": dict(org) if org else None, "open_by_rating": by_rating,
            "active_scenarios": scenarios, "scoring_model": settings.scoring_model_version,
            "llm_provider": settings.ai_llm_provider}
