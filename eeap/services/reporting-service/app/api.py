from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.service import get_engine

router = APIRouter(tags=["Reports"])


@router.get("/reports/templates")
async def templates(_: Principal = Depends(require_permission("reports:read")),
                    engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT template_id, version, report_type, name, formats, enabled "
                                       "FROM reporting.report_templates ORDER BY template_id, version"))
        return [dict(r) for r in rows.mappings()]


@router.get("/reports")
async def list_reports(limit: int = Query(50, ge=1, le=500),
                       _: Principal = Depends(require_permission("reports:read")),
                       engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT report_id, report_type, title, formats, status, snapshot_at, created_at, completed_at "
                 "FROM reporting.reports ORDER BY created_at DESC LIMIT :limit"),
            {"limit": limit},
        )
        return {"items": [dict(r) for r in rows.mappings()], "next_cursor": None}
