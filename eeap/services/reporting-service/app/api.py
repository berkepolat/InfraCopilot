from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.events import enqueue_event, new_envelope
from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.service import get_engine

from .config import SCHEMA, settings
from .render import CONTENT_TYPES
from .snapshot import SnapshotError, collect, parse_delegation
from .storage import ReportStore, snapshot_key

router = APIRouter(tags=["Reports"])

DELEGATION_HEADER = "x-eeap-delegation"
REPORT_STREAM = "eeap.report"
ReportType = Literal["executive_summary", "technical", "remediation_roadmap", "mitre_mapping"]
ReportFormat = Literal["json", "html", "pdf"]


def get_store(request: Request) -> ReportStore:
    store = getattr(request.app.state, "report_store", None)
    if store is None:
        store = request.app.state.report_store = ReportStore(settings)
    return store


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
            text("SELECT r.report_id, r.report_type, r.title, r.formats, r.status, r.error, r.snapshot_at, "
                 "r.created_at, r.completed_at, r.expires_at, "
                 "coalesce(array_agg(a.format ORDER BY a.format) FILTER (WHERE a.format IS NOT NULL), '{}') "
                 "AS available_formats "
                 "FROM reporting.reports r LEFT JOIN reporting.report_artifacts a USING (report_id) "
                 "GROUP BY r.report_id ORDER BY r.created_at DESC LIMIT :limit"),
            {"limit": limit},
        )
        return {"items": [dict(r) for r in rows.mappings()], "next_cursor": None}


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: ReportType
    formats: list[ReportFormat] = Field(default_factory=lambda: ["html", "pdf"], min_length=1, max_length=3)
    title: str | None = Field(default=None, min_length=1, max_length=200)


@router.post("/reports", status_code=202)
async def create_report(payload: ReportRequest, request: Request,
                        principal: Principal = Depends(require_permission("reports:create")),
                        engine: AsyncEngine = Depends(get_engine),
                        store: ReportStore = Depends(get_store)):
    async with engine.connect() as conn:
        template = (await conn.execute(text(
            "SELECT template_id, version, name, formats FROM reporting.report_templates "
            "WHERE report_type = :t AND enabled ORDER BY version DESC LIMIT 1"),
            {"t": payload.report_type})).mappings().first()
    if template is None:
        raise HTTPException(422, detail=f"no enabled template for {payload.report_type}")
    formats = sorted(set(payload.formats))
    if not set(formats) <= set(template["formats"]):
        raise HTTPException(422, detail=f"{payload.report_type} supports {', '.join(template['formats'])}")

    tokens = parse_delegation(request.headers.get(DELEGATION_HEADER))
    try:
        snapshot = await collect(payload.report_type, tokens, settings.upstream_urls(),
                                 max_findings=settings.report_max_findings,
                                 timeout=settings.upstream_timeout_seconds)
    except SnapshotError as exc:
        raise HTTPException(502, detail=f"could not collect report data: {exc}") from exc

    report_id = str(uuid.uuid4())
    snapshot_at = datetime.now(UTC)
    title = payload.title or template["name"]
    await store.put(snapshot_key(report_id), json.dumps(snapshot, default=str).encode(), "application/json")
    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO reporting.reports (report_id, template_id, template_version, report_type, title, formats, "
            "parameters, snapshot_at, requested_by, expires_at) VALUES (:id, :tid, :tv, :type, :title, :formats, "
            "CAST(:params AS jsonb), :at, :by, :expires)"),
            {"id": report_id, "tid": template["template_id"], "tv": template["version"],
             "type": payload.report_type, "title": title, "formats": formats,
             "params": json.dumps({"omitted": snapshot["omitted"]}), "at": snapshot_at, "by": principal.subject,
             "expires": snapshot_at + timedelta(days=settings.report_retention_days)})
        await enqueue_event(conn, SCHEMA, REPORT_STREAM, new_envelope(
            event_type="report.requested", source=settings.service_name, subject=f"report:{report_id}",
            actor={"type": "user", "id": principal.subject},
            data={"report_id": report_id, "report_type": payload.report_type, "formats": formats}))
    return {"report_id": report_id, "status": "queued", "title": title, "formats": formats,
            "snapshot_at": snapshot_at, "omitted": snapshot["omitted"]}


@router.get("/reports/{report_id}")
async def get_report(report_id: uuid.UUID, _: Principal = Depends(require_permission("reports:read")),
                     engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        row = (await conn.execute(text(
            "SELECT report_id, template_id, template_version, report_type, title, formats, parameters, snapshot_at, "
            "status, requested_by, error, created_at, completed_at, expires_at "
            "FROM reporting.reports WHERE report_id = :id"), {"id": report_id})).mappings().first()
        if row is None:
            raise HTTPException(404, detail="report not found")
        artifacts = await conn.execute(text(
            "SELECT format, sha256, size_bytes, created_at FROM reporting.report_artifacts "
            "WHERE report_id = :id ORDER BY format"), {"id": report_id})
        return {**row, "artifacts": [dict(a) for a in artifacts.mappings()]}


@router.get("/reports/{report_id}/download/{fmt}")
async def download_report(report_id: uuid.UUID, fmt: ReportFormat,
                          _: Principal = Depends(require_permission("reports:read")),
                          engine: AsyncEngine = Depends(get_engine),
                          store: ReportStore = Depends(get_store)):
    async with engine.connect() as conn:
        row = (await conn.execute(text(
            "SELECT r.report_type, r.snapshot_at, r.expires_at, a.object_key, a.sha256 "
            "FROM reporting.reports r JOIN reporting.report_artifacts a USING (report_id) "
            "WHERE r.report_id = :id AND a.format = :fmt"), {"id": report_id, "fmt": fmt})).mappings().first()
    if row is None:
        raise HTTPException(404, detail="report artifact not found")
    if row["expires_at"] and row["expires_at"] < datetime.now(UTC):
        raise HTTPException(410, detail="report expired")
    data = await store.get(row["object_key"])
    filename = f"eeap-{row['report_type'].replace('_', '-')}-{row['snapshot_at']:%Y%m%d-%H%M}.{fmt}"
    # Always an attachment: rendered HTML is never displayed on the application's origin.
    return Response(content=data, media_type=CONTENT_TYPES[fmt],
                    headers={"content-disposition": f'attachment; filename="{filename}"',
                             "etag": f'"{row["sha256"]}"', "cache-control": "private, no-store"})
