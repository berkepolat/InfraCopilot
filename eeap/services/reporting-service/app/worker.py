from __future__ import annotations

import asyncio
import hashlib
import json
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.db import create_engine
from eeap_shared.utils.events import enqueue_event, new_envelope
from eeap_shared.utils.runtime import Subscription
from eeap_shared.utils.settings import ServiceSettings

from .config import SCHEMA, settings
from .render import CONTENT_TYPES, render_html, render_json, render_pdf
from .storage import ReportStore, artifact_key, snapshot_key

logger = logging.getLogger("eeap.reporting.worker")

RENDER_GROUP = "reporting-service.render"
REPORT_STREAM = "eeap.report"


async def render_report(store: ReportStore, report_id: str, row) -> list[tuple[str, str, str, int]]:
    """Renders every requested format from the stored snapshot; returns (format, key, sha256, size)."""
    snapshot = json.loads(await store.get(snapshot_key(report_id)))
    meta = {"report_id": report_id, "title": row.title, "report_type": row.report_type,
            "snapshot_at": row.snapshot_at.isoformat(), "requested_by": row.requested_by,
            "organization": settings.report_organization,
            "scoring_model": (snapshot["data"].get("summary") or {}).get("scoring_model", "n/a"),
            "template": f"{row.template_id} v{row.template_version}"}
    html: str | None = None
    artifacts = []
    for fmt in row.formats:
        if fmt == "json":
            data = render_json(meta, snapshot)
        else:
            html = html or render_html(row.report_type, meta, snapshot)
            data = html.encode() if fmt == "html" else await asyncio.to_thread(render_pdf, html)
        key = artifact_key(report_id, fmt)
        await store.put(key, data, CONTENT_TYPES[fmt])
        artifacts.append((fmt, key, hashlib.sha256(data).hexdigest(), len(data)))
    return artifacts


def render_handler(engine: AsyncEngine, store: ReportStore):
    async def handle(envelope: dict) -> None:
        if envelope["type"] != "report.requested":
            return
        report_id = envelope["data"]["report_id"]
        async with engine.begin() as conn:
            # Claiming queued -> rendering makes redelivery idempotent.
            row = (await conn.execute(text(
                "UPDATE reporting.reports SET status = 'rendering' WHERE report_id = :id AND status = 'queued' "
                "RETURNING report_type, title, formats, snapshot_at, requested_by, template_id, template_version"),
                {"id": report_id})).first()
        if row is None:
            return
        try:
            artifacts = await render_report(store, report_id, row)
        except Exception as exc:
            logger.exception("report rendering failed", extra={"report_id": report_id})
            async with engine.begin() as conn:
                await conn.execute(text(
                    "UPDATE reporting.reports SET status = 'failed', error = :error, completed_at = now() "
                    "WHERE report_id = :id"), {"id": report_id, "error": f"{type(exc).__name__}: {exc}"[:500]})
                await enqueue_event(conn, SCHEMA, REPORT_STREAM, new_envelope(
                    event_type="report.failed", source=settings.service_name, subject=f"report:{report_id}",
                    data={"report_id": report_id}))
            return
        async with engine.begin() as conn:
            await conn.execute(text(
                "INSERT INTO reporting.report_artifacts (report_id, format, bucket, object_key, sha256, size_bytes) "
                "VALUES (:id, :fmt, :bucket, :key, :sha, :size) ON CONFLICT (report_id, format) DO UPDATE SET "
                "object_key = EXCLUDED.object_key, sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes"),
                [{"id": report_id, "fmt": fmt, "bucket": store.bucket, "key": key, "sha": sha, "size": size}
                 for fmt, key, sha, size in artifacts])
            await conn.execute(text(
                "UPDATE reporting.reports SET status = 'completed', completed_at = now() WHERE report_id = :id"),
                {"id": report_id})
            await enqueue_event(conn, SCHEMA, REPORT_STREAM, new_envelope(
                event_type="report.generated", source=settings.service_name, subject=f"report:{report_id}",
                data={"report_id": report_id, "formats": [a[0] for a in artifacts]}))
        logger.info("report rendered", extra={"report_id": report_id, "formats": [a[0] for a in artifacts]})

    return handle


def subscriptions(service_settings: ServiceSettings) -> list[Subscription]:
    engine = create_engine(service_settings, pool_size=3)
    return [Subscription(RENDER_GROUP, [REPORT_STREAM], render_handler(engine, ReportStore(settings)))]
