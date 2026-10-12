from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.db import create_engine
from eeap_shared.utils.events import enqueue_event, log_only_handler, mark_processed, new_envelope
from eeap_shared.utils.runtime import Subscription
from eeap_shared.utils.settings import ServiceSettings

from . import vuln_feeds
from .config import SCHEMA, AssessmentSettings
from .domain import ImportFormatError, parse_import
from .findings_repo import get_finding, load_controls, set_lifecycle, upsert_observations
from .orchestrator import ORCHESTRATOR_GROUP, run_handler
from .storage import ObjectStore

logger = logging.getLogger("eeap.assessment.worker")

IMPORTS_GROUP = "assessment-service.imports"
ACCEPTANCE_EXPIRY_INTERVAL_SECONDS = 60


async def _fail_import(engine: AsyncEngine, import_id: str, run_id: str, error: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE assessment.imports SET status = 'failed', error = :e, completed_at = now() "
                                "WHERE import_id = CAST(:id AS uuid)"), {"e": error[:2000], "id": import_id})
        await conn.execute(text("UPDATE assessment.assessment_runs SET status = 'failed', completed_at = now(), "
                                "stats = CAST(:s AS jsonb) WHERE run_id = CAST(:r AS uuid)"),
                           {"s": json.dumps({"error": error[:500]}), "r": run_id})
    logger.warning("import failed", extra={"import_id": import_id, "error": error[:200]})


def import_handler(engine: AsyncEngine, store: ObjectStore, settings: AssessmentSettings):
    async def handle(envelope: dict) -> None:
        if envelope["type"] == vuln_feeds.FEED_EVENT:
            await vuln_feeds.import_feed(engine, store, settings, envelope, IMPORTS_GROUP)
            return
        if envelope["type"] != "import.uploaded":
            return
        data = envelope["data"]
        import_id, run_id = data["import_id"], data["run_id"]
        async with engine.connect() as conn:
            record = (await conn.execute(
                text("SELECT bucket, object_key, source_type, status, created_at FROM assessment.imports "
                     "WHERE import_id = CAST(:id AS uuid)"), {"id": import_id})).mappings().first()
        if record is None or record["status"] in ("completed", "failed"):
            return

        try:
            blob = await store.get(record["bucket"], record["object_key"], settings.import_max_bytes)
            parsed = parse_import(record["source_type"], blob, settings.import_max_rows)
        except (ImportFormatError, ValueError) as exc:
            await _fail_import(engine, import_id, run_id, str(exc))
            return

        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, IMPORTS_GROUP, envelope["event_id"]):
                return
            await conn.execute(text("UPDATE assessment.assessment_runs SET status = 'running', started_at = now() "
                                    "WHERE run_id = CAST(:r AS uuid)"), {"r": run_id})
            controls = await load_controls(conn)
            outcome, rejected = await upsert_observations(conn, parsed.rows, run_id=run_id, source="import",
                                                          observed_at=record["created_at"], controls=controls)
            errors = (parsed.errors + rejected)[:50]
            rejected_count = (parsed.total - len(parsed.rows)) + len(rejected)
            accepted = len(parsed.rows) - len(rejected)
            stats = {
                "rows": parsed.total, "accepted": accepted, "rejected": rejected_count,
                "created": outcome["created"], "updated": outcome["updated"], "unchanged": outcome["unchanged"],
                "stale": outcome["stale"],
                "by_severity": {k.split(":", 1)[1]: v for k, v in outcome.items() if k.startswith("severity:")},
                "errors": errors,
            }
            if accepted == 0:
                run_status, import_status = "failed", "failed"
            else:
                run_status = "partially_completed" if rejected_count else "completed"
                import_status = "completed"
            await conn.execute(
                text("UPDATE assessment.imports SET status = :st, stats = CAST(:s AS jsonb), completed_at = now(), "
                     "error = :err WHERE import_id = CAST(:id AS uuid)"),
                {"st": import_status, "s": json.dumps(stats), "id": import_id,
                 "err": "no valid rows" if accepted == 0 else None})
            await conn.execute(
                text("UPDATE assessment.assessment_runs SET status = :st, stats = CAST(:s AS jsonb), "
                     "completed_at = now() WHERE run_id = CAST(:r AS uuid)"),
                {"st": run_status, "s": json.dumps(stats), "r": run_id})
            await enqueue_event(conn, SCHEMA, "eeap.assessment", new_envelope(
                event_type="assessment.run_completed", source=settings.service_name, subject=run_id,
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={"run_id": run_id, "trigger": "import", "full_scope": False, "status": run_status,
                      "stats": {k: v for k, v in stats.items() if k != "errors"}}))
        logger.info("import processed", extra={"import_id": import_id, "accepted": accepted,
                                                "rejected": rejected_count})

    return handle


def acceptance_expiry_task(engine: AsyncEngine):
    """Re-opens findings whose risk acceptance has expired."""

    async def run(stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                async with engine.begin() as conn:
                    expired = (await conn.execute(text(
                        "SELECT f.finding_id::text FROM assessment.findings f WHERE f.lifecycle_state = 'risk_accepted' "
                        "AND NOT EXISTS (SELECT 1 FROM assessment.risk_acceptances a WHERE a.finding_id = f.finding_id "
                        "AND a.revoked_at IS NULL AND a.expires_at > now()) LIMIT 500 "
                        "FOR UPDATE OF f SKIP LOCKED"))).scalars().all()
                    if expired:
                        controls = await load_controls(conn)
                    for finding_id in expired:
                        finding = await get_finding(conn, finding_id)
                        await set_lifecycle(conn, finding, "open", actor="system", note="risk acceptance expired",
                                            trigger="expiry", controls=controls)
                if expired:
                    logger.info("expired risk acceptances re-opened", extra={"count": len(expired)})
            except Exception:
                logger.exception("risk acceptance expiry check failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=ACCEPTANCE_EXPIRY_INTERVAL_SECONDS)
            except TimeoutError:
                pass

    return run


def subscriptions(settings: ServiceSettings) -> list[Subscription]:
    assert isinstance(settings, AssessmentSettings)
    engine = create_engine(settings, pool_size=5)
    store = ObjectStore(settings)
    return [
        Subscription(ORCHESTRATOR_GROUP, ["eeap.assessment"], run_handler(engine, store, settings),
                     background=acceptance_expiry_task(engine)),
        Subscription("assessment-service.evaluator", ["eeap.agent"], log_only_handler("assessment-service.evaluator")),
        Subscription(IMPORTS_GROUP, ["eeap.imports"], import_handler(engine, store, settings)),
    ]
