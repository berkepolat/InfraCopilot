"""Runs server-side (collector-based) assessments: AD configuration collection and evaluation."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from eeap_shared.utils.events import enqueue_event, mark_processed, new_envelope

from .collectors.ad_ldap import AdCollectionError, collect
from .config import SCHEMA, AssessmentSettings
from .controls.ad import AD_CONTROL_IDS, SOURCE_TOOL, evaluate
from .domain import ImportRow
from .findings_repo import ControlMeta, load_controls, upsert_observations
from .storage import ObjectStore

logger = logging.getLogger("eeap.assessment.orchestrator")

ORCHESTRATOR_GROUP = "assessment-service.orchestrator"
ASSESSMENT_STREAM = "eeap.assessment"
DISCOVERY_STREAM = "eeap.discovery"
EVIDENCE_RETENTION_DAYS = 365


async def resolve_unobserved(conn: AsyncConnection, *, run_id: str, control_ids: list[str], domain: str,
                             observed_at: datetime, controls: dict[str, ControlMeta]) -> Counter:
    """Resolves open server findings of the evaluated controls that this run no longer observed."""
    rows = (await conn.execute(text(
        "SELECT asset_id, control_id, subject_key FROM assessment.findings WHERE source = 'server' "
        "AND control_id = ANY(:controls) AND raw_data->>'domain' = :domain AND status <> 'PASS' "
        "AND last_seen_run_id IS DISTINCT FROM CAST(:run AS uuid) AND last_seen_at <= :observed"),
        {"controls": control_ids, "domain": domain, "run": run_id, "observed": observed_at})).mappings().all()
    observations = [ImportRow(asset_id=r["asset_id"], control_id=r["control_id"], status="PASS",
                              subject_key=r["subject_key"], source_tool=SOURCE_TOOL, raw_data={"domain": domain},
                              evidence={"summary": "no longer observed by the AD configuration assessment"})
                    for r in rows]
    outcome, _ = await upsert_observations(conn, observations, run_id=run_id, source="server",
                                           observed_at=observed_at, controls=controls)
    return outcome


def run_handler(engine: AsyncEngine, store: ObjectStore, settings: AssessmentSettings):
    async def handle(envelope: dict) -> None:
        if envelope["type"] != "assessment.run_requested":
            return
        run_id = envelope["data"]["run_id"]
        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, ORCHESTRATOR_GROUP, envelope["event_id"]):
                return
            run = (await conn.execute(text(
                "SELECT run_id, control_ids, status FROM assessment.assessment_runs "
                "WHERE run_id = CAST(:r AS uuid) FOR UPDATE"), {"r": run_id})).mappings().first()
            if run is None or run["status"] != "queued":
                return
            await conn.execute(text("UPDATE assessment.assessment_runs SET status = 'running', started_at = now() "
                                    "WHERE run_id = CAST(:r AS uuid)"), {"r": run_id})
            await enqueue_event(conn, SCHEMA, ASSESSMENT_STREAM, new_envelope(
                event_type="assessment.run_started", source=settings.service_name, subject=run_id,
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={"run_id": run_id, "trigger": envelope["data"].get("trigger", "manual"), "full_scope": True}))

        try:
            await _execute(engine, store, settings, run_id, list(run["control_ids"]) or None, envelope)
        except AdCollectionError as exc:
            await _finish(engine, settings, run_id, "failed", {"error": str(exc)[:500]}, envelope)
            logger.warning("assessment run failed", extra={"run_id": run_id, "error": str(exc)[:200]})
        except Exception as exc:
            logger.exception("assessment run failed", extra={"run_id": run_id})
            await _finish(engine, settings, run_id, "failed", {"error": f"internal error: {type(exc).__name__}"},
                          envelope)

    return handle


async def _finish(engine: AsyncEngine, settings: AssessmentSettings, run_id: str, status: str, stats: dict,
                  envelope: dict, conn: AsyncConnection | None = None) -> None:
    async def write(c: AsyncConnection) -> None:
        await c.execute(text("UPDATE assessment.assessment_runs SET status = :st, stats = CAST(:s AS jsonb), "
                             "completed_at = now() WHERE run_id = CAST(:r AS uuid)"),
                        {"st": status, "s": json.dumps(stats), "r": run_id})
        await enqueue_event(c, SCHEMA, ASSESSMENT_STREAM, new_envelope(
            event_type="assessment.run_completed", source=settings.service_name, subject=run_id,
            correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
            data={"run_id": run_id, "trigger": envelope["data"].get("trigger", "manual"), "full_scope": True,
                  "status": status,
                  "stats": {k: v for k, v in stats.items() if k != "errors"}}))

    if conn is not None:
        await write(conn)
    else:
        async with engine.begin() as c:
            await write(c)


async def _execute(engine: AsyncEngine, store: ObjectStore, settings: AssessmentSettings, run_id: str,
                   requested: list[str] | None, envelope: dict) -> None:
    target = settings.ad_target()
    if target is None:
        raise AdCollectionError("the AD module is not configured (AD_LDAP_URL, AD_BIND_USER, AD_BIND_PASSWORD_FILE)")
    async with engine.connect() as conn:
        enabled = set((await conn.execute(text(
            "SELECT control_id FROM assessment.controls WHERE module = 'AD' AND enabled"))).scalars())
    control_ids = [c for c in AD_CONTROL_IDS if c in enabled and (requested is None or c in requested)]
    if not control_ids:
        raise AdCollectionError("no enabled AD controls were selected")

    snapshot = await asyncio.to_thread(collect, target)
    observed_at = datetime.fromisoformat(snapshot["collected_at"])
    evaluation = evaluate(snapshot, control_ids, observed_at)
    domain = snapshot["domain"]["dns_name"]

    body = json.dumps(snapshot, sort_keys=True).encode()
    sha256 = hashlib.sha256(body).hexdigest()
    object_key = f"evidence/{observed_at:%Y/%m}/{run_id}/ad-snapshot.json"
    await store.put(settings.evidence_bucket, object_key, body, "application/json",
                    {"run-id": run_id, "sha256": sha256, "collector": snapshot["collector"]})

    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO assessment.evidence_objects (run_id, asset_id, bucket, object_key, sha256, size_bytes, "
            "collected_at, retention_until) VALUES (CAST(:run AS uuid), :asset, :bucket, :key, :sha, :size, "
            ":collected, :retain)"),
            {"run": run_id, "asset": evaluation.domain_asset_id, "bucket": settings.evidence_bucket,
             "key": object_key, "sha": sha256, "size": len(body), "collected": observed_at,
             "retain": observed_at + timedelta(days=EVIDENCE_RETENTION_DAYS)})
        controls = await load_controls(conn)
        outcome, rejected = await upsert_observations(conn, evaluation.observations, run_id=run_id,
                                                      source="server", observed_at=observed_at, controls=controls)
        resolved = await resolve_unobserved(conn, run_id=run_id, control_ids=evaluation.evaluated_controls,
                                            domain=domain, observed_at=observed_at, controls=controls)
        for asset in evaluation.assets:
            await enqueue_event(conn, SCHEMA, DISCOVERY_STREAM, new_envelope(
                event_type="discovery.asset_observed", source=settings.service_name, subject=asset["asset_id"],
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={**asset, "source": SOURCE_TOOL, "run_id": run_id, "observed_at": observed_at.isoformat()}))
        stats = {
            "domain": domain, "controls": evaluation.evaluated_controls,
            "objects": {"users": len(snapshot["users"]), "computers": len(snapshot["computers"]),
                        "privileged_groups": len(snapshot["privileged_groups"])},
            "observations": len(evaluation.observations), "created": outcome["created"],
            "updated": outcome["updated"], "unchanged": outcome["unchanged"], "stale": outcome["stale"],
            "resolved": resolved["updated"],
            "by_severity": {k.split(":", 1)[1]: v for k, v in outcome.items() if k.startswith("severity:")},
            "assets_observed": len(evaluation.assets), "evidence_object": object_key, "errors": rejected[:50],
        }
        await _finish(engine, settings, run_id, "partially_completed" if rejected else "completed", stats,
                      envelope, conn=conn)
    logger.info("assessment run completed", extra={"run_id": run_id, "observations": len(evaluation.observations),
                                                   "resolved": resolved["updated"]})
