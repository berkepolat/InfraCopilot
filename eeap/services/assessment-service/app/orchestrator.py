"""Runs server-side assessments: AD (LDAPS) and NET (IP probe) collection + evaluation."""
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

from .ad_relationships import build_relationships
from .collectors.ad_ldap import AdCollectionError, collect as collect_ad
from .collectors.net_probes import NetCollectionError, collect_targets as collect_net
from .config import SCHEMA, AssessmentSettings
from .controls import ad as ad_controls
from .controls import net as net_controls
from .domain import ImportRow
from .findings_repo import ControlMeta, load_controls, upsert_observations
from .storage import ObjectStore
from .targets import asset_id_for_ip

logger = logging.getLogger("eeap.assessment.orchestrator")

ORCHESTRATOR_GROUP = "assessment-service.orchestrator"
ASSESSMENT_STREAM = "eeap.assessment"
DISCOVERY_STREAM = "eeap.discovery"
RELATIONSHIP_STREAM = "eeap.relationship"
EVIDENCE_RETENTION_DAYS = 365


async def resolve_unobserved_ad(conn: AsyncConnection, *, run_id: str, control_ids: list[str], domain: str,
                                observed_at: datetime, controls: dict[str, ControlMeta]) -> Counter:
    """Resolves open server findings of the evaluated AD controls that this run no longer observed."""
    rows = (await conn.execute(text(
        "SELECT asset_id, control_id, subject_key FROM assessment.findings WHERE source = 'server' "
        "AND control_id = ANY(:controls) AND raw_data->>'domain' = :domain AND status <> 'PASS' "
        "AND last_seen_run_id IS DISTINCT FROM CAST(:run AS uuid) AND last_seen_at <= :observed"),
        {"controls": control_ids, "domain": domain, "run": run_id, "observed": observed_at})).mappings().all()
    observations = [ImportRow(asset_id=r["asset_id"], control_id=r["control_id"], status="PASS",
                              subject_key=r["subject_key"], source_tool=ad_controls.SOURCE_TOOL,
                              raw_data={"domain": domain},
                              evidence={"summary": "no longer observed by the AD configuration assessment"})
                    for r in rows]
    outcome, _ = await upsert_observations(conn, observations, run_id=run_id, source="server",
                                           observed_at=observed_at, controls=controls)
    return outcome


async def resolve_unobserved_net(conn: AsyncConnection, *, run_id: str, control_ids: list[str], ips: list[str],
                                 observed_at: datetime, controls: dict[str, ControlMeta]) -> Counter:
    """Resolves open NET findings for the scanned IPs that this run no longer observed."""
    rows = (await conn.execute(text(
        "SELECT asset_id, control_id, subject_key, raw_data->>'ip' AS ip FROM assessment.findings "
        "WHERE source = 'server' AND control_id = ANY(:controls) AND raw_data->>'ip' = ANY(:ips) "
        "AND status <> 'PASS' AND last_seen_run_id IS DISTINCT FROM CAST(:run AS uuid) "
        "AND last_seen_at <= :observed"),
        {"controls": control_ids, "ips": ips, "run": run_id, "observed": observed_at})).mappings().all()
    observations = [ImportRow(asset_id=r["asset_id"], control_id=r["control_id"], status="PASS",
                              subject_key=r["subject_key"], source_tool=net_controls.SOURCE_TOOL,
                              raw_data={"ip": r["ip"]},
                              evidence={"summary": "no longer observed by the network assessment"})
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
                "SELECT run_id, control_ids, status, scope, full_scope FROM assessment.assessment_runs "
                "WHERE run_id = CAST(:r AS uuid) FOR UPDATE"), {"r": run_id})).mappings().first()
            if run is None or run["status"] != "queued":
                return
            await conn.execute(text("UPDATE assessment.assessment_runs SET status = 'running', started_at = now() "
                                    "WHERE run_id = CAST(:r AS uuid)"), {"r": run_id})
            await enqueue_event(conn, SCHEMA, ASSESSMENT_STREAM, new_envelope(
                event_type="assessment.run_started", source=settings.service_name, subject=run_id,
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={"run_id": run_id, "trigger": envelope["data"].get("trigger", "manual"),
                      "full_scope": bool(run["full_scope"]), "scope": run["scope"] or {}}))

        scope = run["scope"] or {}
        try:
            if scope.get("ips"):
                await _execute_net(engine, store, settings, run_id, list(run["control_ids"]) or None,
                                   list(scope["ips"]), envelope)
            else:
                await _execute_ad(engine, store, settings, run_id, list(run["control_ids"]) or None, envelope)
        except (AdCollectionError, NetCollectionError) as exc:
            await _finish(engine, settings, run_id, "failed", {"error": str(exc)[:500]}, envelope)
            logger.warning("assessment run failed", extra={"run_id": run_id, "error": str(exc)[:200]})
        except Exception:
            logger.exception("assessment run failed", extra={"run_id": run_id})
            await _finish(engine, settings, run_id, "failed",
                          {"error": "internal error: unexpected assessment failure"}, envelope)

    return handle


async def _finish(engine: AsyncEngine, settings: AssessmentSettings, run_id: str, status: str, stats: dict,
                  envelope: dict, conn: AsyncConnection | None = None, *, full_scope: bool = True) -> None:
    async def write(c: AsyncConnection) -> None:
        await c.execute(text("UPDATE assessment.assessment_runs SET status = :st, stats = CAST(:s AS jsonb), "
                             "completed_at = now() WHERE run_id = CAST(:r AS uuid)"),
                        {"st": status, "s": json.dumps(stats), "r": run_id})
        await enqueue_event(c, SCHEMA, ASSESSMENT_STREAM, new_envelope(
            event_type="assessment.run_completed", source=settings.service_name, subject=run_id,
            correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
            data={"run_id": run_id, "trigger": envelope["data"].get("trigger", "manual"),
                  "full_scope": full_scope, "status": status,
                  "stats": {k: v for k, v in stats.items() if k != "errors"}}))

    if conn is not None:
        await write(conn)
    else:
        async with engine.begin() as c:
            await write(c)


async def _execute_ad(engine: AsyncEngine, store: ObjectStore, settings: AssessmentSettings, run_id: str,
                      requested: list[str] | None, envelope: dict) -> None:
    target = settings.ad_target()
    if target is None:
        raise AdCollectionError("the AD module is not configured (AD_LDAP_URL, AD_BIND_USER, AD_BIND_PASSWORD_FILE)")
    async with engine.connect() as conn:
        enabled = set((await conn.execute(text(
            "SELECT control_id FROM assessment.controls WHERE module = 'AD' AND enabled"))).scalars())
    control_ids = [c for c in ad_controls.AD_CONTROL_IDS if c in enabled and (requested is None or c in requested)]
    if not control_ids:
        raise AdCollectionError("no enabled AD controls were selected")

    snapshot = await asyncio.to_thread(collect_ad, target)
    observed_at = datetime.fromisoformat(snapshot["collected_at"])
    evaluation = ad_controls.evaluate(snapshot, control_ids, observed_at)
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
        resolved = await resolve_unobserved_ad(conn, run_id=run_id, control_ids=evaluation.evaluated_controls,
                                               domain=domain, observed_at=observed_at, controls=controls)
        for asset in evaluation.assets:
            await enqueue_event(conn, SCHEMA, DISCOVERY_STREAM, new_envelope(
                event_type="discovery.asset_observed", source=settings.service_name, subject=asset["asset_id"],
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={**asset, "source": ad_controls.SOURCE_TOOL, "run_id": run_id,
                      "observed_at": observed_at.isoformat()}))
        relationships = build_relationships(snapshot, run_id)
        await enqueue_event(conn, SCHEMA, RELATIONSHIP_STREAM, new_envelope(
            event_type="relationship.observed", source=settings.service_name, subject=f"ad:{domain}",
            correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
            data={"run_id": run_id, "scope": f"ad:{domain}", "complete": True, "relationships": relationships}))
        stats = {
            "module": "AD", "domain": domain, "controls": evaluation.evaluated_controls,
            "relationships": len(relationships),
            "objects": {"users": len(snapshot["users"]), "computers": len(snapshot["computers"]),
                        "privileged_groups": len(snapshot["privileged_groups"])},
            "observations": len(evaluation.observations), "created": outcome["created"],
            "updated": outcome["updated"], "unchanged": outcome["unchanged"], "stale": outcome["stale"],
            "resolved": resolved["updated"],
            "by_severity": {k.split(":", 1)[1]: v for k, v in outcome.items() if k.startswith("severity:")},
            "assets_observed": len(evaluation.assets), "evidence_object": object_key, "errors": rejected[:50],
        }
        await _finish(engine, settings, run_id, "partially_completed" if rejected else "completed", stats,
                      envelope, conn=conn, full_scope=True)
    logger.info("AD assessment run completed", extra={"run_id": run_id, "observations": len(evaluation.observations),
                                                      "resolved": resolved["updated"]})


async def _execute_net(engine: AsyncEngine, store: ObjectStore, settings: AssessmentSettings, run_id: str,
                       requested: list[str] | None, ips: list[str], envelope: dict) -> None:
    if not ips:
        raise NetCollectionError("network assessment requires at least one IP in scope.ips")
    async with engine.connect() as conn:
        enabled = set((await conn.execute(text(
            "SELECT control_id FROM assessment.controls WHERE module = 'NET' AND enabled"))).scalars())
    control_ids = [c for c in net_controls.NET_CONTROL_IDS if c in enabled and (requested is None or c in requested)]
    if not control_ids:
        raise NetCollectionError("no enabled NET controls were selected")

    snapshot = await asyncio.to_thread(
        collect_net, ips, control_ids=control_ids, timeout=settings.net_probe_timeout_seconds)
    observed_at = datetime.fromisoformat(snapshot["collected_at"])
    evaluation = net_controls.evaluate(snapshot, control_ids, observed_at)

    body = json.dumps(snapshot, sort_keys=True).encode()
    sha256 = hashlib.sha256(body).hexdigest()
    object_key = f"evidence/{observed_at:%Y/%m}/{run_id}/net-snapshot.json"
    await store.put(settings.evidence_bucket, object_key, body, "application/json",
                    {"run-id": run_id, "sha256": sha256, "collector": snapshot["collector"]})

    primary_asset = asset_id_for_ip(ips[0])
    async with engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO assessment.evidence_objects (run_id, asset_id, bucket, object_key, sha256, size_bytes, "
            "collected_at, retention_until) VALUES (CAST(:run AS uuid), :asset, :bucket, :key, :sha, :size, "
            ":collected, :retain)"),
            {"run": run_id, "asset": primary_asset, "bucket": settings.evidence_bucket,
             "key": object_key, "sha": sha256, "size": len(body), "collected": observed_at,
             "retain": observed_at + timedelta(days=EVIDENCE_RETENTION_DAYS)})
        controls = await load_controls(conn)
        outcome, rejected = await upsert_observations(conn, evaluation.observations, run_id=run_id,
                                                      source="server", observed_at=observed_at, controls=controls)
        resolved = await resolve_unobserved_net(conn, run_id=run_id, control_ids=evaluation.evaluated_controls,
                                                ips=ips, observed_at=observed_at, controls=controls)
        for asset in evaluation.assets:
            await enqueue_event(conn, SCHEMA, DISCOVERY_STREAM, new_envelope(
                event_type="discovery.asset_observed", source=settings.service_name, subject=asset["asset_id"],
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={**asset, "source": net_controls.SOURCE_TOOL, "run_id": run_id,
                      "observed_at": observed_at.isoformat()}))
        stats = {
            "module": "NET", "targets": ips, "controls": evaluation.evaluated_controls,
            "observations": len(evaluation.observations), "created": outcome["created"],
            "updated": outcome["updated"], "unchanged": outcome["unchanged"], "stale": outcome["stale"],
            "resolved": resolved["updated"],
            "by_severity": {k.split(":", 1)[1]: v for k, v in outcome.items() if k.startswith("severity:")},
            "assets_observed": len(evaluation.assets), "evidence_object": object_key, "errors": rejected[:50],
        }
        await _finish(engine, settings, run_id, "partially_completed" if rejected else "completed", stats,
                      envelope, conn=conn, full_scope=False)
    logger.info("NET assessment run completed", extra={"run_id": run_id, "targets": len(ips),
                                                       "observations": len(evaluation.observations)})
