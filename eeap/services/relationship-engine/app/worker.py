from __future__ import annotations

import asyncio
import logging
import time

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.db import create_engine
from eeap_shared.utils.events import enqueue_event, mark_processed, new_envelope
from eeap_shared.utils.redis_client import create_redis
from eeap_shared.utils.runtime import Subscription

from .config import SCHEMA, RelationshipSettings
from .ingest import ingest_relationships
from .jobs import GRAPH_STREAM, run_analysis

logger = logging.getLogger("eeap.relationship.ingest")

INGEST_GROUP = "relationship-engine.ingest"
ANALYSIS_GROUP = "relationship-engine.analysis"
PENDING_SINCE_KEY = "graph:analysis:pending_since"
LAST_CHANGE_KEY = "graph:analysis:last_change"
LOCK_KEY = "graph:analysis:lock"
LOCK_TTL_SECONDS = 900
POLL_SECONDS = 5.0
MAX_DEFER_FACTOR = 5


def ingest_handler(engine: AsyncEngine, service: str):
    """Keeps a Computer node per inventory asset and applies observed relationships to the graph."""

    async def handle_asset(envelope: dict) -> None:
        data = envelope["data"]
        asset_id = data["asset_id"]
        tier0 = data.get("tier") == "Tier0"
        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, INGEST_GROUP, envelope["event_id"]):
                return
            await conn.execute(
                text("INSERT INTO graph.nodes (node_key, node_type, display_name, asset_id, is_tier0, properties, "
                     "source) VALUES (:key, 'Computer', :name, :asset_id, :tier0, "
                     "jsonb_build_object('inventory_tier0', CAST(:tier0 AS boolean)), 'asset-service') "
                     "ON CONFLICT (node_key) DO UPDATE SET display_name = EXCLUDED.display_name, "
                     "is_tier0 = EXCLUDED.is_tier0 "
                     "OR COALESCE((graph.nodes.properties->>'collector_tier0')::boolean, false), "
                     "properties = graph.nodes.properties || EXCLUDED.properties, last_seen_at = now()"),
                {"key": f"asset:{asset_id}", "name": data.get("hostname") or asset_id, "asset_id": asset_id,
                 "tier0": tier0},
            )
            await enqueue_event(conn, SCHEMA, GRAPH_STREAM, new_envelope(
                event_type="graph.updated", source=service, subject=f"asset:{asset_id}",
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={"changed_nodes": 1, "reason": envelope["type"]},
            ))
        logger.info("asset node upserted", extra={"asset_id": asset_id})

    async def handle_relationships(envelope: dict) -> None:
        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, INGEST_GROUP, envelope["event_id"]):
                return
            result = await ingest_relationships(conn, envelope["data"], envelope["source"])
            await enqueue_event(conn, SCHEMA, GRAPH_STREAM, new_envelope(
                event_type="graph.updated", source=service, subject=envelope.get("subject"),
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={"changed_nodes": result.nodes, "changed_edges": result.edges,
                      "deactivated_edges": result.deactivated, "reason": envelope["type"]},
            ))
        logger.info("relationships ingested", extra={"nodes": result.nodes, "edges": result.edges,
                                                     "deactivated": result.deactivated})

    async def handle(envelope: dict) -> None:
        if envelope["type"] in ("asset.created", "asset.updated"):
            await handle_asset(envelope)
        elif envelope["type"] == "relationship.observed":
            await handle_relationships(envelope)

    return handle


def analysis_trigger_handler(redis: Redis):
    """Graph changes only mark the graph dirty; the analysis loop debounces bursts into one run."""

    async def handle(envelope: dict) -> None:
        if envelope["type"] != "graph.updated":
            return
        now = str(time.time())
        await redis.set(PENDING_SINCE_KEY, now, nx=True)
        await redis.set(LAST_CHANGE_KEY, now)

    return handle


def analysis_loop(engine: AsyncEngine, redis: Redis, settings: RelationshipSettings):
    debounce = max(0, settings.graph_analysis_debounce_seconds)

    async def due() -> bool:
        pending_since, last_change = await redis.mget(PENDING_SINCE_KEY, LAST_CHANGE_KEY)
        if pending_since is None:
            return False
        now = time.time()
        quiet = now - float(last_change or pending_since)
        return quiet >= debounce or now - float(pending_since) >= debounce * MAX_DEFER_FACTOR

    async def run_locked(trigger: str) -> None:
        if not await redis.set(LOCK_KEY, settings.service_name, nx=True, ex=LOCK_TTL_SECONDS):
            return  # another worker replica is analysing
        try:
            # Changes arriving while the job runs set the keys again and cause a follow-up run.
            await redis.delete(PENDING_SINCE_KEY, LAST_CHANGE_KEY)
            try:
                await run_analysis(engine, settings.service_name, settings.graph_max_path_depth, trigger)
            except Exception:
                await redis.set(PENDING_SINCE_KEY, str(time.time()), nx=True)
                raise
        finally:
            await redis.delete(LOCK_KEY)

    async def run(stop: asyncio.Event) -> None:
        trigger = "startup"
        while not stop.is_set():
            try:
                if trigger == "startup" or await due():
                    await run_locked(trigger)
                    trigger = "graph.updated"
            except Exception:
                logger.exception("graph analysis failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=POLL_SECONDS)
            except TimeoutError:
                pass

    return run


def subscriptions(settings: RelationshipSettings) -> list[Subscription]:
    engine = create_engine(settings, pool_size=5)
    redis = create_redis(settings)
    return [
        Subscription(INGEST_GROUP, ["eeap.asset", "eeap.relationship", "eeap.finding"],
                     ingest_handler(engine, settings.service_name)),
        Subscription(ANALYSIS_GROUP, [GRAPH_STREAM], analysis_trigger_handler(redis),
                     background=analysis_loop(engine, redis, settings)),
    ]
