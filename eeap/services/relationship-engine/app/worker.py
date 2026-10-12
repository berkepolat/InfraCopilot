from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.db import create_engine
from eeap_shared.utils.events import enqueue_event, log_only_handler, mark_processed, new_envelope
from eeap_shared.utils.runtime import Subscription
from eeap_shared.utils.settings import ServiceSettings

from .config import SCHEMA

logger = logging.getLogger("eeap.relationship.ingest")

INGEST_GROUP = "relationship-engine.ingest"


def asset_ingest_handler(engine: AsyncEngine, service: str):
    """Keeps a Computer node per inventory asset, so findings and relationships can attach to it."""

    async def handle(envelope: dict) -> None:
        if envelope["type"] not in ("asset.created", "asset.updated"):
            return
        data = envelope["data"]
        asset_id = data["asset_id"]
        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, INGEST_GROUP, envelope["event_id"]):
                return
            await conn.execute(
                text("INSERT INTO graph.nodes (node_key, node_type, display_name, asset_id, is_tier0, source) "
                     "VALUES (:key, 'Computer', :name, :asset_id, :tier0, 'asset-service') "
                     "ON CONFLICT (node_key) DO UPDATE SET display_name = EXCLUDED.display_name, "
                     "is_tier0 = EXCLUDED.is_tier0, last_seen_at = now()"),
                {"key": f"asset:{asset_id}", "name": data.get("hostname") or asset_id, "asset_id": asset_id,
                 "tier0": data.get("tier") == "Tier0"},
            )
            await enqueue_event(conn, SCHEMA, "eeap.graph", new_envelope(
                event_type="graph.updated", source=service, subject=f"asset:{asset_id}",
                correlation_id=envelope.get("correlation_id"), causation_id=envelope["event_id"],
                data={"changed_nodes": 1, "reason": envelope["type"]},
            ))
        logger.info("asset node upserted", extra={"asset_id": asset_id})

    return handle


def subscriptions(settings: ServiceSettings) -> list[Subscription]:
    engine = create_engine(settings, pool_size=5)
    ingest = asset_ingest_handler(engine, settings.service_name)
    return [
        Subscription(INGEST_GROUP, ["eeap.asset", "eeap.relationship", "eeap.finding"], ingest),
        # Graph analytics (Tier-0 reachability, concentration) are implemented in Phase 2.
        Subscription("relationship-engine.analysis", ["eeap.graph"], log_only_handler("relationship-engine.analysis")),
    ]
