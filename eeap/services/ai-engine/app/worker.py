from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.db import create_engine
from eeap_shared.utils.events import log_only_handler, mark_processed
from eeap_shared.utils.redis_client import create_redis
from eeap_shared.utils.runtime import Subscription
from eeap_shared.utils.settings import ServiceSettings

from .config import SCHEMA
from .engine import mark_dirty, recompute, upsert_asset_fact, upsert_finding_fact

logger = logging.getLogger("eeap.ai.worker")

SCORING_GROUP = "ai-engine.scoring"
RECOMPUTE_INTERVAL_SECONDS = 2.0
FINDING_EVENTS = {"finding.created", "finding.updated", "finding.resolved"}
ASSET_EVENTS = {"asset.created", "asset.updated", "asset.criticality_changed"}


def scoring_handler(engine: AsyncEngine, redis: Redis):
    """Maintains the local read model; scoring itself is batched by the recompute loop."""

    async def handle(envelope: dict) -> None:
        event_type, data = envelope["type"], envelope["data"]
        if event_type not in FINDING_EVENTS | ASSET_EVENTS | {"assessment.run_completed"}:
            return
        occurred_at = datetime.fromisoformat(envelope["occurred_at"])
        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, SCORING_GROUP, envelope["event_id"]):
                return
            if event_type in FINDING_EVENTS:
                applied = await upsert_finding_fact(conn, data, occurred_at)
            elif event_type in ASSET_EVENTS:
                applied = await upsert_asset_fact(conn, event_type, data, occurred_at)
            else:
                applied = True
        if not applied:
            return
        if event_type in FINDING_EVENTS:
            # Breadth (B) depends on every finding of the control, so the whole control cohort is rescored.
            await mark_dirty(redis, controls=[data["control_id"]], assets=[data["asset_id"]])
        elif event_type in ASSET_EVENTS:
            await mark_dirty(redis, assets=[data["asset_id"]])
        else:
            await mark_dirty(redis)

    return handle


def recompute_loop(engine: AsyncEngine, redis: Redis):
    async def run(stop: asyncio.Event) -> None:
        full = True  # reconcile once on start-up (model changes, missed dirt)
        while not stop.is_set():
            try:
                stats = await recompute(engine, redis, full=full, trigger="startup" if full else "event")
                full = False
                if stats.findings or stats.assets or stats.organization is not None:
                    logger.info("scores recomputed", extra={"findings": stats.findings, "assets": stats.assets,
                                                            "organization": stats.organization,
                                                            "changed": stats.changed})
            except Exception:
                logger.exception("score recomputation failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=RECOMPUTE_INTERVAL_SECONDS)
            except TimeoutError:
                pass

    return run


def subscriptions(settings: ServiceSettings) -> list[Subscription]:
    engine = create_engine(settings, pool_size=5)
    redis = create_redis(settings)
    return [
        Subscription(SCORING_GROUP, ["eeap.finding", "eeap.asset", "eeap.assessment", "eeap.graph"],
                     scoring_handler(engine, redis), background=recompute_loop(engine, redis)),
        # Correlation rules (risk scenarios) build on the graph analytics and are implemented next.
        Subscription("ai-engine.correlation", ["eeap.assessment"], log_only_handler("ai-engine.correlation")),
    ]
