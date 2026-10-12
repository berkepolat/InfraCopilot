"""Event envelope, transactional outbox relay and Redis Streams consumers (ADR-0005)."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

from redis.asyncio import Redis
from redis.exceptions import ResponseError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from ..logging import request_id_var
from .metrics import EVENTS_CONSUMED, EVENTS_PUBLISHED

logger = logging.getLogger("eeap.events")

DLQ_STREAM = "eeap.dlq"
STREAM_MAXLEN = 1_000_000
MAX_HANDLER_ATTEMPTS = 3

EventHandler = Callable[[dict], Awaitable[None]]


def new_envelope(
    *, event_type: str, source: str, data: dict, subject: str | None = None,
    correlation_id: str | None = None, causation_id: str | None = None, actor: dict | None = None,
) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "type": event_type,
        "schema_version": 1,
        "source": source,
        "occurred_at": datetime.now(UTC).isoformat(),
        "correlation_id": correlation_id or request_id_var.get() or str(uuid.uuid4()),
        "causation_id": causation_id,
        "subject": subject,
        "actor": actor,
        "data": data,
        "data_ref": None,
    }


async def enqueue_event(conn: AsyncConnection, schema: str, stream: str, envelope: dict) -> None:
    """Writes an event to the service's outbox inside the caller's transaction."""
    await conn.execute(
        text(
            f'INSERT INTO "{schema}".event_outbox (event_id, stream, event_type, schema_version, envelope) '
            "VALUES (:event_id, :stream, :event_type, :schema_version, CAST(:envelope AS jsonb))"
        ),
        {
            "event_id": envelope["event_id"],
            "stream": stream,
            "event_type": envelope["type"],
            "schema_version": envelope["schema_version"],
            "envelope": json.dumps(envelope, default=str),
        },
    )


class OutboxRelay:
    """Publishes committed outbox rows to Redis Streams. Safe to run in several replicas."""

    def __init__(self, engine: AsyncEngine, redis: Redis, schema: str, service: str,
                 interval_seconds: float = 0.5, batch_size: int = 100) -> None:
        self.engine, self.redis, self.schema, self.service = engine, redis, schema, service
        self.interval, self.batch_size = interval_seconds, batch_size

    async def publish_batch(self) -> int:
        async with self.engine.begin() as conn:
            rows = (await conn.execute(
                text(
                    f'SELECT event_id, stream, event_type, envelope FROM "{self.schema}".event_outbox '
                    "WHERE published_at IS NULL ORDER BY created_at LIMIT :limit FOR UPDATE SKIP LOCKED"
                ),
                {"limit": self.batch_size},
            )).all()
            for row in rows:
                await self.redis.xadd(
                    row.stream, {"envelope": json.dumps(row.envelope)}, maxlen=STREAM_MAXLEN, approximate=True
                )
                EVENTS_PUBLISHED.labels(self.service, row.stream, row.event_type).inc()
            if rows:
                await conn.execute(
                    text(f'UPDATE "{self.schema}".event_outbox SET published_at = now(), attempts = attempts + 1 '
                         "WHERE event_id = ANY(:ids)"),
                    {"ids": [row.event_id for row in rows]},
                )
            return len(rows)

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                published = await self.publish_batch()
            except Exception:
                logger.exception("outbox relay batch failed")
                published = 0
            if not published:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.interval)
                except TimeoutError:
                    pass


async def mark_processed(conn: AsyncConnection, schema: str, group: str, event_id: str) -> bool:
    """Idempotent-consumer guard: returns False if this group already processed the event."""
    result = await conn.execute(
        text(f'INSERT INTO "{schema}".event_inbox (consumer_group, event_id) VALUES (:g, :e) '
             "ON CONFLICT DO NOTHING RETURNING event_id"),
        {"g": group, "e": event_id},
    )
    return result.first() is not None


class StreamConsumer:
    """Consumes one or more streams within a consumer group and dispatches by event type."""

    def __init__(self, redis: Redis, *, service: str, group: str, streams: list[str],
                 handler: EventHandler, consumer_name: str, heartbeat_path: str | None = None) -> None:
        self.redis, self.service, self.group, self.streams = redis, service, group, streams
        self.handler, self.consumer_name, self.heartbeat_path = handler, consumer_name, heartbeat_path

    async def ensure_groups(self) -> None:
        for stream in self.streams:
            try:
                await self.redis.xgroup_create(stream, self.group, id="0", mkstream=True)
            except ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    def _heartbeat(self) -> None:
        if self.heartbeat_path:
            Path(self.heartbeat_path).touch()

    async def _handle(self, stream: str, message_id: str, fields: dict) -> None:
        envelope = json.loads(fields["envelope"])
        event_type = envelope.get("type", "unknown")
        token = request_id_var.set(envelope.get("correlation_id"))
        try:
            for attempt in range(1, MAX_HANDLER_ATTEMPTS + 1):
                try:
                    await self.handler(envelope)
                    EVENTS_CONSUMED.labels(self.service, self.group, event_type, "ok").inc()
                    break
                except Exception as exc:
                    logger.exception("handler failed", extra={"event_type": event_type, "attempt": attempt})
                    if attempt == MAX_HANDLER_ATTEMPTS:
                        await self.redis.xadd(DLQ_STREAM, {
                            "envelope": fields["envelope"], "stream": stream, "message_id": message_id,
                            "group": self.group, "error": repr(exc)[:2000],
                        })
                        EVENTS_CONSUMED.labels(self.service, self.group, event_type, "dlq").inc()
                    else:
                        await asyncio.sleep(0.5 * attempt)
            await self.redis.xack(stream, self.group, message_id)
        finally:
            request_id_var.reset(token)

    async def run(self, stop: asyncio.Event) -> None:
        await self.ensure_groups()
        logger.info("consumer started", extra={"group": self.group, "streams": self.streams})
        while not stop.is_set():
            self._heartbeat()
            try:
                batches = await self.redis.xreadgroup(
                    self.group, self.consumer_name, {s: ">" for s in self.streams}, count=50, block=5000
                )
            except Exception:
                logger.exception("xreadgroup failed")
                await asyncio.sleep(2)
                continue
            for stream, messages in batches or []:
                for message_id, fields in messages:
                    await self._handle(stream, message_id, fields)


def log_only_handler(group: str) -> EventHandler:
    async def handler(envelope: dict) -> None:
        logger.info("event received", extra={"group": group, "event_type": envelope.get("type"),
                                             "subject": envelope.get("subject")})

    return handler
