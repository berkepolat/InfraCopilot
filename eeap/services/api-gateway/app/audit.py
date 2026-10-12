"""Append-only, hash-chained audit log writer (doc 07 §5)."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.logging import request_id_var

logger = logging.getLogger("eeap.audit")

# Serializes chain extension across gateway replicas.
_AUDIT_LOCK_KEY = 0x4545_4150_4155_4454


@dataclass
class AuditEntry:
    actor_type: str
    action: str
    outcome: str
    actor_id: str | None = None
    actor_name: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    details: dict = field(default_factory=dict)


def entry_hash(prev_hash: bytes | None, event_time: datetime, entry: AuditEntry, request_id: str | None) -> bytes:
    canonical = json.dumps(
        {**asdict(entry), "event_time": event_time.isoformat(), "request_id": request_id},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256((prev_hash or b"") + canonical.encode()).digest()


async def write_audit(engine: AsyncEngine, entry: AuditEntry) -> None:
    request_id = request_id_var.get()
    event_time = datetime.now(UTC)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
            prev = (await conn.execute(
                text("SELECT entry_hash FROM audit.audit_log ORDER BY audit_id DESC LIMIT 1")
            )).scalar()
            digest = entry_hash(prev, event_time, entry, request_id)
            await conn.execute(
                text(
                    "INSERT INTO audit.audit_log (event_time, actor_type, actor_id, actor_name, action, "
                    "resource_type, resource_id, outcome, source_ip, user_agent, request_id, details, "
                    "prev_hash, entry_hash) VALUES (:event_time, :actor_type, :actor_id, :actor_name, :action, "
                    ":resource_type, :resource_id, :outcome, CAST(:source_ip AS inet), :user_agent, :request_id, "
                    "CAST(:details AS jsonb), :prev_hash, :entry_hash)"
                ),
                {**asdict(entry), "details": json.dumps(entry.details), "event_time": event_time,
                 "request_id": request_id, "prev_hash": prev, "entry_hash": digest},
            )
    except Exception:
        # Audit failures must be visible to operators; they are alerted on via logs/metrics.
        logger.exception("audit write failed", extra={"action": entry.action})
        raise
