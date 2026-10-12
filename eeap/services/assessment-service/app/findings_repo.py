"""Finding persistence: idempotent upsert by fingerprint, history, lifecycle changes and events."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from eeap_shared.utils.events import enqueue_event, new_envelope

from .config import SCHEMA, settings
from .domain import ImportRow, fingerprint, lifecycle_after_observation

FINDING_STREAM = "eeap.finding"

FINDING_COLUMNS = (
    "f.finding_id, f.fingerprint, f.asset_id, f.control_id, f.control_name, f.category, f.severity, f.status, "
    "f.lifecycle_state, f.subject_key, f.evidence, f.recommendation, f.source, f.source_tool, "
    "f.first_seen_run_id, f.last_seen_run_id, f.first_seen_at, f.last_seen_at, f.resolved_at, f.updated_at"
)


@dataclass(frozen=True)
class ControlMeta:
    control_id: str
    name: str
    category: str
    default_severity: str
    exploitability: float
    privilege_impact: float
    recommendation: str | None


async def load_controls(conn: AsyncConnection) -> dict[str, ControlMeta]:
    rows = await conn.execute(text(
        "SELECT control_id, name, category, default_severity, exploitability::float AS exploitability, "
        "privilege_impact::float AS privilege_impact, recommendation FROM assessment.controls"))
    return {r.control_id: ControlMeta(**r._mapping) for r in rows}


def _event_data(row: dict, control: ControlMeta, trigger: str, run_id: str | None) -> dict:
    return {
        "finding_id": str(row["finding_id"]), "asset_id": row["asset_id"], "control_id": row["control_id"],
        "category": row["category"], "severity": row["severity"], "status": row["status"],
        "lifecycle_state": row["lifecycle_state"], "subject_key": row["subject_key"],
        "exploitability": control.exploitability, "privilege_impact": control.privilege_impact,
        "run_id": run_id, "trigger": trigger,
    }


async def emit_finding_event(conn: AsyncConnection, event_type: str, row: dict, control: ControlMeta, *,
                             trigger: str, run_id: str | None = None, actor: dict | None = None) -> None:
    await enqueue_event(conn, SCHEMA, FINDING_STREAM, new_envelope(
        event_type=event_type, source=settings.service_name, subject=str(row["finding_id"]), actor=actor,
        data=_event_data(row, control, trigger, run_id)))


async def add_history(conn: AsyncConnection, row: dict, *, run_id: str | None, changed_by: str,
                      note: str | None = None) -> None:
    await conn.execute(
        text("INSERT INTO assessment.finding_history (finding_id, run_id, status, severity, lifecycle_state, "
             "changed_by, note) VALUES (:fid, CAST(:run AS uuid), :status, :severity, :state, :by, :note)"),
        {"fid": row["finding_id"], "run": run_id, "status": row["status"], "severity": row["severity"],
         "state": row["lifecycle_state"], "by": changed_by, "note": note},
    )


async def upsert_observations(conn: AsyncConnection, rows: list[ImportRow], *, run_id: str, source: str,
                              observed_at: datetime,
                              controls: dict[str, ControlMeta]) -> tuple[Counter, list[dict]]:
    """Applies observed findings. Returns outcome counters and row-level rejections.

    Observations older than the finding's latest observation are skipped, so imports processed out of
    order (parallel workers) cannot overwrite newer results.
    """
    outcome: Counter = Counter()
    rejected: list[dict] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        control = controls.get(row.control_id)
        if control is None:
            rejected.append({"row": index, "error": f"unknown control_id {row.control_id}"})
            continue
        fp = fingerprint(row.asset_id, row.control_id, row.subject_key)
        if fp in seen:
            rejected.append({"row": index, "error": "duplicate of an earlier row (same asset, control, subject)"})
            continue
        seen.add(fp)

        severity = row.severity or control.default_severity
        values = {
            "fp": fp, "asset_id": row.asset_id, "control_id": row.control_id,
            "control_name": row.control_name or control.name, "category": row.category or control.category,
            "severity": severity, "status": row.status, "subject_key": row.subject_key,
            "evidence": json.dumps(row.evidence, default=str), "raw_data": json.dumps(row.raw_data, default=str),
            "recommendation": row.recommendation or control.recommendation, "source": source,
            "source_tool": row.source_tool, "run": run_id, "observed": observed_at,
        }
        existing = (await conn.execute(
            text("SELECT finding_id, status, severity, lifecycle_state, last_seen_at FROM assessment.findings "
                 "WHERE fingerprint = :fp FOR UPDATE"), {"fp": fp})).mappings().first()
        if existing is not None and existing["last_seen_at"] > observed_at:
            outcome["stale"] += 1
            continue

        if existing is None:
            state = lifecycle_after_observation(None, row.status)
            current = (await conn.execute(
                text("INSERT INTO assessment.findings (fingerprint, asset_id, control_id, control_name, category, "
                     "severity, status, lifecycle_state, subject_key, evidence, recommendation, raw_data, source, "
                     "source_tool, first_seen_run_id, last_seen_run_id, first_seen_at, last_seen_at, resolved_at) "
                     "VALUES (:fp, :asset_id, :control_id, :control_name, :category, :severity, :status, :state, "
                     ":subject_key, CAST(:evidence AS jsonb), :recommendation, CAST(:raw_data AS jsonb), :source, "
                     ":source_tool, CAST(:run AS uuid), CAST(:run AS uuid), :observed, :observed, "
                     "CASE WHEN :state = 'resolved' THEN now() END) "
                     f"RETURNING {FINDING_COLUMNS.replace('f.', '')}"),
                {**values, "state": state})).mappings().one()
            outcome["created"] += 1
            event_type = "finding.created"
        else:
            state = lifecycle_after_observation(existing["lifecycle_state"], row.status)
            current = (await conn.execute(
                text("UPDATE assessment.findings SET control_name = :control_name, category = :category, "
                     "severity = :severity, status = :status, lifecycle_state = :state, evidence = "
                     "CAST(:evidence AS jsonb), recommendation = :recommendation, raw_data = CAST(:raw_data AS jsonb), "
                     "source = :source, source_tool = :source_tool, last_seen_run_id = CAST(:run AS uuid), "
                     "last_seen_at = :observed, resolved_at = CASE WHEN :state = 'resolved' "
                     "THEN coalesce(resolved_at, now()) END WHERE fingerprint = :fp "
                     f"RETURNING {FINDING_COLUMNS.replace('f.', '')}"),
                {**values, "state": state})).mappings().one()
            changed = (existing["status"], existing["severity"], existing["lifecycle_state"]) != \
                      (current["status"], current["severity"], current["lifecycle_state"])
            if not changed:
                outcome["unchanged"] += 1
                continue
            outcome["updated"] += 1
            event_type = "finding.resolved" if state == "resolved" else "finding.updated"

        await add_history(conn, current, run_id=run_id, changed_by="system")
        await emit_finding_event(conn, event_type, current, control, trigger=source, run_id=run_id)
        outcome[f"severity:{current['severity']}"] += 1
    return outcome, rejected


async def get_finding(conn: AsyncConnection, finding_id: str, *, lock: bool = False) -> dict | None:
    row = (await conn.execute(
        text(f"SELECT {FINDING_COLUMNS} FROM assessment.findings f WHERE f.finding_id = CAST(:id AS uuid)"
             + (" FOR UPDATE" if lock else "")), {"id": finding_id})).mappings().first()
    return dict(row) if row else None


async def set_lifecycle(conn: AsyncConnection, finding: dict, target: str, *, actor: str, note: str | None,
                        trigger: str, controls: dict[str, ControlMeta]) -> dict:
    row = dict((await conn.execute(
        text("UPDATE assessment.findings SET lifecycle_state = :state, resolved_at = CASE WHEN :state = 'resolved' "
             "THEN now() END WHERE finding_id = CAST(:id AS uuid) "
             f"RETURNING {FINDING_COLUMNS.replace('f.', '')}"),
        {"state": target, "id": str(finding["finding_id"])})).mappings().one())
    await add_history(conn, row, run_id=None, changed_by=actor, note=note)
    event_type = "finding.resolved" if target == "resolved" else "finding.updated"
    await emit_finding_event(conn, event_type, row, controls[row["control_id"]], trigger=trigger,
                             actor={"type": "user" if actor != "system" else "system", "id": actor})
    return row
