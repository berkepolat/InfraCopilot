"""Fix verification: a targeted reassessment of selected findings and its per-finding outcome.

``plan`` and ``outcome`` are pure; ``complete_verifications`` records the outcome when the run finishes.
"""
from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from .domain import GATING_STATES
from .findings_repo import add_history

MAX_FINDINGS = 50
PORT_SUBJECT = re.compile(r"^(?:tcp|web):(\d{1,5})$")
OUTCOMES = ("verified", "still_failing", "inconclusive", "failed")


class VerificationError(ValueError):
    """The selected findings cannot be verified by a reassessment."""


@dataclass
class VerificationPlan:
    module: str  # "AD" or "NET" (NET runs also evaluate the WIN and LINUX host controls)
    control_ids: list[str]
    ips: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)


def finding_module(control_id: str) -> str:
    return "AD" if control_id.startswith("AD-") else "NET"


def plan(findings: list[dict[str, Any]], default_ports: Collection[int]) -> VerificationPlan:
    """One reassessment run covering the findings' controls (and, for NET, their IPs and ports)."""
    if not findings:
        raise VerificationError("select at least one finding")
    if len(findings) > MAX_FINDINGS:
        raise VerificationError(f"at most {MAX_FINDINGS} findings can be verified at once")
    problems = []
    for f in findings:
        label = f"{f['control_id']} {f.get('subject_key') or f['asset_id']}"
        if f["source"] != "server":
            problems.append(f"{label}: {f['source']} findings are verified by a new {f['source']}")
        elif f["status"] == "PASS" or f["lifecycle_state"] not in GATING_STATES:
            problems.append(f"{label}: finding is {f['lifecycle_state']}, not open")
        elif finding_module(f["control_id"]) == "NET" and not f.get("ip"):
            problems.append(f"{label}: no IP address recorded")
    if problems:
        raise VerificationError("; ".join(problems[:5]) + (f" (+{len(problems) - 5} more)" if len(problems) > 5 else ""))
    modules = {finding_module(f["control_id"]) for f in findings}
    if len(modules) > 1:
        raise VerificationError("verify Active Directory and network/host findings separately")
    module = modules.pop()
    controls = sorted({f["control_id"] for f in findings})
    if module == "AD":
        return VerificationPlan("AD", controls)
    ips = sorted({f["ip"] for f in findings})
    ports = sorted({int(m.group(1)) for f in findings if (m := PORT_SUBJECT.match(f.get("subject_key") or ""))
                    and 0 < int(m.group(1)) <= 65535} - set(default_ports))
    return VerificationPlan("NET", controls, ips, ports)


def outcome(finding: dict[str, Any] | None, run_id: str, run_status: str) -> tuple[str, str]:
    """Verification result for one finding after its reassessment run."""
    if run_status == "failed":
        return "failed", "the verification run failed"
    if finding is None:
        return "inconclusive", "the finding no longer exists"
    if str(finding.get("last_seen_run_id") or "") != run_id:
        return "inconclusive", "the run could not evaluate this finding (host unreachable or not assessed)"
    if finding["status"] == "PASS":
        return "verified", "the reassessment no longer observes the weakness"
    return "still_failing", f"the reassessment still observes {finding['status']}"


async def complete_verifications(conn: AsyncConnection, run_id: str, run_status: str) -> int:
    """Records the outcome of every pending verification of this run; returns how many completed."""
    rows = (await conn.execute(text("""
        SELECT v.verification_id, v.finding_id, v.requested_by, f.status, f.severity, f.lifecycle_state,
               f.last_seen_run_id::text AS last_seen_run_id
        FROM assessment.finding_verifications v
        LEFT JOIN assessment.findings f ON f.finding_id = v.finding_id
        WHERE v.run_id = CAST(:run AS uuid) AND v.status = 'pending' FOR UPDATE OF v"""),
        {"run": run_id})).mappings().all()
    for row in rows:
        finding = dict(row) if row["status"] is not None else None
        status, summary = outcome(finding, run_id, run_status)
        await conn.execute(text(
            "UPDATE assessment.finding_verifications SET status = :status, summary = :summary, "
            "observed_status = :observed, completed_at = now() WHERE verification_id = :id"),
            {"status": status, "summary": summary, "observed": row["status"], "id": row["verification_id"]})
        if finding is not None and status in ("verified", "still_failing"):
            await add_history(conn, {**finding, "finding_id": row["finding_id"]}, run_id=run_id,
                              changed_by=row["requested_by"],
                              note="fix verified" if status == "verified" else "fix verification: still failing")
    return len(rows)
