"""Point-in-time data for a report, read on the requesting user's behalf (ADR-0016).

The gateway passes one short-lived token per upstream; every read is limited to the user's own
permissions, so a section the user may not see is omitted and listed in `omitted`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

REPORT_TYPES = ("executive_summary", "technical", "remediation_roadmap", "mitre_mapping")
OPEN_LIFECYCLE = {"open", "acknowledged", "in_remediation"}
FINDING_FIELDS = ("finding_id", "asset_id", "control_id", "control_name", "category", "severity", "status",
                  "lifecycle_state", "subject_key", "recommendation", "first_seen_at", "last_seen_at")


@dataclass(frozen=True)
class Source:
    upstream: str
    path: str
    params: tuple[tuple[str, Any], ...] = ()
    permission: str = "risk:read"


SOURCES = {
    "summary": Source("ai", "/risk/summary"),
    "scenarios": Source("ai", "/risk/scenarios", (("status", "active"), ("limit", 100))),
    "remediation": Source("ai", "/risk/remediation", (("limit", 500),)),
    "mitre": Source("ai", "/risk/mitre"),
    "top_assets": Source("ai", "/risk/top-assets", (("limit", 10),)),
    "top_findings": Source("ai", "/risk/top-findings", (("limit", 200),)),
    "findings": Source("assessment", "/findings", permission="findings:read"),
}

REPORT_SOURCES = {
    "executive_summary": ("summary", "scenarios", "remediation", "mitre", "top_assets"),
    "technical": ("summary", "top_findings", "findings", "scenarios", "remediation"),
    "remediation_roadmap": ("summary", "remediation", "scenarios"),
    "mitre_mapping": ("summary", "mitre", "remediation"),
}


class SnapshotError(Exception):
    pass


def parse_delegation(header: str | None) -> dict[str, str]:
    tokens = {}
    for part in (header or "").split(","):
        key, sep, token = part.strip().partition("=")
        if sep and key and token:
            tokens[key] = token
    return tokens


def _strip_finding(finding: dict) -> dict:
    return {k: finding.get(k) for k in FINDING_FIELDS}


async def _get(client: httpx.AsyncClient, base_url: str, token: str, path: str, params) -> httpx.Response:
    try:
        return await client.get(base_url + path, params=params, headers={"authorization": f"Bearer {token}"})
    except httpx.HTTPError as exc:
        raise SnapshotError(f"{path} unavailable") from exc


async def _open_findings(client, base_url: str, token: str, max_findings: int) -> list[dict] | None:
    findings: list[dict] = []
    for status in ("FAIL", "WARNING"):
        cursor = None
        while len(findings) < max_findings:
            params = {"status": status, "limit": 500, **({"cursor": cursor} if cursor else {})}
            response = await _get(client, base_url, token, "/findings", params)
            if response.status_code == 403:
                return None
            if response.status_code != 200:
                raise SnapshotError(f"/findings returned {response.status_code}")
            page = response.json()
            findings.extend(_strip_finding(f) for f in page["items"] if f["lifecycle_state"] in OPEN_LIFECYCLE)
            cursor = page.get("next_cursor")
            if not cursor:
                break
    return findings[:max_findings]


async def collect(report_type: str, tokens: dict[str, str], urls: dict[str, str], *, max_findings: int,
                  timeout: float, transport: httpx.AsyncBaseTransport | None = None) -> dict:
    data: dict[str, Any] = {}
    omitted: list[str] = []
    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        for name in REPORT_SOURCES[report_type]:
            source = SOURCES[name]
            token = tokens.get(source.upstream)
            if token is None:
                raise SnapshotError(f"no delegated token for {source.upstream}")
            base_url = urls[source.upstream]
            if name == "findings":
                result = await _open_findings(client, base_url, token, max_findings)
            else:
                response = await _get(client, base_url, token, source.path, dict(source.params))
                if response.status_code not in (200, 403):
                    raise SnapshotError(f"{source.path} returned {response.status_code}")
                result = response.json() if response.status_code == 200 else None
            if result is None:
                omitted.append(f"{name} (requires {source.permission})")
            else:
                data[name] = result
    return {"data": data, "omitted": omitted}
