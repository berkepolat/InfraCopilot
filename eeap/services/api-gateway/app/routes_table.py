"""Public route table: path prefix -> upstream service and required permission per method."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Route:
    prefix: str
    upstream: str
    permissions: dict[str, str]
    overrides: tuple[tuple[str, re.Pattern[str], str], ...] = field(default_factory=tuple)
    max_body_bytes: int | None = None  # None = gateway default
    # Forward POST/PUT bodies as a stream instead of buffering them (large uploads).
    stream_body: bool = False
    # method -> upstreams the service may read on the user's behalf during this request (ADR-0016)
    delegate: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # method -> extra per-user rate limit, e.g. "20/hour"
    rate_limits: dict[str, str] = field(default_factory=dict)
    # GET requests that are audited: (pattern, action)
    audited_reads: tuple[tuple[re.Pattern[str], str], ...] = field(default_factory=tuple)

    def audited_read(self, path: str) -> str | None:
        return next((action for pattern, action in self.audited_reads if pattern.fullmatch(path)), None)

    def matches(self, path: str) -> bool:
        return path == self.prefix or path.startswith(self.prefix + "/")

    def permission_for(self, method: str, path: str) -> str | None:
        for override_method, pattern, permission in self.overrides:
            if override_method == method and pattern.fullmatch(path):
                return permission
        return self.permissions.get(method)


def _o(method: str, pattern: str, permission: str) -> tuple[str, re.Pattern[str], str]:
    return method, re.compile(pattern), permission


_RW = {"GET": "{r}:read", "POST": "{r}:write", "PUT": "{r}:write", "PATCH": "{r}:write", "DELETE": "{r}:delete"}

ROUTES: tuple[Route, ...] = (
    Route("/assets", "asset", {k: v.format(r="assets") for k, v in _RW.items()}),
    Route("/owners", "asset", {"GET": "assets:read", "POST": "assets:write", "PATCH": "assets:write"}),
    Route("/controls", "assessment", {"GET": "controls:read", "PATCH": "controls:manage"}),
    Route("/assessments", "assessment", {"GET": "assessments:read", "POST": "assessments:run"},
          overrides=(_o("POST", r"/assessments/profiles(/.*)?", "assessments:manage"),
                     _o("PATCH", r"/assessments/profiles/.+", "assessments:manage"))),
    Route("/findings", "assessment", {"GET": "findings:read", "POST": "findings:triage"},
          overrides=(_o("POST", r"/findings/[^/]+/risk-acceptance", "findings:accept_risk"),
                     _o("GET", r"/findings/[^/]+/evidence", "evidence:read"))),
    Route("/network-services", "assessment", {"GET": "assets:read"}),
    Route("/ssh-host-keys", "assessment", {"GET": "assets:read", "DELETE": "assessments:manage"}),
    Route("/integrations", "assessment", {m: "integrations:manage" for m in ("GET", "POST", "PATCH", "DELETE")}),
    Route("/imports", "assessment", {"GET": "imports:create", "POST": "imports:create"},
          max_body_bytes=50 * 1024 * 1024),
    Route("/vulnerability-feeds", "assessment", {"GET": "assessments:read", "POST": "assessments:manage"},
          max_body_bytes=1024 * 1024 * 1024, stream_body=True),
    Route("/graph", "relationship", {"GET": "graph:read"}),
    Route("/risk", "ai", {"GET": "risk:read", "POST": "risk:manage", "PATCH": "risk:manage"}),
    Route("/reports", "reporting", {"GET": "reports:read", "POST": "reports:create"},
          delegate={"POST": ("ai", "assessment")}, rate_limits={"POST": "20/hour"},
          audited_reads=((re.compile(r"/reports/[^/]+/download/[a-z]+"), "reports.download"),)),
)


def resolve(path: str) -> Route | None:
    if "/internal" in path or ".." in path:
        return None
    return next((r for r in ROUTES if r.matches(path)), None)
