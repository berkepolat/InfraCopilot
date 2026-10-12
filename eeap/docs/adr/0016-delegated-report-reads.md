# ADR-0016: Reports read data with gateway-delegated, per-upstream user tokens

- Status: Accepted
- Date: 2026-10-12

## Context

Reports combine data owned by other services (risk scores, scenarios, the remediation roadmap
and ATT&CK view in the AI Engine; finding details in the Assessment Service). ADR-0003 rules out
cross-schema SQL, and ADR-0015 notes that background workers have no credential for
service-to-service calls: internal tokens are minted only by the gateway, are audience-bound and
live 60 s. A report must also never show data its requester is not allowed to read.

## Decision

- Routes in the gateway table can declare `delegate` upstreams per method. For `POST /reports`
  the gateway mints, besides the normal token for the Reporting Service, one token per listed
  upstream (`ai`, `assessment`): same user, same permissions, audience = that upstream only,
  60 s TTL. They travel in the `x-eeap-delegation` header, which clients cannot set (the gateway
  forwards an allow-list of request headers only).
- The Reporting Service uses them **within the request** to read the public APIs of those
  services (`/risk/*`, `/findings`), so upstream RBAC applies unchanged. A 403 omits the section
  and records it in `omitted`; other failures abort with 502.
- The collected snapshot is stored in MinIO (`<report_id>/snapshot.json`) with `snapshot_at`;
  the worker renders only from that snapshot and holds no tokens. Reports are therefore
  reproducible and rendering never calls other services.
- Raw evidence is not copied into reports.

## Consequences

- (+) No new secret class and no service-to-service credentials; a compromised Reporting
  Service only sees tokens of requests in flight, each limited to one upstream and 60 s.
- (+) Reports respect the requester's permissions by construction.
- (−) Snapshot collection adds latency to `POST /reports` (bounded by `UPSTREAM_TIMEOUT_SECONDS`
  and the gateway timeout); very large finding sets are capped (`REPORT_MAX_FINDINGS`).
- (−) Scheduled reports (`reporting.report_schedules`) have no user request to delegate from and
  need a separate decision before they are implemented.
