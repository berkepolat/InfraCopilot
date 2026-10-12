# 05 — API Contracts

| Contract | Artifact |
|----------|----------|
| Public REST API (gateway) | [`docs/api/openapi.yaml`](../api/openapi.yaml) (OpenAPI 3.1) |
| Standard Finding | [`shared/schemas/finding.schema.json`](../../shared/schemas/finding.schema.json) |
| Asset | [`shared/schemas/asset.schema.json`](../../shared/schemas/asset.schema.json) |
| Relationship | [`shared/schemas/relationship.schema.json`](../../shared/schemas/relationship.schema.json) |
| Agent job / result | [`shared/schemas/agent-job.schema.json`](../../shared/schemas/agent-job.schema.json) |
| Event envelope | [`shared/schemas/event-envelope.schema.json`](../../shared/schemas/event-envelope.schema.json) |

JSON Schemas are the single source of truth; Pydantic models in `shared/models` and
TypeScript types in `frontend` are generated from them in CI and checked for drift by
contract tests (`tests/contract`).

## 1. Conventions

| Topic | Rule |
|-------|------|
| Base path | `/api/v1`; breaking changes → `/api/v2` with ≥ 6 months overlap |
| Media type | `application/json`; errors `application/problem+json` (RFC 9457) |
| Naming | `snake_case` fields, plural resource nouns, verbs only for actions (`/cancel`, `/revoke`) |
| Pagination | Keyset: `?limit=50&cursor=…` → `{items, next_cursor}` |
| Filtering | Repeated query params for multi-value (`?severity=High&severity=Critical`) |
| Concurrency | `ETag` on single resources; `If-Match` required on `PATCH` |
| Idempotency | `Idempotency-Key` header on `POST` that create runs/reports; stored 24 h in Redis |
| Async operations | `202 Accepted` + resource with `status`; clients poll or subscribe via SSE (Phase 3) |
| Time | RFC 3339 UTC |
| Limits | Request body 1 MiB (JSON) / 50 MiB (agent upload) / 500 MiB (imports) |
| Correlation | `X-Request-ID` echoed in every response and log line |

## 2. Endpoint summary (public)

| Area | Endpoints | Upstream |
|------|-----------|----------|
| Auth | `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `GET /auth/me`, `GET /auth/.well-known/jwks.json` | gateway |
| Users | `GET/POST /users`, `PUT /users/{id}/roles`, `POST /api-keys` | gateway |
| Agents (admin) | `GET /agents`, `GET /agents/{id}`, `POST /agents/{id}/suspend`, `/revoke`, `POST /agents/enrollment-tokens` | gateway |
| Agent channel | `POST /agent/enroll`, `/agent/token`, `/agent/renew`, `/agent/heartbeat`, `GET /agent/jobs`, `POST /agent/jobs/{id}/result`, `POST /agent/uploads` | gateway → assessment-service |
| Assets | `GET/POST /assets`, `POST /assets/bulk`, `GET/PATCH/DELETE /assets/{id}`, `GET /assets/{id}/findings`, `GET/POST /owners` | asset-service |
| Assessments | `GET/POST /assessments/profiles`, `GET/POST /assessments/runs`, `GET /assessments/runs/{id}`, `POST …/cancel`, `GET …/jobs` | assessment-service |
| Controls | `GET /controls`, `PATCH /controls/{id}` | assessment-service |
| Findings | `GET /findings`, `GET /findings/{id}`, `POST /findings/{id}/lifecycle`, `POST …/risk-acceptance`, `GET …/evidence` | assessment-service (+ ai for scores) |
| Graph | `GET /graph/nodes`, `GET /graph/nodes/{id}/neighborhood`, `GET /graph/exposure-paths`, `GET /graph/concentration-areas`, `GET /graph/relationships` | relationship-engine |
| Risk | `GET /risk/summary`, `/risk/scores`, `/risk/scenarios`, `/risk/scenarios/{id}`, `/risk/mitre`, `/risk/remediation`, `POST /risk/analyze` | ai-engine |
| Reports | `GET/POST /reports`, `GET /reports/{id}`, `GET /reports/{id}/download/{format}` | reporting-service |
| Integrations | `GET/POST /integrations`, `POST /imports` | assessment-service |
| Audit | `GET /audit/events` | gateway |
| System | `GET /health/live`, `/health/ready`, `/version` | each |

## 3. Internal service contracts

Services expose their domain APIs on `:8000` without the `/api/v1` gateway prefix change
(same paths). Additional **internal-only** endpoints (blocked at the gateway route table):

| Service | Internal endpoint | Consumer |
|---------|-------------------|----------|
| asset-service | `POST /internal/assets/resolve` — resolve identifiers → `asset_id` | assessment-service, relationship-engine |
| asset-service | `GET /internal/assets/criticality?ids=…` (batch) | ai-engine |
| assessment-service | `POST /internal/agent/jobs/pull`, `POST /internal/agent/results` | gateway (agent channel) |
| assessment-service | `GET /internal/findings/snapshot?as_of=…` (streaming NDJSON) | ai-engine, reporting-service |
| relationship-engine | `GET /internal/graph/metrics?node_keys=…` | ai-engine |
| ai-engine | `GET /internal/risk/snapshot?as_of=…` | reporting-service |

**Internal service token** (minted by gateway for each proxied request, or by a service's
own client credentials for background calls):

```json
{
  "iss": "eeap-gateway", "aud": "asset-service", "sub": "user:3f9c…", "act": "api-gateway",
  "perms": ["assets:read"], "scope": {"owner_ids": ["…"]},
  "rid": "req-01J…", "iat": 1760256000, "exp": 1760256060
}
```

Services re-check `perms` (defense in depth) and apply `scope` for `asset_owner` users.

## 4. Event catalog (Redis Streams)

Envelope: `event-envelope.schema.json`. Stream names: `eeap.<domain>`. Retention:
`MAXLEN ~ 1,000,000` and 7-day min-ID trimming. Delivery: at-least-once; consumers are
idempotent via `event_inbox`.

| Stream | Event type | Producer | Consumers | `data` (summary) |
|--------|-----------|----------|-----------|------------------|
| `eeap.asset` | `asset.created` / `asset.updated` / `asset.retired` | asset | relationship, ai | `asset_id`, `hostname`, `criticality`, `tier`, `environment`, `owner` (+ `changes` on update) |
| `eeap.asset` | `asset.criticality_changed` | asset | ai | `asset_id`, `old`, `new` |
| `eeap.discovery` | `discovery.asset_observed` | assessment | asset | `asset_id`, `hostname`, `fqdn`, `asset_type`, `os_family`, `os_version`, `domain`, `tags`, `identifiers[{id_type,value}]`, `source`, `run_id`, `observed_at` |
| `eeap.assessment` | `assessment.run_requested` | assessment (API) | assessment (orchestrator) | `run_id`, `trigger`, `control_ids` |
| `eeap.assessment` | `assessment.run_started` / `assessment.run_completed` | assessment | ai, reporting, frontend (SSE) | `run_id`, `stats`, `full_scope` |
| `eeap.agent` | `agent.enrolled` / `agent.revoked` / `agent.stale` | gateway | assessment, asset | `agent_id`, `hostname`, `platform` |
| `eeap.agent` | `agent.result_submitted` | assessment (API, after storing payload) | assessment (evaluator) | `job_id`, `agent_id`, `evidence_id` |
| `eeap.imports` | `import.uploaded` | assessment (API) | assessment (imports worker) | `import_id`, `run_id`, `source_type`, `size_bytes` |
| `eeap.finding` | `finding.created` / `finding.updated` / `finding.resolved` | assessment | relationship, ai | `finding_id`, `asset_id`, `control_id`, `category`, `status`, `severity`, `lifecycle_state`, `subject_key`, `exploitability`, `privilege_impact`, `run_id`, `trigger` (`import`/`triage`/`expiry`) — consumed by the AI read model (ADR-0015) |
| `eeap.relationship` | `relationship.observed` | assessment | relationship | batch of relationship objects (or `data_ref`) |
| `eeap.graph` | `graph.updated` / `graph.analysis_completed` | relationship | ai | `analysis_id`, changed node count |
| `eeap.risk` | `risk.scores_updated` / `correlation.completed` | ai | reporting, frontend | counts, org score |
| `eeap.report` | `report.requested` / `report.generated` / `report.failed` | reporting | reporting worker, frontend | `report_id`, formats |
| `eeap.audit` | `audit.event` | gateway | SIEM forwarder (optional) | audit row |

Consumer groups are named `<service>.<purpose>` (e.g. `ai-engine.scoring`). Messages
failing 5 times move to `eeap.dlq` with the error and original stream ID.

## 5. Error model

```json
{
  "type": "https://docs.eeap.local/errors/validation",
  "title": "Validation failed",
  "status": 422,
  "detail": "1 field is invalid",
  "instance": "/api/v1/assets",
  "request_id": "req-01JA4…",
  "errors": [{"field": "criticality", "message": "must be one of Critical, High, Medium, Low"}]
}
```

| Status | Use |
|--------|-----|
| 400 | Malformed request |
| 401 | Missing/invalid/expired credentials |
| 403 | Authenticated but lacking permission or outside scope |
| 404 | Not found (also used instead of 403 for scoped objects to avoid enumeration) |
| 409 | State conflict (invalid lifecycle transition, duplicate) |
| 412 | ETag mismatch |
| 413 | Payload too large |
| 422 | Schema validation failed |
| 429 | Rate limited (`Retry-After`) |
| 503 | Upstream unavailable (gateway circuit breaker open) |
