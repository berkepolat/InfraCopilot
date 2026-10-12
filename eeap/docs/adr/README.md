# Architecture Decision Records

Format: [Michael Nygard ADR](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).
Statuses: `Proposed` → `Accepted` → (`Superseded by ADR-XXXX` | `Deprecated`).
ADRs are immutable once accepted; changes are made by a new ADR that supersedes the old one.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-microservice-decomposition.md) | Microservice decomposition along assessment pipeline stages | Accepted |
| [0002](0002-technology-stack.md) | Python/FastAPI backend, Next.js frontend | Accepted |
| [0003](0003-postgresql-schema-per-service.md) | Single PostgreSQL cluster with schema-per-service | Accepted |
| [0004](0004-graph-storage-in-postgresql.md) | Exposure graph stored in PostgreSQL, analyzed in-process | Accepted |
| [0005](0005-redis-streams-event-bus.md) | Redis Streams with transactional outbox as the event bus | Accepted |
| [0006](0006-minio-object-storage.md) | MinIO for evidence, imports and reports | Accepted |
| [0007](0007-authentication-and-rbac-at-gateway.md) | JWT authentication and RBAC enforced at the gateway, re-checked in services | Accepted |
| [0008](0008-agent-pull-model-mtls.md) | Pull-based agents with mTLS enrollment and no command channel | Accepted |
| [0009](0009-collector-control-plugin-model.md) | Collector / Control plugin model and Standard Finding Format | Accepted |
| [0010](0010-deterministic-scoring-ai-advisory.md) | Deterministic scoring and correlation; LLMs advisory only | Accepted |
| [0011](0011-defensive-scope-guardrails.md) | Defensive-only scope guardrails | Accepted |
| [0012](0012-observability.md) | Observability: JSON logs, Prometheus metrics, OpenTelemetry traces | Accepted |
| [0013](0013-secrets-management.md) | Secrets via Docker secrets and `*_FILE`, external store in production | Accepted |
| [0014](0014-integration-adapter-framework.md) | Integration adapters normalize third-party data | Accepted |
| [0015](0015-ai-engine-event-fed-read-model.md) | AI Engine scores from an event-fed local read model | Accepted |
| [0016](0016-delegated-report-reads.md) | Reports read data with gateway-delegated, per-upstream user tokens | Accepted |
| [0017](0017-winrm-jea-posture-collection.md) | Credentialed Windows posture over WinRM through a JEA endpoint | Accepted |
| [0018](0018-ssh-forced-command-posture.md) | Linux posture over SSH with a forced, read-only command | Accepted |
| [0019](0019-offline-osv-package-vulnerabilities.md) | Known vulnerable packages from uploaded OSV data | Accepted |
| [0020](0020-exploitation-and-exposure-in-risk-scoring.md) | Exploitation evidence and network exposure in risk scoring | Accepted |
| [0021](0021-windows-patch-status-from-wua-cache.md) | Windows patch status from the Windows Update Agent cache | Accepted |
