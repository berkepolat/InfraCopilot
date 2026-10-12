# ADR-0001: Microservice decomposition along assessment pipeline stages

- Status: Accepted
- Date: 2026-10-12

## Context

EEAP's pipeline (discover → collect → evaluate → graph → correlate → score → report) has
stages with very different load profiles: collection and evaluation are bursty and
I/O-bound, graph analytics are CPU/memory-heavy, reporting is CPU-bound (PDF rendering),
and the API is latency-sensitive. Teams will extend different stages independently
(new control modules, new integrations, new report templates).

## Decision

Decompose into six backend services aligned to pipeline stages and bounded contexts:
API Gateway, Asset, Assessment, Relationship Engine, AI Engine, Reporting; plus the
Frontend and two agent types. Each service runs in two roles from one image (`api`,
`worker`) so that asynchronous workloads scale independently of request handling.

## Alternatives considered

- **Modular monolith**: simpler operations, but couples scaling of graph analytics and PDF
  rendering to API latency, and weakens data ownership boundaries. Still a valid fallback
  for very small deployments.
- **Finer-grained services** (separate scoring, MITRE, scheduler services): more network
  hops and operational overhead without independent scaling benefit at expected volume.

## Consequences

- (+) Independent scaling, deployment and ownership per stage.
- (+) Clear contracts (REST + events) force a stable Standard Finding Format.
- (−) Distributed-system concerns: eventual consistency, idempotency, tracing — addressed by
  ADR-0005 (outbox/inbox) and ADR-0012 (observability).
- (−) More containers to operate; mitigated by a single Compose file and shared service template.
