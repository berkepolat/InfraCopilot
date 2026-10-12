# ADR-0003: Single PostgreSQL cluster with schema-per-service

- Status: Accepted
- Date: 2026-10-12

## Context

Microservices should own their data, but enterprise customers expect a deployable,
backed-up and supportable footprint. Running six database servers for a single-node
install is disproportionate.

## Decision

One PostgreSQL 16 cluster, one database `eeap`, one schema and one login role per service
(`iam`/`audit` → gateway, `asset`, `assessment`, `graph`, `ai`, `reporting`). Each role
owns only its schema. No cross-schema foreign keys or joins; cross-service references are
logical IDs. Each service migrates its own schema with Alembic.

## Alternatives considered

- Database-per-service on separate clusters: strongest isolation, highest ops cost.
- Shared schema: fastest to build, but destroys ownership boundaries and makes independent
  migrations unsafe.
- Document DB for findings: flexible, but loses relational integrity, transactions with the
  outbox, and mature tooling.

## Consequences

- (+) One backup/restore unit; simple T1 operations.
- (+) Can split any schema into its own cluster later by changing `DATABASE_URL` only.
- (−) Shared resource contention (noisy neighbor); mitigated by per-role connection limits,
  pool sizes, and moving to separate clusters at T3 if needed.
- (−) Reporting needs cross-domain data → obtained via internal snapshot APIs, not SQL joins.
