# ADR-0002: Python/FastAPI backend, Next.js frontend

- Status: Accepted
- Date: 2026-10-12

## Context

Backend services need strong data-validation tooling, a rich ecosystem for LDAP, network
protocol inspection, XML/JSON parsing (third-party imports), graph analytics and LLM
integration. The frontend needs dashboards, data grids and an interactive graph view.

## Decision

- Backend: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 (async) + Alembic, `redis-py`,
  `boto3`/`minio` client, NetworkX, Jinja2 + WeasyPrint for reports.
- Frontend: Next.js 14 (App Router), React 18, TypeScript (strict), TanStack Query,
  Cytoscape.js, ECharts.
- Agents: .NET 8 for Windows (native registry/WMI/LSA policy APIs, Windows Service
  hosting, Authenticode signing); Go for Linux (single static binary, no runtime deps).

## Alternatives considered

- Go or Java for all backend services: better raw throughput, but slower iteration and a
  weaker ecosystem for security-data parsing and AI tooling; throughput is not the bottleneck.
- Python agents: requires shipping an interpreter to endpoints; larger attack surface.

## Consequences

- (+) One language across backend services; shared Pydantic models from JSON Schemas.
- (+) OpenAPI generated natively by FastAPI; typed TS client generated for the frontend.
- (−) CPU-heavy graph analytics in Python: bounded by limits in ADR-0004; can move hot
  paths to Rust/NumPy extensions or a graph DB later.
