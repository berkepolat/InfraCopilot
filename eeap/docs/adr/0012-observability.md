# ADR-0012: Observability — JSON logs, Prometheus metrics, OpenTelemetry traces

- Status: Accepted
- Date: 2026-10-12

## Context

A distributed, event-driven pipeline is hard to debug without correlated telemetry.
Enterprise customers forward logs to their SIEM and run Prometheus-compatible monitoring.

## Decision

- **Logs**: structured JSON to stdout via `shared/logging` (fields: `ts, level, service,
  msg, request_id, correlation_id, trace_id, user_id`); secret redaction filter; Docker
  json-file rotation; Loki/Promtail in the `observability` profile.
- **Metrics**: Prometheus `/metrics` on every service (HTTP RED metrics, event
  publish/consume counters, stream lag, domain gauges); Grafana dashboards shipped.
- **Traces**: OpenTelemetry SDK instrumentation (FastAPI, SQLAlchemy, Redis, httpx); trace
  context propagated over HTTP headers and in the event envelope; OTLP exporter optional.
- **Health**: `/health/live` and `/health/ready` on all services.

## Consequences

- (+) End-to-end correlation from an API call through events to report generation.
- (−) Slight overhead; sampling configurable via `OTEL_TRACES_SAMPLER_ARG`.
