from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

HTTP_REQUESTS = Counter(
    "http_requests_total", "HTTP requests", ["service", "method", "route", "status"]
)
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["service", "method", "route"]
)
EVENTS_PUBLISHED = Counter("eeap_events_published_total", "Events published", ["service", "stream", "type"])
EVENTS_CONSUMED = Counter(
    "eeap_events_consumed_total", "Events consumed", ["service", "group", "type", "outcome"]
)


def metrics_response() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
