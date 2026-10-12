"""FastAPI application factory implementing the common service runtime contract (doc 02 §1)."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable
from contextlib import AbstractAsyncContextManager

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ..logging import request_id_var
from .metrics import HTTP_LATENCY, HTTP_REQUESTS, metrics_response

ReadinessCheck = Callable[[], Awaitable[None]]
logger = logging.getLogger("eeap.http")

PROBLEM_JSON = "application/problem+json"


def problem(status: int, title: str, detail: str | None = None, **extra) -> JSONResponse:
    body = {"type": "about:blank", "title": title, "status": status}
    if detail:
        body["detail"] = detail
    request_id = request_id_var.get()
    if request_id:
        body["request_id"] = request_id
    body.update(extra)
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON)


def create_app(
    *,
    service_name: str,
    title: str,
    routers: Iterable[APIRouter] = (),
    readiness_checks: dict[str, ReadinessCheck] | None = None,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[None]] | None = None,
) -> FastAPI:
    app = FastAPI(title=title, version="0.1.0", lifespan=lifespan, docs_url="/docs", redoc_url=None)
    app.state.readiness_checks = dict(readiness_checks or {})

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or f"req-{uuid.uuid4().hex}"
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            elapsed = time.perf_counter() - started
            HTTP_REQUESTS.labels(service_name, request.method, route_path, str(status)).inc()
            HTTP_LATENCY.labels(service_name, request.method, route_path).observe(elapsed)
            if not route_path.startswith(("/health", "/metrics")):
                logger.info(
                    "%s %s %s", request.method, request.url.path, status,
                    extra={"status": status, "duration_ms": round(elapsed * 1000, 1)},
                )
            request_id_var.reset(token)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException):
        response = problem(exc.status_code, title=_title_for(exc.status_code), detail=str(exc.detail))
        for key, value in (exc.headers or {}).items():
            response.headers[key] = value
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError):
        errors = [
            {"field": ".".join(str(p) for p in err["loc"][1:]), "message": err["msg"]} for err in exc.errors()
        ]
        return problem(422, "Validation failed", f"{len(errors)} field(s) invalid", errors=errors)

    @app.exception_handler(Exception)
    async def unhandled_handler(_: Request, exc: Exception):
        logger.exception("unhandled error")
        return problem(500, "Internal Server Error")

    @app.get("/health/live", include_in_schema=False)
    async def live():
        return {"status": "ok", "service": service_name}

    @app.get("/health/ready", include_in_schema=False)
    async def ready():
        checks = app.state.readiness_checks
        results = await asyncio.gather(
            *(asyncio.wait_for(check(), timeout=2.0) for check in checks.values()), return_exceptions=True
        )
        status = {name: ("ok" if not isinstance(r, BaseException) else f"error: {type(r).__name__}")
                  for name, r in zip(checks, results)}
        healthy = all(v == "ok" for v in status.values())
        return JSONResponse({"status": "ok" if healthy else "degraded", "checks": status},
                            status_code=200 if healthy else 503)

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        return metrics_response()

    for router in routers:
        app.include_router(router)
    return app


def _title_for(status: int) -> str:
    return {
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
        409: "Conflict", 412: "Precondition Failed", 413: "Payload Too Large",
        422: "Validation failed", 423: "Locked", 429: "Too Many Requests",
        502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
    }.get(status, "Error")
