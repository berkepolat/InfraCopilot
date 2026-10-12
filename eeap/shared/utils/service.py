"""Wires the standard runtime pieces (DB, Redis, readiness, outbox relay, token verifier) into an app."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncEngine

from .app_factory import ReadinessCheck, create_app
from .db import create_engine, database_check
from .events import OutboxRelay
from .internal_auth import InternalTokenVerifier
from .minio_check import minio_check
from .redis_client import create_redis, redis_check
from .settings import ServiceSettings

BackgroundTask = Callable[[FastAPI, asyncio.Event], Awaitable[None]]


def build_service_app(
    settings: ServiceSettings,
    *,
    title: str,
    routers: Iterable[APIRouter],
    outbox_schema: str | None = None,
    extra_checks: dict[str, ReadinessCheck] | None = None,
    background: Iterable[BackgroundTask] = (),
    on_shutdown: Iterable[Callable[[], Awaitable[None]]] = (),
) -> FastAPI:
    engine = create_engine(settings) if settings.database_url else None
    redis = create_redis(settings)

    checks: dict[str, ReadinessCheck] = {"redis": redis_check(redis)}
    if engine is not None:
        checks["database"] = database_check(engine)
    if settings.minio_endpoint:
        checks["minio"] = minio_check(settings.minio_endpoint)
    checks.update(extra_checks or {})

    background = list(background)
    on_shutdown = list(on_shutdown)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        stop = asyncio.Event()
        tasks = []
        if engine is not None and outbox_schema:
            relay = OutboxRelay(engine, redis, outbox_schema, settings.service_name)
            tasks.append(asyncio.create_task(relay.run(stop)))
        tasks.extend(asyncio.create_task(task(app, stop)) for task in background)
        try:
            yield
        finally:
            stop.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            for hook in on_shutdown:
                await hook()
            await redis.aclose()
            if engine is not None:
                await engine.dispose()

    app = create_app(
        service_name=settings.service_name, title=title, routers=routers,
        readiness_checks=checks, lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.redis = redis
    public_key = settings.internal_token_public_key()
    if public_key:
        app.state.token_verifier = InternalTokenVerifier(public_key, settings.service_name)
    return app


def get_engine(request: Request) -> AsyncEngine:
    return request.app.state.engine
