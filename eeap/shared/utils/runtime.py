"""Container entrypoint dispatching on EEAP_ROLE: api | worker | migrate."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from prometheus_client import start_http_server

from ..logging import configure_logging
from .db import database_url_with_password
from .events import EventHandler, StreamConsumer
from .redis_client import create_redis
from .settings import ServiceSettings

logger = logging.getLogger("eeap.runtime")

MIGRATIONS_ENV_DIR = Path(__file__).resolve().parent.parent / "migrations"


WorkerTask = Callable[[asyncio.Event], Awaitable[None]]


@dataclass(frozen=True)
class Subscription:
    group: str
    streams: list[str]
    handler: EventHandler
    # Runs alongside the consumer in whichever worker hosts this group (e.g. debounced recomputation).
    background: WorkerTask | None = None


@dataclass(frozen=True)
class ServiceRuntime:
    settings: ServiceSettings
    asgi_app: str
    versions_dir: Path
    version_table_schema: str
    subscriptions: Callable[[ServiceSettings], list[Subscription]] | None = None


def run_migrations(settings: ServiceSettings, versions_dir: Path, schema: str) -> None:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_ENV_DIR))
    cfg.set_main_option("version_locations", str(versions_dir))
    cfg.attributes["url"] = database_url_with_password(settings)
    cfg.attributes["version_table_schema"] = schema
    command.upgrade(cfg, "head")
    logger.info("migrations applied", extra={"schema": schema})


async def run_worker(settings: ServiceSettings, subscriptions: list[Subscription]) -> None:
    enabled = set(settings.consumer_groups)
    selected = [s for s in subscriptions if not enabled or s.group in enabled]
    if not selected:
        raise RuntimeError("no consumer groups selected for this worker")
    start_http_server(settings.worker_metrics_port)
    redis = create_redis(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    consumer_name = f"{settings.service_name}-{socket.gethostname()}"
    consumers = [
        StreamConsumer(redis, service=settings.service_name, group=s.group, streams=s.streams,
                       handler=s.handler, consumer_name=consumer_name,
                       heartbeat_path=settings.worker_heartbeat_path)
        for s in selected
    ]
    tasks = [c.run(stop) for c in consumers] + [s.background(stop) for s in selected if s.background]
    try:
        await asyncio.gather(*tasks)
    finally:
        await redis.aclose()
        logger.info("worker stopped")


def main(runtime: ServiceRuntime) -> None:
    settings = runtime.settings
    configure_logging(settings.service_name, settings.log_level)
    role = os.environ.get("EEAP_ROLE", settings.eeap_role)
    logger.info("starting", extra={"role": role, "env": settings.eeap_env})
    if role == "api":
        import uvicorn

        uvicorn.run(runtime.asgi_app, host="0.0.0.0", port=8000, log_config=None,
                    access_log=False, proxy_headers=False, server_header=False)
    elif role == "worker":
        if runtime.subscriptions is None:
            raise SystemExit(f"{settings.service_name} has no worker role")
        asyncio.run(run_worker(settings, runtime.subscriptions(settings)))
    elif role == "migrate":
        run_migrations(settings, runtime.versions_dir, runtime.version_table_schema)
    else:
        raise SystemExit(f"unknown EEAP_ROLE {role!r}")
