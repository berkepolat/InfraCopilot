from __future__ import annotations

import asyncio
import socket

from fastapi import FastAPI

from eeap_shared.utils.events import StreamConsumer
from eeap_shared.utils.service import build_service_app

from .api import router
from .config import SCHEMA, settings
from .discovery import DISCOVERY_GROUP, discovery_handler


async def embedded_discovery_consumer(app: FastAPI, stop: asyncio.Event) -> None:
    consumer = StreamConsumer(app.state.redis, service=settings.service_name, group=DISCOVERY_GROUP,
                              streams=["eeap.discovery"], handler=discovery_handler(app.state.engine),
                              consumer_name=f"{settings.service_name}-{socket.gethostname()}")
    await consumer.run(stop)


app = build_service_app(
    settings,
    title="EEAP Asset Service",
    routers=[router],
    outbox_schema=SCHEMA,
    background=[embedded_discovery_consumer] if settings.eeap_run_embedded_worker else [],
)
