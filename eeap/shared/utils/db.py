from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from .settings import ServiceSettings


def database_url_with_password(settings: ServiceSettings) -> str:
    if not settings.database_url:
        raise RuntimeError("DATABASE_URL is not configured")
    url = make_url(settings.database_url)
    password = settings.database_password()
    if password:
        url = url.set(password=password)
    return url.render_as_string(hide_password=False)


def create_engine(settings: ServiceSettings, pool_size: int = 10) -> AsyncEngine:
    return create_async_engine(
        database_url_with_password(settings),
        pool_size=pool_size,
        max_overflow=5,
        pool_pre_ping=True,
        connect_args={"server_settings": {"application_name": settings.service_name}},
    )


def database_check(engine: AsyncEngine):
    async def check() -> None:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    return check
