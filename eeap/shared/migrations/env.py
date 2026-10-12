"""Generic Alembic environment shared by all services.

Each service supplies its own version_locations and version_table_schema, so every schema
keeps an independent migration history (ADR-0003).
"""
import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config
URL = config.attributes["url"]
VERSION_SCHEMA = config.attributes["version_table_schema"]


def _run(connection) -> None:
    context.configure(connection=connection, version_table_schema=VERSION_SCHEMA, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()


async def _main() -> None:
    engine = create_async_engine(URL)
    async with engine.connect() as connection:
        await connection.run_sync(_run)
        await connection.commit()
    await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline migrations are not supported")
asyncio.run(_main())
