from __future__ import annotations

from redis.asyncio import Redis

from .settings import ServiceSettings


def create_redis(settings: ServiceSettings) -> Redis:
    return Redis.from_url(settings.redis_url, password=settings.redis_password(), decode_responses=True)


def redis_check(redis: Redis):
    async def check() -> None:
        if not await redis.ping():
            raise RuntimeError("redis ping failed")

    return check
