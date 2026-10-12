from __future__ import annotations

import time

from redis.asyncio import Redis

from .config import parse_rate


class RateLimiter:
    """Fixed-window counters in Redis, shared by all gateway replicas."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def hit(self, bucket: str, key: str, rate: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        limit, window = parse_rate(rate)
        now = int(time.time())
        window_start = now - now % window
        redis_key = f"rl:{bucket}:{key}:{window_start}"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(redis_key)
            pipe.expire(redis_key, window + 1)
            count, _ = await pipe.execute()
        if count > limit:
            return False, window_start + window - now
        return True, 0
