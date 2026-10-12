from __future__ import annotations

import httpx


def minio_check(endpoint: str):
    url = endpoint.rstrip("/") + "/minio/health/live"

    async def check() -> None:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(url)
            response.raise_for_status()

    return check
