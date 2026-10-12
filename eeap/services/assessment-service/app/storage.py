"""Object storage access for import originals and evidence (MinIO, per-service credentials)."""
from __future__ import annotations

import asyncio
import io
from urllib.parse import urlparse

from minio import Minio

from .config import AssessmentSettings


class ObjectStore:
    def __init__(self, settings: AssessmentSettings) -> None:
        if not settings.minio_endpoint:
            raise RuntimeError("MINIO_ENDPOINT is not configured")
        endpoint = urlparse(settings.minio_endpoint)
        self._client = Minio(endpoint.netloc, access_key=settings.minio_access_key,
                             secret_key=settings.minio_secret_key(), secure=endpoint.scheme == "https")

    async def put(self, bucket: str, key: str, data: bytes, content_type: str, metadata: dict[str, str]) -> None:
        await asyncio.to_thread(self._client.put_object, bucket, key, io.BytesIO(data), len(data),
                                content_type=content_type, metadata=metadata)

    async def get(self, bucket: str, key: str, max_bytes: int) -> bytes:
        def _read() -> bytes:
            response = self._client.get_object(bucket, key)
            try:
                data = response.read(max_bytes + 1)
            finally:
                response.close()
                response.release_conn()
            if len(data) > max_bytes:
                raise ValueError("object exceeds the configured import size limit")
            return data

        return await asyncio.to_thread(_read)
