"""Report objects in MinIO (bucket eeap-reports, reporting-service credentials only)."""
from __future__ import annotations

import asyncio
import io
from urllib.parse import urlparse

from minio import Minio

from .config import ReportingSettings


def snapshot_key(report_id: str) -> str:
    return f"{report_id}/snapshot.json"


def artifact_key(report_id: str, fmt: str) -> str:
    return f"{report_id}/report.{fmt}"


class ReportStore:
    def __init__(self, settings: ReportingSettings) -> None:
        if not settings.minio_endpoint:
            raise RuntimeError("MINIO_ENDPOINT is not configured")
        endpoint = urlparse(settings.minio_endpoint)
        self._client = Minio(endpoint.netloc, access_key=settings.minio_access_key,
                             secret_key=settings.minio_secret_key(), secure=endpoint.scheme == "https")
        self.bucket = settings.reports_bucket

    async def put(self, key: str, data: bytes, content_type: str) -> None:
        await asyncio.to_thread(self._client.put_object, self.bucket, key, io.BytesIO(data), len(data),
                                content_type=content_type)

    async def get(self, key: str) -> bytes:
        def _read() -> bytes:
            response = self._client.get_object(self.bucket, key)
            try:
                return response.read()
            finally:
                response.close()
                response.release_conn()

        return await asyncio.to_thread(_read)
