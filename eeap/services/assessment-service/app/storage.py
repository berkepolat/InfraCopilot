"""Object storage access for import originals and evidence (MinIO, per-service credentials)."""
from __future__ import annotations

import asyncio
import hashlib
import io
import queue
from collections.abc import AsyncIterator
from urllib.parse import urlparse

from minio import Minio

from .config import AssessmentSettings

STREAM_PART_SIZE = 16 * 1024 * 1024


class ObjectTooLarge(ValueError):
    pass


class _QueueReader:
    """File-like object for the MinIO uploader thread, fed by the request handler through a queue."""

    def __init__(self) -> None:
        self.queue: queue.Queue[bytes | BaseException | None] = queue.Queue(maxsize=8)
        self._buffer = b""
        self._eof = False

    def read(self, size: int = -1) -> bytes:
        while not self._eof and (not self._buffer or (size < 0)):
            item = self.queue.get()
            if item is None:
                self._eof = True
            elif isinstance(item, BaseException):
                raise item
            else:
                self._buffer += item
                if size >= 0:
                    break
        if size < 0:
            data, self._buffer = self._buffer, b""
        else:
            data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data


class ObjectReader(io.RawIOBase):
    """Seekable read-only view of an object through ranged GETs (no local copy)."""

    def __init__(self, client: Minio, bucket: str, key: str, size: int) -> None:
        self._client, self._bucket, self._key, self._size, self._pos = client, bucket, key, size, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self._size}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def readinto(self, buffer) -> int:
        length = min(len(buffer), self._size - self._pos)
        if length <= 0:
            return 0
        response = self._client.get_object(self._bucket, self._key, offset=self._pos, length=length)
        try:
            data = response.read()
        finally:
            response.close()
            response.release_conn()
        buffer[:len(data)] = data
        self._pos += len(data)
        return len(data)


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

    async def put_stream(self, bucket: str, key: str, chunks: AsyncIterator[bytes], content_type: str,
                         metadata: dict[str, str], max_bytes: int) -> tuple[int, str]:
        """Streams chunks into a multipart upload with bounded memory; returns (size, sha256)."""
        reader = _QueueReader()
        upload = asyncio.ensure_future(asyncio.to_thread(
            self._client.put_object, bucket, key, reader, -1, content_type=content_type, metadata=metadata,
            part_size=STREAM_PART_SIZE))
        digest, size = hashlib.sha256(), 0

        async def send(item) -> None:
            while True:
                if upload.done():
                    await upload
                    raise RuntimeError("object upload ended before the stream")
                try:
                    reader.queue.put_nowait(item)
                    return
                except queue.Full:
                    await asyncio.sleep(0.01)

        try:
            async for chunk in chunks:
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    raise ObjectTooLarge(f"object exceeds {max_bytes} bytes")
                digest.update(chunk)
                await send(chunk)
        except BaseException:
            if not upload.done():
                await asyncio.to_thread(reader.queue.put, RuntimeError("upload aborted"))
            try:
                await upload
            except Exception:  # noqa: BLE001, S110 — the original error is raised below
                pass
            raise
        await send(None)
        await upload
        return size, digest.hexdigest()

    def open(self, bucket: str, key: str) -> io.BufferedReader:
        """Blocking; use from a worker thread."""
        size = self._client.stat_object(bucket, key).size
        return io.BufferedReader(ObjectReader(self._client, bucket, key, size), buffer_size=8 * 1024 * 1024)

    async def remove(self, bucket: str, key: str) -> None:
        await asyncio.to_thread(self._client.remove_object, bucket, key)

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
