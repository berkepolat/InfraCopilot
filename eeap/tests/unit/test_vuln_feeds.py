import asyncio
import importlib
import io
import json
import zipfile
from datetime import UTC, datetime

import pytest
from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
vuln_feeds = importlib.import_module("assessment_app.vuln_feeds")
storage = importlib.import_module("assessment_app.storage")
linux_host = importlib.import_module("assessment_app.controls.linux_host")
net = importlib.import_module("assessment_app.controls.net")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def _record(advisory_id, ecosystems, fixed="1.2-3", package="openssl", modified="2026-10-01T00:00:00Z"):
    return {"id": advisory_id, "modified": modified,
            "affected": [{"package": {"ecosystem": e, "name": package},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}
                         for e in ecosystems]}


def _zip(records: dict[str, object]) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, record in records.items():
            archive.writestr(name, record if isinstance(record, str) else json.dumps(record))
    buffer.seek(0)
    return buffer


def _read(fileobj, batch_size=2):
    feed = vuln_feeds.scan_feed(fileobj)
    fileobj.seek(0)
    batches = list(vuln_feeds.iter_rows(fileobj, set(feed["ecosystems"]), batch_size))
    return feed, batches


def test_feed_passes_keep_only_the_covered_release_in_batches():
    feed, batches = _read(_zip({
        "CVE-1.json": _record("CVE-1", ["Debian:12", "Debian:11"]),
        "CVE-2.json": _record("CVE-2", ["Debian:12"], package="curl", modified="2026-10-05T08:00:00Z"),
        "DSA-3.json": _record("DSA-3", ["Debian:12", "Ubuntu:Pro:22.04:LTS"], fixed="2.0"),
        "broken.json": "{not json",
        "README.txt": "ignored",
    }))
    assert feed == {"ecosystems": ["Debian:12"], "records": 3,
                    "newest_modified": datetime(2026, 10, 5, 8, 0, tzinfo=UTC)}
    assert [[(r[0], r[1], r[2]) for r in batch] for batch in batches] == [
        [("Debian:12", "openssl", "CVE-1"), ("Debian:12", "curl", "CVE-2")], [("Debian:12", "openssl", "DSA-3")]]


@pytest.mark.parametrize(("payload", "message"), [
    (io.BytesIO(b"not a zip"), "not a zip archive"),
    (_zip({"a.txt": "x"}), "no OSV JSON records"),
    (_zip({"a.json": _record("GHSA-1", ["PyPI"])}), "supported distribution"),
])
def test_scan_feed_rejects_unusable_files(payload, message):
    with pytest.raises(vuln_feeds.FeedError, match=message):
        vuln_feeds.scan_feed(payload)


class _FakeResponse:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, *_):
        return self._data

    def close(self):
        pass

    def release_conn(self):
        pass


class _FakeMinio:
    def __init__(self, data: bytes = b""):
        self.data, self.ranges, self.uploaded = data, [], None

    def get_object(self, bucket, key, offset=0, length=0):
        self.ranges.append((offset, length))
        return _FakeResponse(self.data[offset:offset + length])

    def put_object(self, bucket, key, stream, length, **kwargs):
        assert length == -1 and kwargs["part_size"] == storage.STREAM_PART_SIZE
        parts = []
        while chunk := stream.read(5):
            parts.append(chunk)
        self.uploaded = b"".join(parts)


def test_object_reader_lets_zipfile_read_through_ranges():
    data = _zip({"CVE-1.json": _record("CVE-1", ["Alpine:v3.20"], fixed="3.3.2-r0")}).getvalue()
    client = _FakeMinio(data)
    reader = io.BufferedReader(storage.ObjectReader(client, "b", "k", len(data)), buffer_size=64)
    feed, batches = _read(reader)
    assert feed["ecosystems"] == ["Alpine:v3.20"] and batches[0][0][6] == "3.3.2-r0" and len(client.ranges) > 1
    assert all(offset + length <= len(data) for offset, length in client.ranges)


def _store(client) -> object:
    store = object.__new__(storage.ObjectStore)
    store._client = client
    return store


async def _chunks(*parts):
    for part in parts:
        yield part


def test_put_stream_uploads_and_hashes():
    client = _FakeMinio()
    size, sha = asyncio.run(_store(client).put_stream("b", "k", _chunks(b"PK\x03\x04", b"", b"rest-of-file"),
                                                      "application/zip", {}, 1000))
    assert client.uploaded == b"PK\x03\x04rest-of-file" and size == 16
    assert sha == __import__("hashlib").sha256(b"PK\x03\x04rest-of-file").hexdigest()


def test_put_stream_enforces_the_size_limit():
    client = _FakeMinio()
    with pytest.raises(storage.ObjectTooLarge):
        asyncio.run(_store(client).put_stream("b", "k", _chunks(b"x" * 600, b"x" * 600), "application/zip", {},
                                              1000))
    assert client.uploaded is None


def _vulnerabilities(vulnerable, age=3):
    return {"status": "ok", "ecosystem": "Alpine:v3.20", "feed_id": "f", "data_as_of": "2026-10-09T00:00:00+00:00",
            "data_age_days": age, "packages_checked": 40, "vulnerable": vulnerable}


def _evaluate(linux_probe):
    host = {"ip": "10.0.0.40", "probes": {"linux": {"status": "ok", "posture": {"host": {}}, **linux_probe}}}
    evaluation = net.evaluate({"hosts": [host]}, ["LIN-009"], NOW)
    return {r.subject_key: (r.status, r.severity, r.details.get("summary") if hasattr(r, "details") else None)
            for r in evaluation.observations}, evaluation.unassessed


def test_lin009_reports_each_vulnerable_package():
    group = {"package": "openssl", "installed": "3.3.1-r0", "fixed_version": "3.3.2-r0", "binaries": ["libcrypto3"],
             "severity": "Critical", "advisory_count": 7,
             "cves": [f"CVE-2024-{n}" for n in range(7)], "advisories": []}
    rows, unassessed = _evaluate({"vulnerabilities": _vulnerabilities([group])})
    assert {k: v[:2] for k, v in rows.items()} == {"pkg:openssl": ("FAIL", "Critical"), "vuln-data": ("PASS", None)}
    assert unassessed == {}


def test_lin009_passes_and_warns_about_old_data():
    rows, _ = _evaluate({"vulnerabilities": _vulnerabilities([], age=45)})
    assert {k: v[:2] for k, v in rows.items()} == {"packages": ("PASS", None), "vuln-data": ("WARNING", "Low")}


@pytest.mark.parametrize("probe", [{}, {"vulnerabilities": {"status": "no-data", "ecosystems": ["Debian:12"]}},
                                   {"vulnerabilities": {"status": "unsupported", "os": "Arch Linux"}}])
def test_lin009_without_data_keeps_findings_open(probe):
    rows, unassessed = _evaluate(probe)
    assert rows == {} and unassessed == {"10.0.0.40": ["LIN-009"]}
