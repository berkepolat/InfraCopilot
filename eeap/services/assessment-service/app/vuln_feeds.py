"""Uploaded OSV vulnerability feeds: import into fixed-version ranges and per-host matching for LIN-009.

A feed is an OSV ``all.zip`` downloaded by an administrator (e.g. from
https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip) and uploaded through the API, or
exploitation evidence for the matched CVEs (CISA KEV JSON, EPSS CSV; see ``exploit_data``).
Nothing is fetched from the internet and no host inventory leaves the platform.
"""
from __future__ import annotations

import asyncio
import json
import logging
import zipfile
from collections import Counter
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from eeap_shared.utils.events import mark_processed

from . import exploit_data, vulns
from .config import SCHEMA, AssessmentSettings
from .controls import win_host
from .storage import ObjectStore

logger = logging.getLogger("eeap.assessment.vuln_feeds")

FEED_EVENT = "vuln_feed.uploaded"
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 1_000_000
INSERT_BATCH = 5000
DATA_MAX_AGE_DAYS = 30
SUPPORTED = "Alpine, Debian, Ubuntu, Rocky Linux and AlmaLinux"


class FeedError(ValueError):
    pass


def _records(fileobj) -> Iterator[dict]:
    try:
        archive = zipfile.ZipFile(fileobj)
    except zipfile.BadZipFile as exc:
        raise FeedError("the file is not a zip archive") from exc
    count = 0
    with archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.endswith(".json") or info.file_size > MAX_RECORD_BYTES:
                continue
            count += 1
            if count > MAX_RECORDS:
                raise FeedError(f"the archive has more than {MAX_RECORDS} records")
            with archive.open(info) as member:
                raw = member.read(MAX_RECORD_BYTES + 1)
            try:
                doc = json.loads(raw)
            except ValueError:
                continue
            if isinstance(doc, dict):
                yield doc


def _rows(doc: dict) -> tuple[set[str], list[tuple]]:
    ecosystems, rows = vulns.parse_advisory(doc)
    # Ubuntu Pro / FIPS channels are separate ecosystems; hosts are matched against the standard release.
    return ({e for e in ecosystems if ":Pro:" not in e and ":FIPS" not in e},
            [r for r in rows if ":Pro:" not in r[0] and ":FIPS" not in r[0]])


def scan_feed(fileobj) -> dict[str, Any]:
    """First pass (blocking): the releases the archive covers, record count and data date."""
    record_ecosystems: list[set[str]] = []
    records, newest = 0, None
    for doc in _records(fileobj):
        records += 1
        record_ecosystems.append(_rows(doc)[0])
        modified = doc.get("modified")
        if isinstance(modified, str) and (newest is None or modified > newest):
            newest = modified
    if records == 0:
        raise FeedError("the archive contains no OSV JSON records")
    covered = vulns.covered_ecosystems(record_ecosystems)
    if not covered:
        raise FeedError(f"the archive contains no OSV records for a supported distribution ({SUPPORTED})")
    return {"ecosystems": sorted(covered), "records": records, "newest_modified": _parse_time(newest)}


def iter_rows(fileobj, covered: set[str], batch_size: int = INSERT_BATCH) -> Iterator[list[tuple]]:
    """Second pass (blocking): fixed-version rows of the covered releases in batches; memory stays bounded."""
    batch: list[tuple] = []
    for doc in _records(fileobj):
        batch.extend(dict.fromkeys((e, p, a, tuple(c), s, i, f) for e, p, a, c, s, i, f in _rows(doc)[1]
                                   if e in covered))
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


async def _fail(engine: AsyncEngine, feed_id: str, error: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE assessment.vuln_feeds SET status = 'failed', error = :e, "
                                "completed_at = now() WHERE feed_id = CAST(:id AS uuid)"),
                           {"e": error[:2000], "id": feed_id})
    logger.warning("vulnerability feed import failed", extra={"feed_id": feed_id, "error": error[:200]})


async def import_feed(engine: AsyncEngine, store: ObjectStore, settings: AssessmentSettings, envelope: dict,
                      group: str) -> None:
    feed_id = envelope["data"]["feed_id"]
    async with engine.begin() as conn:
        record = (await conn.execute(text(
            "UPDATE assessment.vuln_feeds SET status = 'importing' WHERE feed_id = CAST(:id AS uuid) "
            "AND status IN ('queued', 'importing') RETURNING bucket, object_key, kind"),
            {"id": feed_id})).mappings().first()
    if record is None:
        return
    if record["kind"] != "osv":
        await _import_exploit_data(engine, store, envelope, group, feed_id, record)
        return

    def _scan() -> dict[str, Any]:
        with store.open(record["bucket"], record["object_key"]) as fileobj:
            return scan_feed(fileobj)

    try:
        feed = await asyncio.to_thread(_scan)
        ecosystems = feed["ecosystems"]
        per_ecosystem: Counter[str] = Counter()
        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, group, envelope["event_id"]):
                return
            await conn.execute(text("DELETE FROM assessment.vuln_ranges WHERE ecosystem = ANY(:e)"),
                               {"e": ecosystems})
            insert = text("INSERT INTO assessment.vuln_ranges (ecosystem, package, advisory_id, cves, severity, "
                          "introduced, fixed) VALUES (:e, :p, :a, CAST(:c AS text[]), :s, :i, :f)")
            fileobj = await asyncio.to_thread(store.open, record["bucket"], record["object_key"])
            batches = iter_rows(fileobj, set(ecosystems))
            try:
                while (batch := await asyncio.to_thread(next, batches, None)) is not None:
                    per_ecosystem.update(r[0] for r in batch)
                    await conn.execute(insert, [{"e": e, "p": p, "a": a, "c": list(c), "s": s, "i": i, "f": f}
                                                for e, p, a, c, s, i, f in batch])
            finally:
                fileobj.close()
            await _record_import(conn, feed_id, feed, per_ecosystem)
    except (FeedError, zipfile.BadZipFile, OSError, EOFError) as exc:
        await _fail(engine, feed_id, str(exc) or exc.__class__.__name__)
        return
    await _remove_upload(store, record, feed_id)
    logger.info("vulnerability feed imported", extra={"feed_id": feed_id, "ecosystems": ecosystems,
                                                       "ranges": sum(per_ecosystem.values())})


async def _remove_upload(store: ObjectStore, record: dict, feed_id: str) -> None:
    try:
        await store.remove(record["bucket"], record["object_key"])
    except Exception:  # noqa: BLE001 — the imported data is already committed
        logger.warning("could not remove the uploaded feed object", extra={"feed_id": feed_id})


async def _import_exploit_data(engine: AsyncEngine, store: ObjectStore, envelope: dict, group: str, feed_id: str,
                               record: dict) -> None:
    """KEV or EPSS: small enough to parse in memory; each upload replaces the previous data set."""
    limit = exploit_data.MAX_KEV_BYTES if record["kind"] == "kev" else exploit_data.MAX_EPSS_BYTES

    def _parse() -> dict[str, Any]:
        with store.open(record["bucket"], record["object_key"]) as fileobj:
            return exploit_data.parse(record["kind"], fileobj.read(limit + 1))

    try:
        data = await asyncio.to_thread(_parse)
    except (exploit_data.ExploitDataError, OSError) as exc:
        await _fail(engine, feed_id, str(exc) or exc.__class__.__name__)
        return
    async with engine.begin() as conn:
        if not await mark_processed(conn, SCHEMA, group, envelope["event_id"]):
            return
        if data["kind"] == "kev":
            await conn.execute(text("DELETE FROM assessment.vuln_kev"))
            insert = text("INSERT INTO assessment.vuln_kev (cve, vendor, product, name, date_added, ransomware) "
                          "VALUES (:c, :v, :p, :n, :d, :r)")
            params = [{"c": c, "v": v, "p": p, "n": n, "d": d, "r": r} for c, v, p, n, d, r in data["rows"]]
        else:
            await conn.execute(text("DELETE FROM assessment.vuln_epss"))
            insert = text("INSERT INTO assessment.vuln_epss (cve, epss, percentile) VALUES (:c, :e, :p)")
            params = [{"c": c, "e": e, "p": p} for c, e, p in data["rows"]]
        for start in range(0, len(params), INSERT_BATCH):
            await conn.execute(insert, params[start:start + INSERT_BATCH])
        await conn.execute(text(
            "UPDATE assessment.vuln_feeds SET status = 'completed', records = :n, newest_modified = :m, "
            "data_version = :v, error = NULL, completed_at = now() WHERE feed_id = CAST(:id AS uuid)"),
            {"n": len(params), "m": data["as_of"], "v": data["version"], "id": feed_id})
    await _remove_upload(store, record, feed_id)
    logger.info("exploit data imported", extra={"feed_id": feed_id, "kind": data["kind"], "records": len(params)})


async def _record_import(conn: AsyncConnection, feed_id: str, feed: dict, per_ecosystem: Counter) -> None:
    ecosystems = feed["ecosystems"]
    for ecosystem in ecosystems:
        await conn.execute(text(
            "INSERT INTO assessment.vuln_ecosystems (ecosystem, feed_id, ranges, newest_modified, imported_at) "
            "VALUES (:e, CAST(:id AS uuid), :n, :m, now()) ON CONFLICT (ecosystem) DO UPDATE SET "
            "feed_id = EXCLUDED.feed_id, ranges = EXCLUDED.ranges, newest_modified = EXCLUDED.newest_modified, "
            "imported_at = EXCLUDED.imported_at"),
            {"e": ecosystem, "id": feed_id, "n": per_ecosystem.get(ecosystem, 0), "m": feed["newest_modified"]})
    await conn.execute(text(
        "UPDATE assessment.vuln_feeds SET status = 'completed', ecosystems = :e, records = :r, ranges = :n, "
        "newest_modified = :m, error = NULL, completed_at = now() WHERE feed_id = CAST(:id AS uuid)"),
        {"e": ecosystems, "r": feed["records"], "n": sum(per_ecosystem.values()), "m": feed["newest_modified"],
         "id": feed_id})


async def attach_vulnerabilities(conn: AsyncConnection, linux_hosts: dict[str, dict], now: datetime) -> None:
    """Adds ``vulnerabilities`` to every assessed host whose posture includes a package inventory."""
    for result in linux_hosts.values():
        posture = result.get("posture") if result.get("status") == "ok" else None
        inventory = (posture or {}).get("packages") or {}
        if not inventory.get("pkg"):
            continue
        host = posture.get("host") or {}
        candidates = vulns.host_ecosystems(host.get("os_id"), host.get("os_version_id"))
        if not candidates:
            result["vulnerabilities"] = {"status": "unsupported", "os": host.get("os_pretty")}
            continue
        feed = (await conn.execute(text(
            "SELECT ecosystem, feed_id::text, newest_modified, imported_at FROM assessment.vuln_ecosystems "
            "WHERE ecosystem = ANY(:e) ORDER BY array_position(CAST(:e AS text[]), ecosystem) LIMIT 1"),
            {"e": candidates})).mappings().first()
        if feed is None:
            result["vulnerabilities"] = {"status": "no-data", "ecosystems": candidates}
            continue
        packages = vulns.parse_packages(inventory["pkg"], inventory.get("format"))
        names = sorted({p["name"] for p in packages} | {p["source"] for p in packages})
        ranges = [dict(r) for r in (await conn.execute(text(
            "SELECT package, advisory_id, cves, severity, introduced, fixed FROM assessment.vuln_ranges "
            "WHERE ecosystem = :e AND package = ANY(:p)"), {"e": feed["ecosystem"], "p": names})).mappings()]
        reference = feed["newest_modified"] or feed["imported_at"]
        result["vulnerabilities"] = {
            "status": "ok", "ecosystem": feed["ecosystem"], "feed_id": feed["feed_id"],
            "data_as_of": reference.isoformat(), "data_age_days": max(0, (now - reference).days),
            "packages_checked": len(packages),
            "vulnerable": vulns.match_packages(packages, ranges, feed["ecosystem"]),
        }
    await attach_exploit_data(conn, [r["vulnerabilities"] for r in linux_hosts.values()
                                     if (r.get("vulnerabilities") or {}).get("status") == "ok"])


async def attach_update_exploit_data(conn: AsyncConnection, windows_hosts: dict[str, dict]) -> None:
    """Adds KEV/EPSS context to the missing Windows security updates (WIN-010) of every assessed host."""
    wrapped = []
    for result in windows_hosts.values():
        missing = win_host.security_updates(result.get("posture") if result.get("status") == "ok" else None)
        if missing:
            wrapped.append((result, {"vulnerable": missing}))
    if wrapped:
        await attach_exploit_data(conn, [w for _, w in wrapped])
        for result, w in wrapped:
            result["exploit_data"] = w["exploit_data"]


async def attach_exploit_data(conn: AsyncConnection, results: list[dict]) -> None:
    """Adds KEV listing, EPSS and a per-package exploitability to every vulnerable package group."""
    groups = [g for r in results for g in r["vulnerable"]]
    sources = {r["kind"]: r for r in (await conn.execute(text(
        "SELECT DISTINCT ON (kind) kind, newest_modified, completed_at, data_version FROM assessment.vuln_feeds "
        "WHERE kind IN ('kev', 'epss') AND status = 'completed' ORDER BY kind, completed_at DESC"))).mappings()}
    context = {kind: {"as_of": (row["newest_modified"] or row["completed_at"]).isoformat(),
                      "version": row["data_version"]} for kind, row in sources.items()}
    for result in results:
        result["exploit_data"] = context
    cves = sorted({c for g in groups for c in g["cves"]})
    if not cves or not sources:
        return
    kev = {r["cve"]: dict(r) for r in (await conn.execute(text(
        "SELECT cve, ransomware FROM assessment.vuln_kev WHERE cve = ANY(:c)"), {"c": cves})).mappings()}
    epss = {r.cve: (float(r.epss), float(r.percentile)) for r in await conn.execute(text(
        "SELECT cve, epss, percentile FROM assessment.vuln_epss WHERE cve = ANY(:c)"), {"c": cves})}
    for group in groups:
        group.update(exploit_data.assess(group["cves"], kev, epss, "epss" in sources))
