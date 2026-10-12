"""Reconciles discovery.asset_observed events into the inventory and applies classification rules."""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from eeap_shared.utils.events import enqueue_event, mark_processed, new_envelope

from .config import SCHEMA, settings

logger = logging.getLogger("eeap.asset.discovery")

DISCOVERY_GROUP = "asset-service.discovery"
CLASSIFIED_FIELDS = ("tier", "criticality", "environment")
EVENT_FIELDS = ("asset_id", "hostname", "asset_type", "criticality", "tier", "environment", "owner")
ID_TYPES = frozenset({"ip", "mac", "fqdn", "hostname", "ad_object_sid", "ad_object_guid", "ad_dn",
                      "cloud_resource_id", "serial", "agent_id"})


def rule_matches(condition: dict, asset: dict) -> bool:
    for key, expected in condition.items():
        if key == "tags_any":
            if not set(expected) & set(asset.get("tags") or []):
                return False
        elif asset.get(key) != expected:
            return False
    return True


def classify(rules: list[dict], asset: dict) -> dict:
    """Values from matching rules; rules are applied in priority order and the first value for a field wins."""
    result: dict = {}
    for rule in rules:
        if rule_matches(rule["condition"], asset):
            for field in CLASSIFIED_FIELDS:
                if field in rule["set_values"] and field not in result:
                    result[field] = rule["set_values"][field]
    return result


_SELECT = (
    "SELECT a.asset_id, a.hostname, a.fqdn::text AS fqdn, a.asset_type, a.criticality, a.criticality_locked, "
    "a.tier, o.name AS owner, a.environment, a.os_family, a.os_version, a.domain::text AS domain, a.status, "
    "a.tags, a.classification_source FROM asset.assets a LEFT JOIN asset.owners o ON o.owner_id = a.owner_id "
    "WHERE a.asset_id = :id"
)


async def _load_rules(conn: AsyncConnection) -> list[dict]:
    rows = await conn.execute(text("SELECT condition, set_values FROM asset.classification_rules "
                                   "WHERE enabled ORDER BY priority, name"))
    return [dict(r) for r in rows.mappings()]


def _placeholder_name(name: str | None, asset_id: str) -> bool:
    if not name or name == asset_id:
        return True
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


async def reconcile(conn: AsyncConnection, data: dict, observed_at: datetime) -> tuple[dict | None, dict]:
    """Creates or refreshes the observed asset. Returns (before, after)."""
    asset_id = data["asset_id"]
    before = (await conn.execute(text(_SELECT + " FOR UPDATE OF a"), {"id": asset_id})).mappings().first()
    before = dict(before) if before else None
    values = {"id": asset_id, "hostname": data.get("hostname") or asset_id, "fqdn": data.get("fqdn"),
              "asset_type": data.get("asset_type") or "Other", "os_family": data.get("os_family"),
              "os_version": data.get("os_version"), "domain": data.get("domain"),
              "tags": sorted(set(data.get("tags") or [])), "observed": observed_at}
    if before is None:
        await conn.execute(text(
            "INSERT INTO asset.assets (asset_id, hostname, fqdn, asset_type, os_family, os_version, domain, tags, "
            "status, classification_source, first_seen_at, last_seen_at) VALUES (:id, :hostname, :fqdn, "
            ":asset_type, :os_family, :os_version, :domain, :tags, 'discovered', 'discovery', :observed, :observed)"),
            values)
    else:
        # Discovery fills gaps and refreshes OS data; it never overrides manually classified asset types.
        # A placeholder name (the IP or asset id) is replaced once a host reports its real name.
        values["hostname"] = (data["hostname"] if _placeholder_name(before["hostname"], asset_id)
                              and data.get("hostname") and not _placeholder_name(data["hostname"], asset_id)
                              else before["hostname"])
        await conn.execute(text(
            "UPDATE asset.assets SET last_seen_at = greatest(last_seen_at, :observed), hostname = :hostname, "
            "fqdn = coalesce(fqdn, :fqdn), domain = coalesce(domain, :domain), "
            "os_family = coalesce(:os_family, os_family), os_version = coalesce(:os_version, os_version), "
            "asset_type = CASE WHEN classification_source = 'manual' THEN asset_type ELSE :asset_type END, "
            "tags = ARRAY(SELECT DISTINCT t FROM unnest(tags || CAST(:tags AS text[])) AS t ORDER BY t) "
            "WHERE asset_id = :id"), values)

    current = dict((await conn.execute(text(_SELECT), {"id": asset_id})).mappings().one())
    if not current["criticality_locked"]:
        changes = {k: v for k, v in classify(await _load_rules(conn), current).items() if current[k] != v}
        if changes:
            assignments = ", ".join(f"{k} = :{k}" for k in changes)
            source = "rule" if current["classification_source"] != "manual" else "manual"
            await conn.execute(text(f"UPDATE asset.assets SET {assignments}, classification_source = :src "
                                    "WHERE asset_id = :id"), {**changes, "src": source, "id": asset_id})

    for identifier in data.get("identifiers") or []:
        if identifier.get("id_type") not in ID_TYPES or not identifier.get("value"):
            continue
        # A stable identifier already bound to another asset is left there (reported, not moved).
        inserted = (await conn.execute(text(
            "INSERT INTO asset.asset_identifiers (asset_id, id_type, value, source, first_seen_at, last_seen_at) "
            "VALUES (:id, :type, :value, :source, :observed, :observed) ON CONFLICT DO NOTHING RETURNING 1"),
            {"id": asset_id, "type": identifier["id_type"], "value": str(identifier["value"])[:1024],
             "source": data.get("source") or "discovery", "observed": observed_at})).scalar()
        if inserted is None:
            owner = (await conn.execute(text(
                "UPDATE asset.asset_identifiers SET last_seen_at = greatest(last_seen_at, :observed) "
                "WHERE id_type = :type AND value = :value AND asset_id = :id RETURNING asset_id"),
                {"id": asset_id, "type": identifier["id_type"], "value": str(identifier["value"])[:1024],
                 "observed": observed_at})).scalar()
            if owner is None:
                logger.warning("identifier belongs to another asset",
                               extra={"asset_id": asset_id, "id_type": identifier["id_type"]})

    after = dict((await conn.execute(text(_SELECT), {"id": asset_id})).mappings().one())
    return before, after


def discovery_handler(engine: AsyncEngine):
    async def handle(envelope: dict) -> None:
        if envelope["type"] != "discovery.asset_observed":
            return
        data = envelope["data"]
        observed_at = datetime.fromisoformat(data.get("observed_at") or envelope["occurred_at"])
        async with engine.begin() as conn:
            if not await mark_processed(conn, SCHEMA, DISCOVERY_GROUP, envelope["event_id"]):
                return
            before, after = await reconcile(conn, data, observed_at)
            actor = {"type": "system", "id": data.get("source") or "discovery"}
            asset_id = after["asset_id"]
            if before is None:
                await enqueue_event(conn, SCHEMA, "eeap.asset", new_envelope(
                    event_type="asset.created", source=settings.service_name, subject=asset_id, actor=actor,
                    causation_id=envelope["event_id"], data={k: after[k] for k in EVENT_FIELDS}))
                return
            changed = {k: after[k] for k in after if after[k] != before[k]}
            if changed:
                await enqueue_event(conn, SCHEMA, "eeap.asset", new_envelope(
                    event_type="asset.updated", source=settings.service_name, subject=asset_id, actor=actor,
                    causation_id=envelope["event_id"],
                    data={"asset_id": asset_id, "changes": json.loads(json.dumps(changed, default=str)),
                          **{k: after[k] for k in EVENT_FIELDS if k != "asset_id"}}))
            if before["criticality"] != after["criticality"]:
                await enqueue_event(conn, SCHEMA, "eeap.asset", new_envelope(
                    event_type="asset.criticality_changed", source=settings.service_name, subject=asset_id,
                    actor=actor, causation_id=envelope["event_id"],
                    data={"asset_id": asset_id, "old": before["criticality"], "new": after["criticality"]}))

    return handle
