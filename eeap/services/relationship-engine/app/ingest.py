"""Writes relationship.observed facts into the exposure graph (graph.nodes / graph.edges)."""
from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

# Inventory (asset events) and collectors both mark Tier-0; each keeps its own flag in properties so one
# source can clear its claim without overriding the other.
_UPSERT_NODE = text(
    "INSERT INTO graph.nodes (node_key, node_type, display_name, asset_id, domain, is_tier0, is_privileged, "
    "enabled, properties, source) "
    "VALUES (:node_key, :node_type, :display_name, :asset_id, :domain, :is_tier0, :is_privileged, :enabled, "
    "CAST(:properties AS jsonb), :source) "
    "ON CONFLICT (node_key) DO UPDATE SET "
    "node_type = EXCLUDED.node_type, display_name = EXCLUDED.display_name, "
    "asset_id = COALESCE(EXCLUDED.asset_id, graph.nodes.asset_id), "
    "domain = COALESCE(EXCLUDED.domain, graph.nodes.domain), "
    "is_tier0 = EXCLUDED.is_tier0 OR COALESCE((graph.nodes.properties->>'inventory_tier0')::boolean, false), "
    "is_privileged = EXCLUDED.is_privileged, enabled = EXCLUDED.enabled, "
    "properties = graph.nodes.properties || EXCLUDED.properties, "
    "last_seen_at = now(), deleted_at = NULL"
)

_UPSERT_EDGE = text(
    "INSERT INTO graph.edges (source_node_id, target_node_id, relationship, properties, origin, observed_run_id) "
    "VALUES (CAST(:source_id AS uuid), CAST(:target_id AS uuid), :relationship, CAST(:properties AS jsonb), "
    ":origin, CAST(:run_id AS uuid)) "
    "ON CONFLICT (source_node_id, target_node_id, relationship) DO UPDATE SET "
    "properties = EXCLUDED.properties, origin = EXCLUDED.origin, observed_run_id = EXCLUDED.observed_run_id, "
    "is_active = true, last_seen_at = now()"
)


@dataclass(frozen=True)
class IngestResult:
    nodes: int
    edges: int
    deactivated: int


def _node_params(node: dict, source: str) -> dict:
    properties = dict(node.get("properties") or {})
    properties["collector_tier0"] = bool(node.get("is_tier0"))
    return {
        "node_key": node["node_key"], "node_type": node["node_type"],
        "display_name": node.get("display_name") or node["node_key"], "asset_id": node.get("asset_id"),
        "domain": node.get("domain"), "is_tier0": bool(node.get("is_tier0")),
        "is_privileged": bool(node.get("is_privileged")), "enabled": node.get("enabled"),
        "properties": json.dumps(properties), "source": source,
    }


async def ingest_relationships(conn: AsyncConnection, data: dict, source: str) -> IngestResult:
    """Upserts nodes and edges; with `complete` set, collector edges of the scope not seen in this run go inactive."""
    relationships = data.get("relationships") or []
    run_id, scope = data.get("run_id"), data.get("scope")

    nodes: dict[str, dict] = {}
    for rel in relationships:
        for end in ("source_node", "target_node"):
            node = rel.get(end)
            if node:
                nodes[node["node_key"]] = _node_params(node, source)
    if nodes:
        await conn.execute(_UPSERT_NODE, list(nodes.values()))

    keys = {k for rel in relationships for k in (rel["source"], rel["target"])}
    ids: dict[str, str] = {}
    if keys:
        rows = await conn.execute(text("SELECT node_key, node_id::text FROM graph.nodes WHERE node_key = ANY(:keys)"),
                                  {"keys": sorted(keys)})
        ids = {r[0]: r[1] for r in rows}

    edges: dict[tuple[str, str, str], dict] = {}
    for rel in relationships:
        source_id, target_id = ids.get(rel["source"]), ids.get(rel["target"])
        if source_id is None or target_id is None or source_id == target_id:
            continue
        properties = dict(rel.get("properties") or {})
        if scope:
            properties.setdefault("scope", scope)
        edges[(source_id, target_id, rel["relationship"])] = {
            "source_id": source_id, "target_id": target_id, "relationship": rel["relationship"],
            "properties": json.dumps(properties), "origin": rel.get("origin") or "collector",
            "run_id": rel.get("observed_run_id") or run_id,
        }
    if edges:
        await conn.execute(_UPSERT_EDGE, list(edges.values()))

    deactivated = 0
    if data.get("complete") and scope and run_id:
        result = await conn.execute(
            text("UPDATE graph.edges SET is_active = false WHERE is_active AND origin = 'collector' "
                 "AND properties->>'scope' = :scope AND observed_run_id IS DISTINCT FROM CAST(:run_id AS uuid)"),
            {"scope": scope, "run_id": run_id})
        deactivated = result.rowcount or 0
    return IngestResult(nodes=len(nodes), edges=len(edges), deactivated=deactivated)
