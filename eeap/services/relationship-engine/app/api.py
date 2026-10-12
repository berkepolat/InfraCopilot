from __future__ import annotations

import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.pagination import decode_cursor, page
from eeap_shared.utils.service import get_engine

from .config import settings

router = APIRouter(tags=["Graph"])

NodeType = Literal["User", "Computer", "Group", "ServiceAccount", "Tier0Asset"]
RelationshipType = Literal["MemberOf", "AdministrativeAccess", "Delegation", "AuthenticationRisk", "RemoteAccess",
                           "PrivilegedAccess"]
AreaType = Literal["privileged_group_sprawl", "admin_access_hub", "delegation_cluster", "service_account_hub",
                   "tier0_exposure"]

LATEST_ANALYSIS = ("(SELECT analysis_id FROM graph.analysis_runs WHERE status = 'completed' "
                   "ORDER BY completed_at DESC LIMIT 1)")


def _uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid node id") from exc


async def _nodes(conn: AsyncConnection, node_ids: list[str]) -> list[dict]:
    if not node_ids:
        return []
    rows = (await conn.execute(text(
        "SELECT n.node_id::text AS node_id, n.node_key, n.node_type, n.display_name, n.asset_id, n.is_tier0, "
        "n.is_privileged, m.tier0_reachable, m.min_hops_to_tier0, m.propagation_score, m.concentration_score "
        "FROM graph.nodes n LEFT JOIN graph.node_metrics m "
        f"ON m.node_id = n.node_id AND m.analysis_id = {LATEST_ANALYSIS} "
        "WHERE n.node_id = ANY(CAST(:ids AS uuid[]))"), {"ids": node_ids})).mappings()
    nodes = []
    for r in rows:
        nodes.append({
            "node_id": r["node_id"], "node_key": r["node_key"], "node_type": r["node_type"],
            "display_name": r["display_name"], "asset_id": r["asset_id"], "is_tier0": r["is_tier0"],
            "is_privileged": r["is_privileged"],
            "metrics": {"tier0_reachable": bool(r["tier0_reachable"]), "min_hops_to_tier0": r["min_hops_to_tier0"],
                        "propagation_score": float(r["propagation_score"] or 0),
                        "concentration_score": float(r["concentration_score"] or 0)},
        })
    return nodes


async def _edges(conn: AsyncConnection, edge_ids: list[str]) -> list[dict]:
    if not edge_ids:
        return []
    rows = (await conn.execute(text(
        "SELECT edge_id::text AS edge_id, source_node_id::text AS source_node_id, "
        "target_node_id::text AS target_node_id, relationship, properties FROM graph.edges "
        "WHERE edge_id = ANY(CAST(:ids AS uuid[]))"), {"ids": edge_ids})).mappings()
    return [dict(r) for r in rows]


@router.get("/graph/nodes")
async def list_nodes(
    limit: int = Query(50, ge=1, le=500),
    cursor: str | None = None,
    node_type: NodeType | None = None,
    is_tier0: bool | None = None,
    q: str | None = Query(None, max_length=200),
    _: Principal = Depends(require_permission("graph:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clauses, params = ["n.deleted_at IS NULL"], {"limit": limit + 1}
    after = decode_cursor(cursor)
    if after:
        clauses.append("n.node_key > :after")
        params["after"] = after["node_key"]
    if node_type:
        clauses.append("n.node_type = :node_type")
        params["node_type"] = node_type
    if is_tier0 is not None:
        clauses.append("n.is_tier0 = :is_tier0")
        params["is_tier0"] = is_tier0
    if q:
        clauses.append("n.display_name ILIKE :q")
        params["q"] = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql = ("SELECT n.node_id, n.node_key, n.node_type, n.display_name, n.asset_id, n.is_tier0, n.is_privileged, "
           "n.source, n.last_seen_at, m.tier0_reachable, m.min_hops_to_tier0, m.propagation_score "
           f"FROM graph.nodes n LEFT JOIN graph.node_metrics m ON m.node_id = n.node_id "
           f"AND m.analysis_id = {LATEST_ANALYSIS} "
           f"WHERE {' AND '.join(clauses)} ORDER BY n.node_key LIMIT :limit")
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]
    for r in rows:
        r["metrics"] = {"tier0_reachable": bool(r.pop("tier0_reachable")),
                        "min_hops_to_tier0": r.pop("min_hops_to_tier0"),
                        "propagation_score": float(r.pop("propagation_score") or 0)}
    return page(rows, limit, lambda r: {"node_key": r["node_key"]})


@router.get("/graph/nodes/{node_id}/neighborhood")
async def neighborhood(
    node_id: str,
    depth: int = Query(1, ge=1, le=3),
    relationship: list[RelationshipType] | None = Query(None),
    direction: Literal["in", "out", "both"] = "both",
    _: Principal = Depends(require_permission("graph:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    start = _uuid(node_id)
    cap = settings.graph_max_response_nodes
    seen, frontier, edge_ids, truncated = {start}, [start], set(), False
    match = {"in": "e.target_node_id = ANY(CAST(:ids AS uuid[]))",
             "out": "e.source_node_id = ANY(CAST(:ids AS uuid[]))",
             "both": "(e.source_node_id = ANY(CAST(:ids AS uuid[])) OR e.target_node_id = ANY(CAST(:ids AS uuid[])))"}
    rel_clause = " AND e.relationship = ANY(:rels)" if relationship else ""
    async with engine.connect() as conn:
        if not (await conn.execute(text("SELECT 1 FROM graph.nodes WHERE node_id = CAST(:id AS uuid)"),
                                   {"id": start})).first():
            raise HTTPException(status_code=404, detail="node not found")
        for _level in range(depth):
            if not frontier:
                break
            rows = (await conn.execute(text(
                "SELECT e.edge_id::text, e.source_node_id::text, e.target_node_id::text FROM graph.edges e "
                f"WHERE e.is_active AND {match[direction]}{rel_clause} LIMIT :cap"),
                {"ids": frontier, "rels": relationship or [], "cap": cap + 1})).all()
            if len(rows) > cap:
                truncated = True
            next_frontier = []
            for edge_id, source, target in rows[:cap]:
                new = [n for n in (source, target) if n not in seen]
                if len(seen) + len(new) > cap:
                    truncated = True
                    continue
                edge_ids.add(edge_id)
                seen.update(new)
                next_frontier.extend(new)
            frontier = next_frontier
        return {"nodes": await _nodes(conn, sorted(seen)), "edges": await _edges(conn, sorted(edge_ids)),
                "truncated": truncated}


@router.get("/graph/exposure-paths")
async def exposure_paths(
    from_node_id: str,
    max_depth: int = Query(4, ge=1, le=6),
    max_paths: int = Query(10, ge=1, le=50),
    _: Principal = Depends(require_permission("graph:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    """Shortest privilege chains to Tier 0, following the hop distances of the latest analysis."""
    start = _uuid(from_node_id)
    depth = min(max_depth, settings.graph_max_path_depth)
    sql = (
        "WITH RECURSIVE m AS ("
        "  SELECT node_id, min_hops_to_tier0 AS hops FROM graph.node_metrics "
        f"  WHERE analysis_id = {LATEST_ANALYSIS} AND tier0_reachable"
        "), walk(node_id, hops, nodes, edges) AS ("
        "  SELECT node_id, hops, ARRAY[node_id], ARRAY[]::uuid[] FROM m WHERE node_id = CAST(:start AS uuid) "
        "  UNION ALL "
        "  SELECT e.target_node_id, t.hops, w.nodes || e.target_node_id, w.edges || e.edge_id "
        "  FROM walk w JOIN graph.edges e ON e.source_node_id = w.node_id AND e.is_active "
        "  JOIN m t ON t.node_id = e.target_node_id AND t.hops = w.hops - 1 "
        "  WHERE w.hops > 0 AND cardinality(w.edges) < :depth"
        ") SELECT nodes::text[] AS nodes, edges::text[] AS edges FROM walk "
        "WHERE hops = 0 AND cardinality(edges) > 0 LIMIT :max_paths"
    )
    async with engine.connect() as conn:
        rows = (await conn.execute(text(sql), {"start": start, "depth": depth, "max_paths": max_paths})).all()
        node_ids = sorted({n for r in rows for n in r.nodes})
        edge_ids = sorted({e for r in rows for e in r.edges})
        nodes = {n["node_id"]: n for n in await _nodes(conn, node_ids)}
        edges = {e["edge_id"]: e for e in await _edges(conn, edge_ids)}
    paths = [{"nodes": [nodes[n] for n in r.nodes if n in nodes], "edges": [edges[e] for e in r.edges if e in edges],
              "truncated": False} for r in rows]
    return {"paths": paths}


@router.get("/graph/concentration-areas")
async def concentration_areas(
    area_type: AreaType | None = None,
    limit: int = Query(50, ge=1, le=200),
    _: Principal = Depends(require_permission("graph:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clause = "AND a.area_type = :area_type" if area_type else ""
    async with engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT a.area_id::text AS area_id, a.analysis_id::text AS analysis_id, a.area_type, a.score, "
            "a.member_count, a.summary, n.node_id::text AS anchor_node_id, n.node_key AS anchor_node_key, "
            "n.node_type AS anchor_node_type, n.display_name AS anchor_display_name "
            "FROM graph.concentration_areas a JOIN graph.nodes n ON n.node_id = a.anchor_node_id "
            f"WHERE a.analysis_id = {LATEST_ANALYSIS} {clause} "
            "ORDER BY a.score DESC, a.member_count DESC LIMIT :limit"),
            {"area_type": area_type, "limit": limit})).mappings()
        items = [{**r, "score": float(r["score"])} for r in rows]
    return {"items": items}


@router.get("/graph/analysis/latest")
async def latest_analysis(
    _: Principal = Depends(require_permission("graph:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    async with engine.connect() as conn:
        run = (await conn.execute(text(
            "SELECT analysis_id::text AS analysis_id, trigger, status, node_count, edge_count, parameters, "
            "started_at, completed_at FROM graph.analysis_runs WHERE status = 'completed' "
            "ORDER BY completed_at DESC LIMIT 1"))).mappings().first()
        if run is None:
            return {"analysis": None}
        stats = (await conn.execute(text(
            "SELECT count(*) FILTER (WHERE m.tier0_reachable AND NOT n.is_tier0) AS exposed_nodes, "
            "count(*) FILTER (WHERE n.is_tier0) AS tier0_nodes, "
            "count(*) FILTER (WHERE m.min_hops_to_tier0 = 1) AS one_hop_nodes "
            "FROM graph.node_metrics m JOIN graph.nodes n ON n.node_id = m.node_id "
            "WHERE m.analysis_id = CAST(:id AS uuid)"), {"id": run["analysis_id"]})).mappings().one()
        areas = (await conn.execute(text(
            "SELECT area_type, count(*) AS n FROM graph.concentration_areas WHERE analysis_id = CAST(:id AS uuid) "
            "GROUP BY area_type"), {"id": run["analysis_id"]})).all()
    return {"analysis": {**run, **stats, "areas": {a.area_type: a.n for a in areas}}}


@router.get("/graph/relationships")
async def list_relationships(
    limit: int = Query(100, ge=1, le=500),
    cursor: str | None = None,
    _: Principal = Depends(require_permission("graph:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clauses, params = ["e.is_active"], {"limit": limit + 1}
    after = decode_cursor(cursor)
    if after:
        clauses.append("e.edge_id > CAST(:after AS uuid)")
        params["after"] = after["edge_id"]
    sql = ("SELECT e.edge_id::text AS edge_id, s.node_key AS source, e.relationship, t.node_key AS target, "
           "e.properties, e.origin, e.observed_run_id::text AS observed_run_id, e.last_seen_at AS observed_at "
           "FROM graph.edges e JOIN graph.nodes s ON s.node_id = e.source_node_id "
           "JOIN graph.nodes t ON t.node_id = e.target_node_id "
           f"WHERE {' AND '.join(clauses)} ORDER BY e.edge_id LIMIT :limit")
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]
    result = page(rows, limit, lambda r: {"edge_id": r["edge_id"]})
    for item in result["items"]:
        item.pop("edge_id")
        if isinstance(item["properties"], str):
            item["properties"] = json.loads(item["properties"])
    return result
