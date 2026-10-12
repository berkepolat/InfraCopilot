"""Graph analysis job: load the active graph, analyse it, persist results and publish them."""
from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.events import enqueue_event, new_envelope

from .analysis import AnalysisResult, analyze
from .config import SCHEMA

logger = logging.getLogger("eeap.relationship.analysis")

GRAPH_STREAM = "eeap.graph"
KEEP_ANALYSIS_RUNS = 5
MAX_PUBLISHED_FACTS = 50_000


async def _load(engine: AsyncEngine) -> tuple[list[dict], list[dict]]:
    async with engine.connect() as conn:
        nodes = [dict(r) for r in (await conn.execute(text(
            "SELECT node_id::text AS node_id, node_key, node_type, display_name, asset_id, is_tier0, is_privileged, "
            "enabled, properties->>'dn' AS dn FROM graph.nodes WHERE deleted_at IS NULL"))).mappings()]
        edges = [dict(r) for r in (await conn.execute(text(
            "SELECT source_node_id::text AS source_id, target_node_id::text AS target_id, relationship "
            "FROM graph.edges WHERE is_active"))).mappings()]
    return nodes, edges


def _facts(nodes: list[dict], result: AnalysisResult) -> list[dict]:
    """Per-subject graph context for scoring, keyed the way findings reference subjects (asset id or DN)."""
    metrics = {m.node_id: m for m in result.metrics}
    facts = []
    for node in nodes:
        m = metrics.get(node["node_id"])
        if not (node["is_tier0"] or node["is_privileged"] or (m and m.tier0_reachable)):
            continue
        fact = {"propagation_score": m.propagation_score if m else 0.0,
                "tier0_reachable": bool(m and m.tier0_reachable),
                "min_hops": m.min_hops_to_tier0 if m else None,
                "is_tier0": node["is_tier0"], "is_privileged": node["is_privileged"]}
        if node["asset_id"]:
            facts.append({"kind": "asset", "key": node["asset_id"], **fact})
        if node["dn"]:
            facts.append({"kind": "dn", "key": node["dn"].lower(), **fact})
    return facts[:MAX_PUBLISHED_FACTS]


async def run_analysis(engine: AsyncEngine, service: str, max_depth: int, trigger: str) -> dict:
    async with engine.begin() as conn:
        analysis_id = (await conn.execute(text(
            "INSERT INTO graph.analysis_runs (trigger, parameters) VALUES (:trigger, CAST(:params AS jsonb)) "
            "RETURNING analysis_id::text"),
            {"trigger": trigger, "params": json.dumps({"max_depth": max_depth})})).scalar_one()
    try:
        nodes, edges = await _load(engine)
        result = await asyncio.to_thread(analyze, nodes, edges, max_depth)
        facts = _facts(nodes, result)
        async with engine.begin() as conn:
            if result.metrics:
                await conn.execute(text(
                    "INSERT INTO graph.node_metrics (analysis_id, node_id, tier0_reachable, min_hops_to_tier0, "
                    "paths_to_tier0, inbound_privileged_degree, concentration_score, propagation_score) "
                    "VALUES (CAST(:analysis_id AS uuid), CAST(:node_id AS uuid), :reachable, :hops, :paths, "
                    ":inbound, :concentration, :propagation)"),
                    [{"analysis_id": analysis_id, "node_id": m.node_id, "reachable": m.tier0_reachable,
                      "hops": m.min_hops_to_tier0, "paths": m.paths_to_tier0, "inbound": m.inbound_privileged_degree,
                      "concentration": m.concentration_score, "propagation": m.propagation_score}
                     for m in result.metrics])
            if result.areas:
                await conn.execute(text(
                    "INSERT INTO graph.concentration_areas (analysis_id, anchor_node_id, area_type, score, "
                    "member_count, summary) VALUES (CAST(:analysis_id AS uuid), CAST(:anchor AS uuid), :type, "
                    ":score, :count, :summary)"),
                    [{"analysis_id": analysis_id, "anchor": a.anchor_node_id, "type": a.area_type, "score": a.score,
                      "count": a.member_count, "summary": a.summary} for a in result.areas])
            await conn.execute(text(
                "UPDATE graph.analysis_runs SET status = 'completed', completed_at = now(), node_count = :n, "
                "edge_count = :e WHERE analysis_id = CAST(:id AS uuid)"),
                {"n": result.node_count, "e": result.edge_count, "id": analysis_id})
            await conn.execute(text(
                "DELETE FROM graph.analysis_runs WHERE analysis_id NOT IN (SELECT analysis_id FROM graph.analysis_runs "
                "ORDER BY started_at DESC LIMIT :keep)"), {"keep": KEEP_ANALYSIS_RUNS})
            counts = {"nodes": result.node_count, "edges": result.edge_count,
                      "tier0_reachable": sum(1 for m in result.metrics if m.tier0_reachable),
                      "areas": len(result.areas)}
            await enqueue_event(conn, SCHEMA, GRAPH_STREAM, new_envelope(
                event_type="graph.analysis_completed", source=service, subject=f"analysis:{analysis_id}",
                data={"analysis_id": analysis_id, "trigger": trigger, "counts": counts, "facts": facts}))
    except Exception as exc:
        async with engine.begin() as conn:
            await conn.execute(text(
                "UPDATE graph.analysis_runs SET status = 'failed', completed_at = now(), error = :error "
                "WHERE analysis_id = CAST(:id AS uuid)"), {"error": str(exc)[:2000], "id": analysis_id})
        raise
    logger.info("graph analysis completed", extra={"analysis_id": analysis_id, **counts})
    return {"analysis_id": analysis_id, **counts}
