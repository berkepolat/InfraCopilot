from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.pagination import decode_cursor, page
from eeap_shared.utils.service import get_engine

router = APIRouter(tags=["Graph"])


@router.get("/graph/nodes")
async def list_nodes(
    limit: int = Query(50, ge=1, le=500),
    cursor: str | None = None,
    node_type: Literal["User", "Computer", "Group", "ServiceAccount", "Tier0Asset"] | None = None,
    is_tier0: bool | None = None,
    _: Principal = Depends(require_permission("graph:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clauses, params = ["deleted_at IS NULL"], {"limit": limit + 1}
    after = decode_cursor(cursor)
    if after:
        clauses.append("node_key > :after")
        params["after"] = after["node_key"]
    if node_type:
        clauses.append("node_type = :node_type")
        params["node_type"] = node_type
    if is_tier0 is not None:
        clauses.append("is_tier0 = :is_tier0")
        params["is_tier0"] = is_tier0
    sql = ("SELECT node_id, node_key, node_type, display_name, asset_id, is_tier0, is_privileged, source, "
           f"last_seen_at FROM graph.nodes WHERE {' AND '.join(clauses)} ORDER BY node_key LIMIT :limit")
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]
    return page(rows, limit, lambda r: {"node_key": r["node_key"]})
