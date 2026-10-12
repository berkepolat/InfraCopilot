from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from eeap_shared.models.domain import AssetCreate, Criticality, Environment, Tier
from eeap_shared.utils.events import enqueue_event, new_envelope
from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.pagination import decode_cursor, page
from eeap_shared.utils.service import get_engine

from .config import SCHEMA, settings

router = APIRouter(tags=["Assets"])

_SELECT = (
    "SELECT a.asset_id, a.hostname, a.fqdn::text AS fqdn, a.asset_type, a.criticality, a.criticality_locked, "
    "a.tier, o.name AS owner, a.owner_id, a.environment, a.os_family, a.os_version, a.domain::text AS domain, "
    "a.status, a.tags, a.attributes, a.first_seen_at, a.last_seen_at "
    "FROM asset.assets a LEFT JOIN asset.owners o ON o.owner_id = a.owner_id "
)


class AssetPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    criticality: Criticality | None = None
    criticality_locked: bool | None = None
    tier: Tier | None = None
    environment: Environment | None = None
    owner: str | None = None
    tags: list[str] | None = Field(default=None, max_length=50)
    status: Literal["active", "discovered", "retired"] | None = None


def _scope_filter(principal: Principal) -> tuple[str, dict]:
    owner_ids = principal.scope.get("owner_ids")
    if owner_ids is None:
        return "", {}
    return " AND a.owner_id = ANY(CAST(:scope_owner_ids AS uuid[]))", {"scope_owner_ids": owner_ids}


async def _resolve_owner(conn: AsyncConnection, name: str | None) -> str | None:
    if not name:
        return None
    return (await conn.execute(
        text("INSERT INTO asset.owners (name) VALUES (:n) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name "
             "RETURNING owner_id::text"),
        {"n": name},
    )).scalar()


async def _fetch(conn: AsyncConnection, asset_id: str, principal: Principal) -> dict | None:
    scope_sql, scope_params = _scope_filter(principal)
    row = (await conn.execute(text(_SELECT + "WHERE a.asset_id = :id" + scope_sql),
                              {"id": asset_id, **scope_params})).mappings().first()
    return dict(row) if row else None


@router.get("/assets")
async def list_assets(
    limit: int = Query(50, ge=1, le=500),
    cursor: str | None = None,
    q: str | None = Query(None, max_length=255),
    asset_type: str | None = None,
    criticality: Criticality | None = None,
    environment: Environment | None = None,
    tier: Tier | None = None,
    status: Literal["active", "discovered", "retired"] | None = None,
    principal: Principal = Depends(require_permission("assets:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clauses, params = ["TRUE"], {"limit": limit + 1}
    after = decode_cursor(cursor)
    if after:
        clauses.append("a.asset_id > :after")
        params["after"] = after["asset_id"]
    for column, value in (("asset_type", asset_type), ("criticality", criticality),
                          ("environment", environment), ("tier", tier), ("status", status)):
        if value:
            clauses.append(f"a.{column} = :{column}")
            params[column] = value
    if q:
        clauses.append("(a.hostname ILIKE :q OR a.fqdn::text ILIKE :q)")
        params["q"] = f"%{q}%"
    scope_sql, scope_params = _scope_filter(principal)
    sql = _SELECT + "WHERE " + " AND ".join(clauses) + scope_sql + " ORDER BY a.asset_id LIMIT :limit"
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(text(sql), {**params, **scope_params})).mappings()]
    return page(rows, limit, lambda r: {"asset_id": r["asset_id"]})


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: str, principal: Principal = Depends(require_permission("assets:read")),
                    engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        asset = await _fetch(conn, asset_id, principal)
    if asset is None:
        raise HTTPException(404, detail="asset not found")
    return asset


@router.post("/assets", status_code=201)
async def create_asset(payload: AssetCreate, principal: Principal = Depends(require_permission("assets:write")),
                       engine: AsyncEngine = Depends(get_engine)):
    try:
        async with engine.begin() as conn:
            owner_id = await _resolve_owner(conn, payload.owner)
            await conn.execute(
                text("INSERT INTO asset.assets (asset_id, hostname, fqdn, asset_type, criticality, "
                     "criticality_locked, tier, environment, owner_id, os_family, os_version, domain, tags, "
                     "attributes, classification_source) VALUES (:asset_id, :hostname, :fqdn, :asset_type, "
                     ":criticality, :criticality_locked, :tier, :environment, CAST(:owner_id AS uuid), :os_family, "
                     ":os_version, :domain, :tags, CAST(:attributes AS jsonb), 'manual')"),
                {**payload.model_dump(exclude={"owner", "attributes"}), "owner_id": owner_id,
                 "attributes": json.dumps(payload.attributes)},
            )
            asset = await _fetch(conn, payload.asset_id, Principal(principal.subject, principal.permissions))
            await enqueue_event(conn, SCHEMA, "eeap.asset", new_envelope(
                event_type="asset.created", source=settings.service_name, subject=payload.asset_id,
                actor={"type": "user", "id": principal.subject},
                data={k: asset[k] for k in ("asset_id", "hostname", "asset_type", "criticality", "tier",
                                            "environment", "owner")},
            ))
    except IntegrityError as exc:
        raise HTTPException(409, detail=f"asset {payload.asset_id} already exists") from exc
    return asset


@router.patch("/assets/{asset_id}")
async def update_asset(asset_id: str, payload: AssetPatch,
                       principal: Principal = Depends(require_permission("assets:write")),
                       engine: AsyncEngine = Depends(get_engine)):
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, detail="no fields to update")
    async with engine.begin() as conn:
        before = await _fetch(conn, asset_id, principal)
        if before is None:
            raise HTTPException(404, detail="asset not found")
        if "owner" in changes:
            changes["owner_id"] = await _resolve_owner(conn, changes.pop("owner"))
        if "criticality" in changes and "criticality_locked" not in changes:
            changes["criticality_locked"] = True
        assignments = ", ".join(
            f"{k} = CAST(:{k} AS uuid)" if k == "owner_id" else f"{k} = :{k}" for k in changes
        )
        await conn.execute(text(f"UPDATE asset.assets SET {assignments} WHERE asset_id = :asset_id"),
                           {**changes, "asset_id": asset_id})
        after = await _fetch(conn, asset_id, principal)
        changed = {k: after[k] for k in after if after[k] != before[k] and k != "last_seen_at"}
        actor = {"type": "user", "id": principal.subject}
        if changed:
            await enqueue_event(conn, SCHEMA, "eeap.asset", new_envelope(
                event_type="asset.updated", source=settings.service_name, subject=asset_id, actor=actor,
                data={"asset_id": asset_id, "changes": changed, "tier": after["tier"],
                      "hostname": after["hostname"], "criticality": after["criticality"],
                      "environment": after["environment"], "owner": after["owner"]}))
        if before["criticality"] != after["criticality"]:
            await enqueue_event(conn, SCHEMA, "eeap.asset", new_envelope(
                event_type="asset.criticality_changed", source=settings.service_name, subject=asset_id,
                actor=actor, data={"asset_id": asset_id, "old": before["criticality"], "new": after["criticality"]}))
    return after


@router.get("/owners")
async def list_owners(_: Principal = Depends(require_permission("assets:read")),
                      engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT owner_id, name, email::text AS email, escalation_contact "
                                       "FROM asset.owners ORDER BY name"))
        return [dict(r) for r in rows.mappings()]
