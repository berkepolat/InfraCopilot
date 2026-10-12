from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from eeap_shared.models.domain import FindingStatus, Severity
from eeap_shared.utils.events import enqueue_event, new_envelope
from eeap_shared.utils.internal_auth import Principal, require_permission
from eeap_shared.utils.pagination import decode_cursor, page
from eeap_shared.utils.service import get_engine

from .config import SCHEMA, settings
from .domain import CONTENT_TYPES, RISK_ACCEPTABLE_FROM, LifecycleState, SourceType, check_triage_transition
from .findings_repo import FINDING_COLUMNS, get_finding, load_controls, set_lifecycle
from .storage import ObjectStore

router = APIRouter(tags=["Assessments"])

IMPORT_STREAM = "eeap.imports"


def get_store(request: Request) -> ObjectStore:
    return request.app.state.object_store


# ------------------------------------------------------------------------------------------- controls

@router.get("/controls")
async def list_controls(
    module: Literal["AD", "WIN", "NET", "LINUX", "CLOUD", "IMPORT"] | None = None,
    enabled: bool | None = None,
    _: Principal = Depends(require_permission("controls:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clauses, params = ["TRUE"], {}
    if module:
        clauses.append("module = :module")
        params["module"] = module
    if enabled is not None:
        clauses.append("enabled = :enabled")
        params["enabled"] = enabled
    sql = ("SELECT control_id, name, module, category, default_severity, exploitability::float, "
           "privilege_impact::float, execution_site, mitre_techniques, version, enabled "
           f"FROM assessment.controls WHERE {' AND '.join(clauses)} ORDER BY control_id")
    async with engine.connect() as conn:
        return [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]


# ------------------------------------------------------------------------------------------- runs

@router.get("/assessments/runs")
async def list_runs(
    limit: int = Query(50, ge=1, le=500),
    cursor: str | None = None,
    _: Principal = Depends(require_permission("assessments:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    params: dict = {"limit": limit + 1}
    where = ""
    after = decode_cursor(cursor)
    if after:
        where = "WHERE (created_at, run_id) < (:ts, CAST(:id AS uuid))"
        params.update(ts=datetime.fromisoformat(after["created_at"]), id=after["run_id"])
    sql = ("SELECT run_id, profile_id, trigger, status, scope, control_ids, full_scope, stats, requested_by, "
           f"created_at, started_at, completed_at FROM assessment.assessment_runs {where} "
           "ORDER BY created_at DESC, run_id DESC LIMIT :limit")
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]
    return page(rows, limit, lambda r: {"created_at": r["created_at"].isoformat(), "run_id": str(r["run_id"])})


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_ids: list[str] | None = Field(default=None, max_length=50)
    # When set, runs the NET controls against these IP addresses (see SCAN_ALLOWED_CIDRS).
    targets: list[str] | None = Field(default=None, max_length=256)
    # Extra TCP ports or ranges ("8081", "9000-9010") scanned on top of the common port profile.
    ports: list[str] | None = Field(default=None, max_length=64)


@router.post("/assessments/runs", status_code=202)
async def start_run(payload: RunRequest, principal: Principal = Depends(require_permission("assessments:run")),
                    engine: AsyncEngine = Depends(get_engine)):
    from .collectors.port_scan import MAX_CONNECTIONS_PER_RUN, PortSpecError, parse_ports, scan_ports
    from .targets import TargetError, authorize_targets, parse_targets

    module = "NET" if payload.targets else "AD"
    if payload.ports and module != "NET":
        raise HTTPException(422, detail="ports require targets (network assessment)")
    try:
        ips = authorize_targets(parse_targets(payload.targets), settings.scan_allowed_cidrs) if module == "NET" else []
        extra_ports = parse_ports(payload.ports)
    except (TargetError, PortSpecError) as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    if len(ips) * len(scan_ports(extra_ports)) > MAX_CONNECTIONS_PER_RUN:
        raise HTTPException(422, detail=f"targets x ports exceeds {MAX_CONNECTIONS_PER_RUN} connections per run")

    async with engine.begin() as conn:
        enabled = set((await conn.execute(text(
            "SELECT control_id FROM assessment.controls WHERE enabled AND module = :module"),
            {"module": module})).scalars())
        requested = payload.control_ids or sorted(enabled)
        unknown = sorted(set(requested) - enabled)
        if unknown:
            raise HTTPException(422, detail=f"not an enabled {module} control: {', '.join(unknown)}")
        if not requested:
            raise HTTPException(422, detail=f"no {module} controls are enabled")
        # Reject mixing modules in one run.
        prefixes = {c.split("-", 1)[0] for c in requested}
        if prefixes != {module}:
            raise HTTPException(422, detail=f"control_ids must all belong to module {module} for this request")
        busy = (await conn.execute(text(
            "SELECT run_id::text FROM assessment.assessment_runs WHERE trigger IN ('manual', 'api', 'schedule') "
            "AND status IN ('queued', 'running') AND created_at > now() - interval '1 hour' LIMIT 1"))).scalar()
        if busy:
            raise HTTPException(409, detail=f"assessment run {busy} is still in progress")
        scope = {"ips": ips} if ips else {}
        if extra_ports:
            scope["ports"] = extra_ports
        full_scope = module == "AD"
        run_id = (await conn.execute(
            text("INSERT INTO assessment.assessment_runs "
                 "(trigger, control_ids, scope, full_scope, requested_by) "
                 "VALUES ('manual', :controls, CAST(:scope AS jsonb), :full, :by) RETURNING run_id::text"),
            {"controls": requested, "scope": json.dumps(scope), "full": full_scope,
             "by": principal.subject})).scalar_one()
        await enqueue_event(conn, SCHEMA, "eeap.assessment", new_envelope(
            event_type="assessment.run_requested", source=settings.service_name, subject=run_id,
            actor={"type": "user", "id": principal.subject},
            data={"run_id": run_id, "trigger": "manual", "control_ids": requested, "scope": scope}))
    return {"run_id": run_id, "status": "queued", "control_ids": requested, "scope": scope,
            "module": module}


@router.get("/assessments/runs/{run_id}")
async def get_run(run_id: uuid.UUID, _: Principal = Depends(require_permission("assessments:read")),
                  engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        row = (await conn.execute(text(
            "SELECT run_id, profile_id, trigger, status, scope, control_ids, full_scope, stats, requested_by, "
            "created_at, started_at, completed_at FROM assessment.assessment_runs WHERE run_id = :id"),
            {"id": run_id})).mappings().first()
    if row is None:
        raise HTTPException(404, detail="run not found")
    return dict(row)


# ------------------------------------------------------------------------------------------- imports

@router.post("/imports", status_code=202)
async def create_import(
    request: Request,
    source_type: SourceType = Query(..., description="eeap_json (Standard Finding Format) or eeap_csv"),
    principal: Principal = Depends(require_permission("imports:create")),
    engine: AsyncEngine = Depends(get_engine),
    store: ObjectStore = Depends(get_store),
):
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type not in CONTENT_TYPES[source_type]:
        raise HTTPException(415, detail=f"{source_type} expects Content-Type {CONTENT_TYPES[source_type][0]}")
    declared = int(request.headers.get("content-length") or 0)
    if declared > settings.import_max_bytes:
        raise HTTPException(413, detail="import file too large")
    body = await request.body()
    if not body:
        raise HTTPException(422, detail="import file is empty")
    if len(body) > settings.import_max_bytes:
        raise HTTPException(413, detail="import file too large")

    import_id = str(uuid.uuid4())
    sha256 = hashlib.sha256(body).hexdigest()
    now = datetime.now(UTC)
    extension = "json" if source_type == "eeap_json" else "csv"
    object_key = f"imports/{now:%Y/%m}/{import_id}.{extension}"
    await store.put(settings.imports_bucket, object_key, body, content_type,
                    {"import-id": import_id, "sha256": sha256, "uploaded-by": principal.subject})

    async with engine.begin() as conn:
        run_id = (await conn.execute(
            text("INSERT INTO assessment.assessment_runs (trigger, full_scope, status, requested_by, scope) "
                 "VALUES ('import', false, 'queued', :by, CAST(:scope AS jsonb)) RETURNING run_id::text"),
            {"by": principal.subject, "scope": f'{{"import_id": "{import_id}"}}'})).scalar_one()
        await conn.execute(
            text("INSERT INTO assessment.imports (import_id, source_type, bucket, object_key, sha256, run_id, "
                 "created_by) VALUES (CAST(:id AS uuid), :type, :bucket, :key, :sha, CAST(:run AS uuid), :by)"),
            {"id": import_id, "type": source_type, "bucket": settings.imports_bucket, "key": object_key,
             "sha": sha256, "run": run_id, "by": principal.subject})
        await enqueue_event(conn, SCHEMA, IMPORT_STREAM, new_envelope(
            event_type="import.uploaded", source=settings.service_name, subject=import_id,
            actor={"type": "user", "id": principal.subject},
            data={"import_id": import_id, "run_id": run_id, "source_type": source_type, "size_bytes": len(body)}))
    return {"import_id": import_id, "run_id": run_id, "status": "uploaded", "sha256": sha256}


_IMPORT_COLUMNS = ("import_id, source_type, object_key, sha256, status, run_id, stats, error, created_by, "
                   "created_at, completed_at")


@router.get("/imports")
async def list_imports(limit: int = Query(50, ge=1, le=200),
                       _: Principal = Depends(require_permission("imports:create")),
                       engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        rows = await conn.execute(text(f"SELECT {_IMPORT_COLUMNS} FROM assessment.imports "
                                       "ORDER BY created_at DESC LIMIT :limit"), {"limit": limit})
        return {"items": [dict(r) for r in rows.mappings()], "next_cursor": None}


@router.get("/imports/{import_id}")
async def get_import(import_id: uuid.UUID, _: Principal = Depends(require_permission("imports:create")),
                     engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        row = (await conn.execute(text(f"SELECT {_IMPORT_COLUMNS} FROM assessment.imports "
                                       "WHERE import_id = :id"), {"id": import_id})).mappings().first()
    if row is None:
        raise HTTPException(404, detail="import not found")
    return dict(row)


# ------------------------------------------------------------------------------------ network services

@router.get("/network-services")
async def list_network_services(
    limit: int = Query(200, ge=1, le=1000),
    ip: str | None = Query(None, max_length=45),
    asset_id: str | None = Query(None, max_length=128),
    port: int | None = Query(None, ge=1, le=65535),
    state: Literal["open", "closed"] | None = "open",
    _: Principal = Depends(require_permission("assets:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clauses, params = ["TRUE"], {"limit": limit}
    if ip is not None:
        clauses.append("host(ip) = :ip")
        params["ip"] = ip
    for name, value in (("asset_id", asset_id), ("port", port), ("state", state)):
        if value is not None:
            clauses.append(f"{name} = :{name}")
            params[name] = value
    sql = ("SELECT service_id, asset_id, host(ip) AS ip, transport, port, state, service, product, version, "
           "tls_version, details, first_seen_at, last_seen_at, last_seen_run_id, closed_at "
           f"FROM assessment.network_services WHERE {' AND '.join(clauses)} ORDER BY network_services.ip, port LIMIT :limit")
    async with engine.connect() as conn:
        items = [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]
    return {"items": items, "count": len(items)}


# ------------------------------------------------------------------------------------------- findings

@router.get("/findings")
async def list_findings(
    limit: int = Query(50, ge=1, le=500),
    cursor: str | None = None,
    asset_id: str | None = None,
    control_id: str | None = None,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    lifecycle_state: LifecycleState | None = None,
    _: Principal = Depends(require_permission("findings:read")),
    engine: AsyncEngine = Depends(get_engine),
):
    clauses, params = ["TRUE"], {"limit": limit + 1}
    for name, value in (("asset_id", asset_id), ("control_id", control_id), ("severity", severity),
                        ("status", status), ("lifecycle_state", lifecycle_state)):
        if value is not None:
            clauses.append(f"f.{name} = :{name}")
            params[name] = value
    after = decode_cursor(cursor)
    if after:
        clauses.append("(f.last_seen_at, f.finding_id) < (:ts, CAST(:id AS uuid))")
        params.update(ts=datetime.fromisoformat(after["last_seen_at"]), id=after["finding_id"])
    sql = (f"SELECT {FINDING_COLUMNS} FROM assessment.findings f WHERE {' AND '.join(clauses)} "
           "ORDER BY f.last_seen_at DESC, f.finding_id DESC LIMIT :limit")
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(text(sql), params)).mappings()]
    return page(rows, limit, lambda r: {"last_seen_at": r["last_seen_at"].isoformat(),
                                        "finding_id": str(r["finding_id"])})


@router.get("/findings/{finding_id}")
async def finding_detail(finding_id: uuid.UUID, _: Principal = Depends(require_permission("findings:read")),
                         engine: AsyncEngine = Depends(get_engine)):
    async with engine.connect() as conn:
        finding = await get_finding(conn, str(finding_id))
        if finding is None:
            raise HTTPException(404, detail="finding not found")
        history = await conn.execute(
            text("SELECT run_id, status, severity, lifecycle_state, changed_by, note, changed_at "
                 "FROM assessment.finding_history WHERE finding_id = :id ORDER BY changed_at DESC LIMIT 100"),
            {"id": finding_id})
        acceptances = await conn.execute(
            text("SELECT acceptance_id, justification, approved_by, expires_at, revoked_at, created_at "
                 "FROM assessment.risk_acceptances WHERE finding_id = :id ORDER BY created_at DESC"),
            {"id": finding_id})
        return {**finding, "history": [dict(r) for r in history.mappings()],
                "risk_acceptances": [dict(r) for r in acceptances.mappings()]}


class TriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifecycle_state: LifecycleState
    note: str | None = Field(default=None, max_length=2000)


@router.post("/findings/{finding_id}/lifecycle")
async def triage_finding(finding_id: uuid.UUID, payload: TriageRequest,
                         principal: Principal = Depends(require_permission("findings:triage")),
                         engine: AsyncEngine = Depends(get_engine)):
    async with engine.begin() as conn:
        finding = await get_finding(conn, str(finding_id), lock=True)
        if finding is None:
            raise HTTPException(404, detail="finding not found")
        try:
            check_triage_transition(finding["lifecycle_state"], payload.lifecycle_state)
        except ValueError as exc:
            raise HTTPException(409, detail=str(exc)) from exc
        if finding["lifecycle_state"] == "risk_accepted":
            await conn.execute(
                text("UPDATE assessment.risk_acceptances SET revoked_at = now() "
                     "WHERE finding_id = :id AND revoked_at IS NULL"), {"id": finding_id})
        controls = await load_controls(conn)
        return await set_lifecycle(conn, finding, payload.lifecycle_state, actor=principal.subject,
                                   note=payload.note, trigger="triage", controls=controls)


class RiskAcceptanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    justification: str = Field(min_length=20, max_length=4000)
    expires_at: datetime


@router.post("/findings/{finding_id}/risk-acceptance", status_code=201)
async def accept_risk(finding_id: uuid.UUID, payload: RiskAcceptanceRequest,
                      principal: Principal = Depends(require_permission("findings:accept_risk")),
                      engine: AsyncEngine = Depends(get_engine)):
    now = datetime.now(UTC)
    expires_at = payload.expires_at if payload.expires_at.tzinfo else payload.expires_at.replace(tzinfo=UTC)
    if not now < expires_at <= now + timedelta(days=settings.risk_acceptance_max_days):
        raise HTTPException(422, detail=f"expires_at must be in the future and within "
                                        f"{settings.risk_acceptance_max_days} days")
    async with engine.begin() as conn:
        finding = await get_finding(conn, str(finding_id), lock=True)
        if finding is None:
            raise HTTPException(404, detail="finding not found")
        if finding["lifecycle_state"] not in RISK_ACCEPTABLE_FROM:
            raise HTTPException(409, detail=f"cannot accept risk for a finding in {finding['lifecycle_state']}")
        acceptance_id = (await conn.execute(
            text("INSERT INTO assessment.risk_acceptances (finding_id, justification, approved_by, expires_at) "
                 "VALUES (:id, :why, :by, :exp) RETURNING acceptance_id"),
            {"id": finding_id, "why": payload.justification, "by": principal.subject, "exp": expires_at})
        ).scalar_one()
        controls = await load_controls(conn)
        row = await set_lifecycle(conn, finding, "risk_accepted", actor=principal.subject,
                                  note=f"risk accepted until {expires_at.isoformat()}", trigger="triage",
                                  controls=controls)
    return {**row, "acceptance_id": acceptance_id, "expires_at": expires_at}
