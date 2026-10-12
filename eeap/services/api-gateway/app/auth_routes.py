from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import text

from . import users
from .audit import AuditEntry, write_audit
from .context import GatewayState, client_ip, gateway_state, user_claims
from .security import new_opaque_token, sha256, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=1024)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=512)


class LogoutRequest(BaseModel):
    refresh_token: str | None = Field(default=None, max_length=512)


def _too_many(retry_after: int) -> HTTPException:
    return HTTPException(429, detail="rate limit exceeded", headers={"Retry-After": str(retry_after)})


async def _issue_token_pair(state: GatewayState, conn, user: users.UserRecord, family_id: uuid.UUID,
                            ip: str | None, user_agent: str | None) -> tuple[dict, uuid.UUID]:
    roles, permissions, scope = await users.roles_permissions_scope(conn, user.user_id)
    access = state.issuer.issue(user_id=user.user_id, username=user.username, roles=roles,
                                permissions=permissions, scope=scope)
    refresh, refresh_hash = new_opaque_token()
    token_id = uuid.uuid4()
    await conn.execute(
        text("INSERT INTO iam.refresh_tokens (token_id, user_id, family_id, token_hash, expires_at, client_ip, "
             "user_agent) VALUES (:tid, CAST(:uid AS uuid), :fid, :hash, :exp, CAST(:ip AS inet), :ua)"),
        {"tid": token_id, "uid": user.user_id, "fid": family_id, "hash": refresh_hash,
         "exp": datetime.now(UTC) + timedelta(seconds=state.settings.refresh_token_ttl_seconds),
         "ip": ip, "ua": (user_agent or "")[:500]},
    )
    body = {
        "access_token": access, "token_type": "Bearer", "expires_in": state.settings.access_token_ttl_seconds,
        "refresh_token": refresh, "refresh_expires_in": state.settings.refresh_token_ttl_seconds,
    }
    return body, token_id


@router.post("/login")
async def login(payload: LoginRequest, request: Request, state: GatewayState = Depends(gateway_state)):
    ip = client_ip(request, state.settings)
    ua = request.headers.get("user-agent")
    username = payload.username.strip().lower()

    for bucket, key, rate in (("login_ip", ip or "unknown", state.settings.rate_limit_login_per_ip),
                              ("login_user", username, state.settings.rate_limit_login_per_user)):
        allowed, retry_after = await state.limiter.hit(bucket, key, rate)
        if not allowed:
            await write_audit(state.engine, AuditEntry("anonymous", "auth.login", "denied", actor_name=username,
                                                       source_ip=ip, user_agent=ua,
                                                       details={"reason": f"rate_limited:{bucket}"}))
            raise _too_many(retry_after)

    async with state.engine.begin() as conn:
        user = await users.get_by_username(conn, username)
        if user and user.locked_until and user.locked_until > datetime.now(UTC):
            verify_password(None, payload.password)
            outcome = ("denied", "account_locked")
        elif user and user.is_active and user.auth_source == "local" \
                and verify_password(user.password_hash, payload.password):
            await users.record_successful_login(conn, user.user_id)
            body, _ = await _issue_token_pair(state, conn, user, uuid.uuid4(), ip, ua)
            outcome = ("success", None)
        else:
            if user is None:
                verify_password(None, payload.password)
            locked = bool(user) and await users.record_failed_login(
                conn, user.user_id, state.settings.lockout_threshold, state.settings.lockout_minutes)
            outcome = ("failure", "account_locked_now" if locked else "invalid_credentials")

    await write_audit(state.engine, AuditEntry(
        "user" if user else "anonymous", "auth.login", outcome[0], actor_id=user.user_id if user else None,
        actor_name=username, source_ip=ip, user_agent=ua, details={"reason": outcome[1]} if outcome[1] else {}))

    if outcome[0] == "success":
        return body
    if outcome[1] == "account_locked":
        raise HTTPException(423, detail="account temporarily locked")
    raise HTTPException(401, detail="invalid username or password")


@router.post("/refresh")
async def refresh(payload: RefreshRequest, request: Request, state: GatewayState = Depends(gateway_state)):
    ip = client_ip(request, state.settings)
    ua = request.headers.get("user-agent")
    reuse_detected = False
    async with state.engine.begin() as conn:
        row = (await conn.execute(
            text("SELECT token_id, user_id::text AS user_id, family_id, expires_at, revoked_at "
                 "FROM iam.refresh_tokens WHERE token_hash = :h FOR UPDATE"),
            {"h": sha256(payload.refresh_token)},
        )).mappings().first()
        if row is None or row["expires_at"] <= datetime.now(UTC):
            raise HTTPException(401, detail="invalid refresh token")
        if row["revoked_at"] is not None:
            await conn.execute(
                text("UPDATE iam.refresh_tokens SET revoked_at = now() WHERE family_id = :f AND revoked_at IS NULL"),
                {"f": row["family_id"]},
            )
            reuse_detected = True
        else:
            user = await users.get_by_id(conn, row["user_id"])
            if user is None or not user.is_active:
                raise HTTPException(401, detail="invalid refresh token")
            body, new_id = await _issue_token_pair(state, conn, user, row["family_id"], ip, ua)
            await conn.execute(
                text("UPDATE iam.refresh_tokens SET revoked_at = now(), replaced_by = :n WHERE token_id = :t"),
                {"n": new_id, "t": row["token_id"]},
            )
    if reuse_detected:
        await write_audit(state.engine, AuditEntry("user", "auth.refresh", "denied", actor_id=row["user_id"],
                                                   source_ip=ip, user_agent=ua,
                                                   details={"reason": "refresh_token_reuse_family_revoked"}))
        raise HTTPException(401, detail="invalid refresh token")
    return body


@router.post("/logout", status_code=204)
async def logout(request: Request, payload: LogoutRequest | None = None,
                 state: GatewayState = Depends(gateway_state)):
    claims = user_claims(request)
    async with state.engine.begin() as conn:
        if payload and payload.refresh_token:
            await conn.execute(
                text("UPDATE iam.refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL AND family_id = "
                     "(SELECT family_id FROM iam.refresh_tokens WHERE token_hash = :h AND user_id = CAST(:u AS uuid))"),
                {"h": sha256(payload.refresh_token), "u": claims["sub"]},
            )
        else:
            await conn.execute(
                text("UPDATE iam.refresh_tokens SET revoked_at = now() "
                     "WHERE user_id = CAST(:u AS uuid) AND revoked_at IS NULL"),
                {"u": claims["sub"]},
            )
    await write_audit(state.engine, AuditEntry("user", "auth.logout", "success", actor_id=claims["sub"],
                                               actor_name=claims.get("name"),
                                               source_ip=client_ip(request, state.settings)))
    return Response(status_code=204)


@router.get("/me")
async def me(request: Request):
    claims = user_claims(request)
    return {"user_id": claims["sub"], "username": claims.get("name"), "roles": claims.get("roles", []),
            "permissions": claims.get("perms", []), "scope": claims.get("scope", {})}


@router.get("/.well-known/jwks.json")
async def jwks(state: GatewayState = Depends(gateway_state)):
    return state.issuer.jwks()
