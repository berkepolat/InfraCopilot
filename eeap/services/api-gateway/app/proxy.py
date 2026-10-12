from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from eeap_shared.logging import request_id_var
from eeap_shared.utils.internal_auth import mint_internal_token

from .audit import AuditEntry, write_audit
from .context import GatewayState, client_ip, gateway_state, user_claims
from .routes_table import resolve

router = APIRouter(prefix="/api/v1", tags=["Proxy"])

_FORWARD_REQUEST_HEADERS = ("content-type", "accept", "if-match", "if-none-match", "idempotency-key")
_FORWARD_RESPONSE_HEADERS = ("content-type", "etag", "location", "retry-after", "cache-control")
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
async def proxy(path: str, request: Request, state: GatewayState = Depends(gateway_state)):
    upstream_path = "/" + path
    route = resolve(upstream_path)
    if route is None:
        raise HTTPException(404, detail="no such endpoint")

    claims = user_claims(request)
    ip = client_ip(request, state.settings)
    allowed, retry_after = await state.limiter.hit("user", claims["sub"], state.settings.rate_limit_user)
    if not allowed:
        raise HTTPException(429, detail="rate limit exceeded", headers={"Retry-After": str(retry_after)})

    method = request.method
    permission = route.permission_for(method, upstream_path)
    resource_type = route.prefix.strip("/")
    resource_id = upstream_path[len(route.prefix) + 1:].split("/", 1)[0] or None
    audit_base = dict(actor_type="user", actor_id=claims["sub"], actor_name=claims.get("name"),
                      resource_type=resource_type, resource_id=resource_id, source_ip=ip,
                      user_agent=request.headers.get("user-agent"))

    if permission is None or permission not in claims.get("perms", []):
        await write_audit(state.engine, AuditEntry(action=f"{resource_type}.{method.lower()}", outcome="denied",
                                                   details={"required_permission": permission}, **audit_base))
        raise HTTPException(403, detail="insufficient permission")

    max_body = route.max_body_bytes or state.settings.max_body_bytes
    content_length = int(request.headers.get("content-length") or 0)
    if content_length > max_body:
        raise HTTPException(413, detail="request body too large")
    body = await request.body()
    if len(body) > max_body:
        raise HTTPException(413, detail="request body too large")

    audience, base_url = state.settings.upstreams()[route.upstream]
    token = mint_internal_token(
        state.internal_private_key, audience=audience, subject=f"user:{claims['sub']}",
        permissions=claims.get("perms", []), scope=claims.get("scope") or {}, request_id=request_id_var.get(),
    )
    headers = {k: v for k, v in request.headers.items() if k.lower() in _FORWARD_REQUEST_HEADERS}
    headers["authorization"] = f"Bearer {token}"
    headers["x-request-id"] = request_id_var.get() or ""

    try:
        upstream = await state.http.request(method, base_url + upstream_path, params=request.query_params,
                                            content=body, headers=headers)
    except httpx.TimeoutException as exc:
        raise HTTPException(504, detail=f"{audience} timed out") from exc
    except httpx.TransportError as exc:
        raise HTTPException(503, detail=f"{audience} unavailable") from exc

    if method in _MUTATING:
        outcome = "success" if upstream.status_code < 400 else "denied" if upstream.status_code in (401, 403) \
            else "failure"
        await write_audit(state.engine, AuditEntry(action=f"{resource_type}.{method.lower()}", outcome=outcome,
                                                   details={"status": upstream.status_code, "path": upstream_path},
                                                   **audit_base))

    response_headers = {k: v for k, v in upstream.headers.items() if k.lower() in _FORWARD_RESPONSE_HEADERS}
    return Response(content=upstream.content, status_code=upstream.status_code, headers=response_headers)
