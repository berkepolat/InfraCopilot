from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import jwt
from fastapi import HTTPException, Request
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from .config import GatewaySettings
from .ratelimit import RateLimiter
from .security import JwtIssuer


@dataclass
class GatewayState:
    settings: GatewaySettings
    engine: AsyncEngine
    issuer: JwtIssuer
    limiter: RateLimiter
    http: AsyncClient
    internal_private_key: str


def gateway_state(request: Request) -> GatewayState:
    return request.app.state.gateway


def client_ip(request: Request, settings: GatewaySettings) -> str | None:
    peer = request.client.host if request.client else None
    if peer is None:
        return None
    forwarded = request.headers.get("x-real-ip")
    try:
        peer_addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if forwarded and any(peer_addr in net for net in settings.trusted_networks()):
        return forwarded
    return peer


def user_claims(request: Request) -> dict:
    """Validates the user's access JWT from the Authorization header."""
    state = gateway_state(request)
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, detail="missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    try:
        return state.issuer.verify(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(401, detail="invalid or expired token", headers={"WWW-Authenticate": "Bearer"}) from exc
