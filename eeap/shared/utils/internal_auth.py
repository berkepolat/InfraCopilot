"""Short-lived, audience-bound service tokens minted by the API Gateway (ADR-0007).

The gateway signs with an Ed25519 private key; services hold only the public key, so a
compromised service cannot mint tokens for other services.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, HTTPException, Request, status

ISSUER = "eeap-gateway"
ALGORITHM = "EdDSA"
DEFAULT_TTL_SECONDS = 60


@dataclass(frozen=True)
class Principal:
    subject: str
    permissions: frozenset[str]
    scope: dict = field(default_factory=dict)
    request_id: str | None = None

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def mint_internal_token(
    private_key_pem: str,
    *,
    audience: str,
    subject: str,
    permissions: list[str] | frozenset[str],
    scope: dict | None = None,
    request_id: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": audience,
        "sub": subject,
        "act": ISSUER,
        "perms": sorted(permissions),
        "scope": scope or {},
        "rid": request_id,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(claims, private_key_pem, algorithm=ALGORITHM)


class InternalTokenVerifier:
    def __init__(self, public_key_pem: str, audience: str) -> None:
        self._key = public_key_pem
        self._audience = audience

    def verify(self, token: str) -> Principal:
        claims = jwt.decode(
            token,
            self._key,
            algorithms=[ALGORITHM],
            audience=self._audience,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
        return Principal(
            subject=claims["sub"],
            permissions=frozenset(claims.get("perms", [])),
            scope=claims.get("scope") or {},
            request_id=claims.get("rid"),
        )


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


async def get_principal(request: Request) -> Principal:
    verifier: InternalTokenVerifier | None = getattr(request.app.state, "token_verifier", None)
    if verifier is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="token verifier not configured")
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized("missing internal service token")
    try:
        return verifier.verify(token)
    except jwt.PyJWTError as exc:
        raise _unauthorized("invalid internal service token") from exc


def require_permission(permission: str):
    async def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"missing permission {permission}")
        return principal

    return dependency
