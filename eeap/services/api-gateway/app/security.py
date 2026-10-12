from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import uuid

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
# Verified against when the user does not exist, so response timing does not reveal valid usernames.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 14


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def new_opaque_token() -> tuple[str, bytes]:
    token = secrets.token_urlsafe(48)
    return token, sha256(token)


def sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


class JwtIssuer:
    """RS256 user access tokens; public key is published as JWKS."""

    def __init__(self, private_pem: str, public_pem: str, issuer: str, audience: str, ttl_seconds: int) -> None:
        self._private = private_pem
        self._public = public_pem
        self.issuer, self.audience, self.ttl = issuer, audience, ttl_seconds
        public_key = serialization.load_pem_public_key(public_pem.encode())
        der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = base64.urlsafe_b64encode(hashlib.sha256(der).digest()[:12]).decode().rstrip("=")
        self._jwk = json.loads(RSAAlgorithm.to_jwk(public_key))

    def issue(self, *, user_id: str, username: str, roles: list[str], permissions: list[str], scope: dict) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer, "aud": self.audience, "sub": user_id, "name": username,
            "roles": sorted(roles), "perms": sorted(permissions), "scope": scope,
            "iat": now, "exp": now + self.ttl, "jti": str(uuid.uuid4()), "typ": "access",
        }
        return jwt.encode(claims, self._private, algorithm="RS256", headers={"kid": self.kid})

    def verify(self, token: str) -> dict:
        claims = jwt.decode(
            token, self._public, algorithms=["RS256"], audience=self.audience, issuer=self.issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
        if claims.get("typ") != "access":
            raise jwt.InvalidTokenError("not an access token")
        return claims

    def jwks(self) -> dict:
        return {"keys": [{**self._jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}
