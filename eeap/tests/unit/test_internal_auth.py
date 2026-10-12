import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eeap_shared.utils.internal_auth import InternalTokenVerifier, mint_internal_token


def _keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return private, public


PRIVATE, PUBLIC = _keypair()


def test_round_trip_preserves_principal():
    token = mint_internal_token(PRIVATE, audience="asset-service", subject="user-1",
                                permissions=["assets:read"], scope={"owner_ids": ["o1"]}, request_id="r1")
    principal = InternalTokenVerifier(PUBLIC, "asset-service").verify(token)
    assert principal.subject == "user-1"
    assert principal.has("assets:read") and not principal.has("assets:write")
    assert principal.scope == {"owner_ids": ["o1"]}
    assert principal.request_id == "r1"


def test_token_for_other_service_is_rejected():
    token = mint_internal_token(PRIVATE, audience="reporting-service", subject="u", permissions=[])
    with pytest.raises(jwt.InvalidAudienceError):
        InternalTokenVerifier(PUBLIC, "asset-service").verify(token)


def test_expired_token_is_rejected():
    token = mint_internal_token(PRIVATE, audience="asset-service", subject="u", permissions=[], ttl_seconds=-5)
    with pytest.raises(jwt.ExpiredSignatureError):
        InternalTokenVerifier(PUBLIC, "asset-service").verify(token)


def test_token_signed_by_another_key_is_rejected():
    other_private, _ = _keypair()
    token = mint_internal_token(other_private, audience="asset-service", subject="u", permissions=[])
    with pytest.raises(jwt.InvalidSignatureError):
        InternalTokenVerifier(PUBLIC, "asset-service").verify(token)


def test_unsigned_token_is_rejected():
    token = jwt.encode({"iss": "eeap-gateway", "aud": "asset-service", "sub": "u", "iat": 0, "exp": 2**31},
                       key=None, algorithm="none")
    with pytest.raises(jwt.InvalidAlgorithmError):
        InternalTokenVerifier(PUBLIC, "asset-service").verify(token)
