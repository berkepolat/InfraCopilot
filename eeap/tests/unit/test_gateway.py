import pytest

from app.config import parse_rate
from app.routes_table import resolve
from app.security import MIN_PASSWORD_LENGTH, hash_password, verify_password


@pytest.mark.parametrize("value,expected", [("10/minute", (10, 60)), ("600/minutes", (600, 60)), ("5/hour", (5, 3600))])
def test_parse_rate(value, expected):
    assert parse_rate(value) == expected


@pytest.mark.parametrize("path,method,permission", [
    ("/assets", "GET", "assets:read"),
    ("/assets/DC01", "PATCH", "assets:write"),
    ("/findings/f1/risk-acceptance", "POST", "findings:accept_risk"),
    ("/findings/f1/evidence", "GET", "evidence:read"),
    ("/findings/f1/lifecycle", "POST", "findings:triage"),
    ("/imports", "POST", "imports:create"),
    ("/assessments/profiles", "POST", "assessments:manage"),
    ("/assessments/runs", "POST", "assessments:run"),
    ("/risk/summary", "GET", "risk:read"),
])
def test_route_permissions(path, method, permission):
    route = resolve(path)
    assert route is not None
    assert route.permission_for(method, path) == permission


@pytest.mark.parametrize("path", ["/internal/agent/results", "/assets/../internal/x", "/assetsX", "/unknown"])
def test_unroutable_paths(path):
    assert resolve(path) is None


def test_imports_have_a_larger_body_limit_than_the_default():
    assert resolve("/imports").max_body_bytes == 50 * 1024 * 1024
    assert resolve("/assets").max_body_bytes is None


def test_unmapped_method_has_no_permission():
    assert resolve("/graph/nodes").permission_for("DELETE", "/graph/nodes") is None


def test_password_hash_round_trip():
    password = "a" * MIN_PASSWORD_LENGTH
    hashed = hash_password(password)
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, password)
    assert not verify_password(hashed, password + "x")


def test_short_password_rejected():
    with pytest.raises(ValueError):
        hash_password("short")
