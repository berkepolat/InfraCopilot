import json
import re
import typing
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from eeap_shared.models import domain

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "shared" / "schemas"


def _load(name: str) -> dict:
    return json.loads((SCHEMAS / f"{name}.schema.json").read_text())


def _enum(schema: dict, prop: str) -> set:
    node = schema["properties"][prop]
    if "$ref" in node:
        node = schema["$defs"][node["$ref"].rsplit("/", 1)[-1]]
    return {v for v in node["enum"] if v is not None}


@pytest.mark.parametrize("path", sorted(SCHEMAS.glob("*.schema.json")), ids=lambda p: p.name)
def test_schema_is_valid_draft_2020_12(path):
    Draft202012Validator.check_schema(json.loads(path.read_text()))


@pytest.mark.parametrize("schema,prop,literal", [
    ("asset", "asset_type", domain.AssetType),
    ("asset", "criticality", domain.Criticality),
    ("asset", "tier", domain.Tier),
    ("asset", "environment", domain.Environment),
    ("finding", "severity", domain.Severity),
    ("finding", "status", domain.FindingStatus),
    ("relationship", "relationship", domain.RelationshipType),
])
def test_model_enums_match_schemas(schema, prop, literal):
    assert set(typing.get_args(literal)) == _enum(_load(schema), prop)


def test_asset_create_payload_validates_against_schema():
    payload = domain.AssetCreate(asset_id="DC01", hostname="dc01", asset_type="DomainController",
                                 criticality="Critical", tier="Tier0", environment="Production")
    schema = _load("asset")
    document = {**payload.model_dump(mode="json", exclude_none=True), "status": "active"}
    errors = [e.message for e in Draft202012Validator(schema).iter_errors(document)
              if e.validator != "required"]
    assert errors == []


def test_route_permissions_exist_in_seed():
    from app.routes_table import ROUTES

    seed = (ROOT / "infrastructure" / "postgres" / "init" / "09_seed_reference_data.sql").read_text()
    seeded = set(re.findall(r"\('([a-z_]+:[a-z_]+)',", seed))
    used = {p for r in ROUTES for p in r.permissions.values()} | {o[2] for r in ROUTES for o in r.overrides}
    assert used - seeded == set()


def test_route_upstreams_are_configured():
    from app.config import GatewaySettings
    from app.routes_table import ROUTES

    assert {r.upstream for r in ROUTES} <= set(GatewaySettings().upstreams())
