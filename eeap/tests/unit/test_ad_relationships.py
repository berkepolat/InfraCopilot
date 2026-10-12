import importlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from conftest import load_service_package
from test_ad_controls import BASE, DOMAIN_SID, account, lab_snapshot

load_service_package("assessment-service", "assessment_app")
rel = importlib.import_module("assessment_app.ad_relationships")

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "shared" / "schemas" / "relationship.schema.json")
                    .read_text())
RUN_ID = "00000000-0000-4000-8000-000000000001"


def edges(snapshot=None):
    return rel.build_relationships(snapshot or lab_snapshot(), RUN_ID)


def find(relationships, relationship, source_name=None, target_name=None):
    return [r for r in relationships if r["relationship"] == relationship
            and (source_name is None or r["source_node"]["display_name"] == source_name)
            and (target_name is None or r["target_node"]["display_name"] == target_name)]


def test_relationships_match_the_event_schema():
    validator = Draft202012Validator(SCHEMA)
    relationships = edges()
    assert relationships
    for r in relationships:
        validator.validate(r)
        assert r["properties"]["scope"] == "ad:lab.eeap.local"
        assert r["origin"] == "collector" and r["observed_run_id"] == RUN_ID


def test_privileged_membership_and_domain_control():
    relationships = edges()
    da_members = find(relationships, "MemberOf", target_name="Domain Admins")
    assert {r["source_node"]["display_name"] for r in da_members} == {"alice", "bob", "carol", "dave", "erin",
                                                                       "frank", "svc_sql"}
    group = da_members[0]["target_node"]
    assert group["node_key"] == f"ad:{DOMAIN_SID}-512" and group["is_tier0"] and group["is_privileged"]
    svc = next(r["source_node"] for r in da_members if r["source_node"]["display_name"] == "svc_sql")
    assert svc["node_type"] == "ServiceAccount" and svc["is_privileged"] and not svc["is_tier0"]
    assert svc["properties"]["dn"] == f"CN=svc_sql,CN=Users,{BASE}"
    frank = next(r["source_node"] for r in da_members if r["source_node"]["display_name"] == "frank")
    assert frank["enabled"] is False

    control = find(relationships, "PrivilegedAccess", "Domain Admins")
    assert len(control) == 1
    domain = control[0]["target_node"]
    assert domain == {**domain, "node_key": "asset:LAB.EEAP.LOCAL", "node_type": "Tier0Asset",
                      "asset_id": "LAB.EEAP.LOCAL", "is_tier0": True}


def test_delegation_edges():
    relationships = edges()
    constrained = find(relationships, "Delegation", "svc_web", "DC1")
    assert len(constrained) == 1
    assert constrained[0]["properties"]["delegation_type"] == "constrained"
    assert constrained[0]["properties"]["protocol_transition"] is True
    dc = constrained[0]["target_node"]
    assert dc["node_key"] == "asset:DC1" and dc["node_type"] == "Computer" and dc["is_tier0"]

    unconstrained = find(relationships, "Delegation", "APP01")
    assert [r["target"] for r in unconstrained] == ["asset:LAB.EEAP.LOCAL"]
    assert unconstrained[0]["properties"]["delegation_type"] == "unconstrained"

    # DCs are trusted for delegation by design; unresolvable SPN hosts produce no edge.
    assert not find(relationships, "Delegation", "DC1")
    assert not find(relationships, "Delegation", "FS01")


def test_disabled_accounts_do_not_delegate_and_edges_are_unique():
    snapshot = lab_snapshot()
    snapshot["users"].append(account("svc_dead", 0x202 | 0x1000000, delegate_to=["cifs/dc1.lab.eeap.local"]))
    relationships = edges(snapshot)
    assert not find(relationships, "Delegation", "svc_dead")
    keys = [(r["source"], r["target"], r["relationship"]) for r in relationships]
    assert len(keys) == len(set(keys))


def test_nested_group_members_become_group_nodes():
    snapshot = lab_snapshot()
    nested = {"dn": f"CN=Tier0 Ops,CN=Users,{BASE}", "sam": "Tier0 Ops", "sid": f"{DOMAIN_SID}-4000",
              "kind": "group", "enabled": None}
    snapshot["privileged_groups"][0]["members"].append(nested)
    edge = find(edges(snapshot), "MemberOf", "Tier0 Ops", "Domain Admins")
    assert len(edge) == 1
    assert edge[0]["source_node"]["node_type"] == "Group" and edge[0]["source_node"]["is_privileged"]
