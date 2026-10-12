import importlib

from conftest import load_service_package

load_service_package("asset-service", "asset_app")
discovery = importlib.import_module("asset_app.discovery")

RULES = [
    {"condition": {"asset_type": "DomainController"}, "set_values": {"tier": "Tier0", "criticality": "Critical"}},
    {"condition": {"asset_type": "Identity", "tags_any": ["ad:domain"]},
     "set_values": {"tier": "Tier0", "criticality": "Critical"}},
    {"condition": {"asset_type": "Database", "environment": "Production"}, "set_values": {"criticality": "High"}},
    {"condition": {"asset_type": "Database"}, "set_values": {"criticality": "Medium", "tier": "Tier1"}},
]


def test_rule_conditions_require_all_keys():
    assert discovery.rule_matches({"asset_type": "Identity", "tags_any": ["ad:domain"]},
                                  {"asset_type": "Identity", "tags": ["ad:domain", "x"]})
    assert not discovery.rule_matches({"asset_type": "Identity", "tags_any": ["ad:domain"]},
                                      {"asset_type": "Identity", "tags": []})
    assert not discovery.rule_matches({"asset_type": "DomainController"}, {"asset_type": "Server"})


def test_first_matching_rule_wins_per_field():
    assert discovery.classify(RULES, {"asset_type": "DomainController", "tags": []}) == \
        {"tier": "Tier0", "criticality": "Critical"}
    assert discovery.classify(RULES, {"asset_type": "Database", "environment": "Production", "tags": []}) == \
        {"criticality": "High", "tier": "Tier1"}
    assert discovery.classify(RULES, {"asset_type": "Workstation", "tags": []}) == {}
