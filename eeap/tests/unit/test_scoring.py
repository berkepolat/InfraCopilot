import ast
import json
import re
from pathlib import Path

import pytest

from conftest import load_service_module

scoring = load_service_module("ai-engine", "scoring", "ai_scoring")

ROOT = Path(__file__).resolve().parents[2]


def _seed_model() -> "scoring.ScoringModel":
    seed = (ROOT / "infrastructure" / "postgres" / "init" / "09_seed_reference_data.sql").read_text()
    weights = re.search(r"\('v1', '[^']*',\s*'(\{.*?\})'::jsonb", seed, re.S).group(1)
    return scoring.ScoringModel("v1", json.loads(weights))


MODEL = _seed_model()


def _inputs(**overrides):
    base = dict(severity="High", status="FAIL", lifecycle_state="open", criticality="High", exploitability=0.7,
                privilege_impact=1.0, affected_count=12, propagation=0.8)
    return scoring.FindingInputs(**{**base, **overrides})


def test_worked_example_from_design_doc():
    result = scoring.score_finding(MODEL, _inputs())
    assert result.score == 77
    assert result.rating == "High"
    assert result.factors["normalized"]["B"] == pytest.approx(0.556, abs=1e-3)
    assert result.factors["floor_applied"] is False


@pytest.mark.parametrize("score,rating", [(100, "Critical"), (90, "Critical"), (89, "High"), (70, "High"),
                                          (69, "Medium"), (40, "Medium"), (39, "Low"), (0, "Low")])
def test_rating_bands(score, rating):
    assert MODEL.rating(score) == rating


@pytest.mark.parametrize("status,lifecycle", [("PASS", "open"), ("INFO", "open"), ("FAIL", "resolved"),
                                              ("FAIL", "risk_accepted"), ("FAIL", "false_positive")])
def test_gated_findings_score_zero_even_when_critical(status, lifecycle):
    result = scoring.score_finding(MODEL, _inputs(severity="Critical", status=status, lifecycle_state=lifecycle))
    assert result.score == 0
    assert result.factors["floor_applied"] is False


def test_open_critical_finding_never_drops_below_high_band():
    result = scoring.score_finding(MODEL, _inputs(severity="Critical", criticality="Low", exploitability=0.0,
                                                  privilege_impact=0.0, affected_count=1, propagation=None))
    assert result.score == 70
    assert result.factors["floor_applied"] is True


def test_warning_and_in_remediation_reduce_score():
    full = scoring.score_finding(MODEL, _inputs()).score
    assert scoring.score_finding(MODEL, _inputs(status="WARNING")).score < full
    assert scoring.score_finding(MODEL, _inputs(lifecycle_state="in_remediation")).score < full


def test_tier0_raises_privilege_impact_and_unknown_asset_defaults_to_medium():
    result = scoring.score_finding(MODEL, _inputs(privilege_impact=0.2, is_tier0=True, criticality=None))
    assert result.factors["normalized"]["P"] == 1.0
    assert result.factors["normalized"]["C"] == 0.5
    assert result.factors["inputs"]["asset_known"] is False


def test_breadth_is_logarithmic_and_capped():
    assert scoring.breadth(0, 100) == 0
    assert scoring.breadth(100, 100) == pytest.approx(1.0)
    assert scoring.breadth(10_000, 100) == 1.0
    assert scoring.breadth(1, 100) < scoring.breadth(10, 100) < scoring.breadth(50, 100)


def test_asset_score_combines_but_is_capped_one_band_above_worst():
    single = scoring.score_asset(MODEL, [60])
    assert single.score == 60
    many = scoring.score_asset(MODEL, [60, 55, 50, 45, 40])
    assert many.score == 75  # noisy-OR would be ~98; cap = 60 + 15
    assert scoring.score_asset(MODEL, [0, 0]).score == 0
    assert scoring.score_asset(MODEL, [95, 90]).score == 100


def test_asset_score_uses_only_top_ten():
    result = scoring.score_asset(MODEL, [50] * 25)
    assert result.factors["contributing"] == 10
    assert result.factors["open_findings"] == 25


def test_weighted_percentile():
    assert scoring.weighted_percentile([], 0.9) == 0
    assert scoring.weighted_percentile([(10, 1), (20, 1), (30, 1), (90, 1)], 0.9) == 90
    assert scoring.weighted_percentile([(10, 1), (90, 0.01)], 0.9) == 10


def test_organization_score_components():
    assets = [scoring.AssetScore("DC01", 80, "Critical", "Tier0"), scoring.AssetScore("WS1", 20, "Low", "Tier2"),
              scoring.AssetScore("DC02", 30, "Critical", "Tier0")]
    result = scoring.score_organization(MODEL, assets, max_scenario_score=0)
    assert result.factors["tier0_exposure_ratio"] == 0.5
    assert result.factors["asset_p90_weighted"] == 80
    assert result.score == 50  # 0.5*80 + 0.3*0 + 0.2*50
    assert result.rating == "Medium"


def test_organization_without_assets_is_zero():
    assert scoring.score_organization(MODEL, [], 0).score == 0


def _migration_v2() -> "scoring.ScoringModel":
    source = (ROOT / "services" / "ai-engine" / "migrations" / "versions" / "ai_0010_exposure_scoring.py").read_text()
    node = next(n for n in ast.parse(source).body
                if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == "V2_WEIGHTS")
    return scoring.ScoringModel("v2", ast.literal_eval(node.value))


V2 = _migration_v2()
LEGACY_HOST = [{"port": 21, "service": "ftp"}, {"port": 22, "service": "ssh"}, {"port": 23, "service": "telnet"},
               {"port": 445, "service": "smb"}]


def test_v2_factor_weights_sum_to_one_and_v1_has_no_exposure_factor():
    assert sum(V2.factor_weights.values()) == pytest.approx(1.0)
    assert "X" in V2.factor_weights and "X" not in MODEL.factor_weights
    assert "X" not in scoring.score_finding(MODEL, _inputs(services=LEGACY_HOST)).factors["normalized"]


def test_network_exposure_grows_with_sensitive_services():
    assert scoring.network_exposure([]) == (0.0, [])
    web, classes = scoring.network_exposure([{"port": 443, "service": "https"}])
    assert web == 0.2 and classes == []
    legacy, classes = scoring.network_exposure(LEGACY_HOST)
    assert classes == ["remote_admin", "file_sharing", "cleartext_login"]
    assert legacy == pytest.approx(0.2 + 3 * 0.05 + 0.2 + 0.15 + 0.15)
    assert scoring.network_exposure([{"port": 2375, "service": "docker"}, {"port": 6379, "service": "redis"},
                                     {"port": 22, "service": "ssh"}])[0] == 1.0
    assert scoring.network_exposure([{"port": 16379, "service": "redis"}])[1] == ["data_store"]


@pytest.mark.parametrize("services,expected", [
    ([{"port": 6379, "service": "redis"}], "High"), ([{"port": 389, "service": "ldap"}], "High"),
    ([{"port": 22, "service": "ssh"}], "Medium"), ([{"port": 443, "service": "https"}], None), ([], None)])
def test_suggested_criticality(services, expected):
    assert scoring.suggested_criticality(services) == expected


def test_v2_exposure_factor_unknown_none_and_exposed():
    unknown = scoring.score_finding(V2, _inputs())
    assert unknown.factors["normalized"]["X"] == 0.3
    assert unknown.factors["inputs"]["exposure_source"] == "not_scanned"
    closed = scoring.score_finding(V2, _inputs(services=[]))
    exposed = scoring.score_finding(V2, _inputs(services=LEGACY_HOST))
    assert closed.factors["normalized"]["X"] == 0.0
    assert exposed.factors["inputs"]["exposed_classes"] == ["remote_admin", "file_sharing", "cleartext_login"]
    assert closed.score < unknown.score < exposed.score


def test_v2_known_exploited_floor():
    weak = dict(severity="Medium", criticality="Low", exploitability=1.0, privilege_impact=0.0, affected_count=1,
                propagation=None, services=[])
    plain = scoring.score_finding(V2, _inputs(**weak))
    kev = scoring.score_finding(V2, _inputs(**weak, known_exploited=True))
    assert plain.score < 80 and plain.factors["floor_applied"] is False
    assert kev.score == 80 and kev.factors["floor"] == "known_exploited"
    assert scoring.score_finding(V2, _inputs(**weak, known_exploited=True, status="PASS")).score == 0
    assert scoring.score_finding(MODEL, _inputs(**weak, known_exploited=True)).score == plain_v1(weak)


def plain_v1(weak: dict) -> int:
    return scoring.score_finding(MODEL, _inputs(**weak)).score
