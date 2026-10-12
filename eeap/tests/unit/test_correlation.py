import importlib.util
import json

from conftest import ROOT, load_service_module

corr = load_service_module("ai-engine", "correlation", "ai_correlation")

BASE = "DC=lab,DC=eeap,DC=local"
SVC_SQL = f"CN=svc_sql,CN=Users,{BASE}"
LEGACY = f"CN=legacy_app,CN=Users,{BASE}"
APP01 = f"CN=APP01,CN=Computers,{BASE}"


def _rules() -> dict:
    spec = importlib.util.spec_from_file_location(
        "ai_0004", ROOT / "services" / "ai-engine" / "migrations" / "versions" / "ai_0004_correlation_rules.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rules = {rule_id: definition for rule_id, (_, definition) in module.RULES.items()}
    rules["CORR-AUTH-001"] = module.AUTH_001_V2
    return json.loads(json.dumps(rules))  # as stored in jsonb


RULES = _rules()


def finding(fid, control, subject, score=70, asset="LAB.EEAP.LOCAL"):
    return corr.FindingFact(fid, control, asset, subject, score)


def fact(hops, *, tier0=False, privileged=False):
    return corr.GraphFact(1.0 if hops == 0 else 0.9, hops is not None, hops, tier0, privileged)


GRAPH = {SVC_SQL.lower(): fact(1, privileged=True), APP01.lower(): fact(1), LEGACY.lower(): None}


def graph_of(f):
    if "dc=" in f.subject_key.lower():
        return GRAPH.get(f.subject_key.lower())
    return fact(0, tier0=True, privileged=True)


def subject_graph(subject):
    return GRAPH.get(subject.lower())


def run(findings, rules=RULES):
    return {(s.rule_id, s.scope_key): s for s in corr.evaluate(rules, findings, graph_of, subject_graph)}


def test_crackable_credentials_with_tier0_path():
    scenarios = run([finding("f1", "AD-002", SVC_SQL, 88), finding("f2", "AD-003", LEGACY, 70)])
    scenario = scenarios[("CORR-AD-001", f"subject:{SVC_SQL.lower()}")]
    assert scenario.title == "Crackable credentials of svc_sql lead directly to Tier 0"
    assert scenario.score == 93  # 88 + 5 x (2 stages - 1)
    assert [s.matched for s in scenario.stages] == [True, True, True]
    assert scenario.stages[1].graph_evidence["min_hops"] == 1
    assert scenario.finding_stages == {"f1": 1}
    # legacy_app has no path to Tier 0, so its weakness alone is no scenario
    assert ("CORR-AD-001", f"subject:{LEGACY.lower()}") not in scenarios


def test_delegation_rule_and_hop_bound():
    scenarios = run([finding("d1", "AD-004", APP01, 64, asset="APP01")])
    scenario = scenarios[("CORR-AD-002", f"subject:{APP01.lower()}")]
    assert scenario.affected_asset_ids == ["APP01"] and scenario.score == 69
    GRAPH[APP01.lower()] = fact(3)
    try:
        assert ("CORR-AD-002", f"subject:{APP01.lower()}") not in run([finding("d1", "AD-004", APP01, 64)])
    finally:
        GRAPH[APP01.lower()] = fact(1)


def test_tier0_subjects_do_not_satisfy_a_path_into_tier0():
    assert not corr.graph_condition_holds({"tier0_reachable": True, "max_hops": 1}, fact(0, tier0=True))
    assert corr.graph_condition_holds({"tier0_reachable": True, "include_tier0": True}, fact(0, tier0=True))
    assert corr.graph_condition_holds({"privileged": True}, fact(None, privileged=True))
    assert not corr.graph_condition_holds({"privileged": True}, None)


def test_organization_rule_min_stages_and_required_stage():
    base = [finding("p1", "AD-001", "default-domain-password-policy", 60),
            finding("s1", "AD-002", SVC_SQL, 88), finding("g1", "AD-007", "S-1-5-21-1-512", 79)]
    scenario = run(base)[("CORR-AD-003", "organization")]
    assert scenario.score == 98  # 88 + 5 x 2
    assert [s.matched for s in scenario.stages] == [True, True, True, False, True]
    assert scenario.stages[3].finding_ids == []

    # the privileged group stage is required
    no_groups = [f for f in base if f.control_id != "AD-007"] + [finding("l1", "AD-008", "laps-schema", 71)]
    assert ("CORR-AD-003", "organization") not in run(no_groups)
    # two stages are not enough
    assert ("CORR-AD-003", "organization") not in run(base[1:])


def test_all_stages_rule_needs_windows_evidence():
    findings = [finding("s1", "AD-002", SVC_SQL, 88), finding("g1", "AD-007", "S-1-5-21-1-512", 79)]
    assert ("CORR-AUTH-001", "organization") not in run(findings)
    scenario = run(findings + [finding("w1", "WIN-001", "registry", 50, asset="WS01")])[("CORR-AUTH-001", "organization")]
    assert scenario.score == 98 and scenario.affected_asset_ids == ["LAB.EEAP.LOCAL", "WS01"]


def test_scores_are_capped_and_zero_scores_do_not_raise_scenarios():
    findings = [finding("p1", "AD-001", "policy", 99), finding("s1", "AD-002", SVC_SQL, 99),
                finding("g1", "AD-007", "S-1", 99), finding("l1", "AD-008", "laps", 99)]
    assert run(findings)[("CORR-AD-003", "organization")].score == 100
    assert not run([finding("s1", "AD-002", SVC_SQL, 0)])


def test_subject_label():
    assert corr.subject_label(SVC_SQL) == "svc_sql"
    assert corr.subject_label("CN=Smith\\, John,OU=Staff,DC=x") == "Smith, John"
    assert corr.subject_label("default-domain-password-policy") == "default-domain-password-policy"
