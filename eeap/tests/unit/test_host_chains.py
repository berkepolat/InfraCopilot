import importlib.util
import json

from conftest import ROOT, load_service_module

corr = load_service_module("ai-engine", "correlation", "ai_correlation")
scoring = load_service_module("ai-engine", "scoring", "ai_scoring")


def _migration(name: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "services" / "ai-engine" / "migrations" / "versions" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HOST = _migration("ai_0012_host_attack_chains")
RULES = json.loads(json.dumps({rule_id: definition for rule_id, (_, definition) in HOST.RULES.items()}))

WEB = "IP-10-0-0-5"
DB = "IP-10-0-0-6"
DC = "AST-DC01"


def exposure(*services):
    listed = [{"port": p, "service": s} for p, s in services]
    score, classes = scoring.network_exposure(listed)
    return corr.ExposureFact(score, tuple(classes), tuple(f"{p}/{s}" for p, s in services))


def graph(hops, tier0=False):
    return corr.GraphFact(0.9, hops is not None, hops, tier0, tier0)


CONTEXT = {
    WEB: corr.AssetContext("web01", None, exposure((22, "ssh"), (443, "https"))),
    DB: corr.AssetContext("db01", graph(2), corr.ExposureFact(0.0, (), ())),
    DC: corr.AssetContext("dc01", graph(0, tier0=True), exposure((88, "kerberos"), (389, "ldap"))),
}


def finding(fid, control, asset, score=60, exploitability=0.5, kev=False, subject="x"):
    return corr.FindingFact(fid, control, asset, subject, score, exploitability, kev)


def run(findings):
    scenarios = corr.evaluate(RULES, findings, lambda f: CONTEXT[f.asset_id].graph if f.asset_id in CONTEXT else None,
                              lambda s: None, CONTEXT.get)
    return {(s.rule_id, s.scope_key): s for s in scenarios}


def test_exposed_host_with_highly_exploitable_vulnerability():
    found = run([finding("f1", "LIN-009", WEB, 71, 0.99, subject="pkg:openssl"),
                 finding("f2", "LIN-009", WEB, 54, 0.41, subject="pkg:zlib")])
    scenario = found[("CORR-HOST-001", f"asset:{WEB.lower()}")]
    assert scenario.title == "web01 is reachable and runs software with a likely exploited vulnerability"
    assert scenario.score == 76  # 71 + 5 x (2 evidence stages - 1)
    exposed, vulnerable, derived = scenario.stages
    assert exposed.exposure_evidence["services"] == ["22/ssh", "443/https"] and exposed.tactic == "initial-access"
    assert vulnerable.finding_ids == ["f1"]  # zlib is below the exploitability threshold
    assert exposed.breaks_chain and vulnerable.breaks_chain and not derived.breaks_chain
    assert derived.as_dict() == {"order": 3, "name": "Host Compromise Exposure", "matched": True, "finding_ids": [],
                                 "derived": True, "tactic": "impact"}
    assert scenario.affected_asset_ids == [WEB]


def test_kev_listed_windows_update_and_unexposed_host():
    found = run([finding("f1", "WIN-010", WEB, 80, 1.0, kev=True, subject="kb:KB5070001"),
                 finding("f2", "LIN-009", DB, 70, 0.99)])
    assert ("CORR-HOST-001", f"asset:{WEB.lower()}") in found
    # db01 was scanned and has no open services: no entry point, no scenario
    assert ("CORR-HOST-001", f"asset:{DB.lower()}") not in found
    assert not run([finding("f3", "LIN-009", "IP-10-0-0-9", 70, 0.99)])  # never scanned


def test_patch_gaps_on_path_to_tier0():
    found = run([finding("f1", "WIN-012", DB, 65), finding("f2", "WIN-010", DC, 75), finding("f3", "LIN-002", WEB)])
    db = found[("CORR-HOST-002", f"asset:{DB.lower()}")]
    assert db.title == "Patch gaps on db01 sit on a path to Tier 0"
    assert db.stages[1].graph_evidence["min_hops"] == 2 and db.stages[1].tactic == "lateral-movement"
    assert ("CORR-HOST-002", f"asset:{DC.lower()}") in found  # the Tier-0 host itself
    assert ("CORR-HOST-002", f"asset:{WEB.lower()}") not in found  # no graph fact


def test_exposed_remote_access_with_weak_settings():
    found = run([finding("f1", "WIN-001", WEB, 50), finding("f2", "LIN-004", WEB, 40)])
    scenario = found[("CORR-HOST-003", f"asset:{WEB.lower()}")]
    assert [s.matched for s in scenario.stages] == [True, True, True, True]
    assert scenario.summary.startswith("web01 offers remote administration or file sharing on the network while 3 ")
    # min_stages 2 with required exposure: only the exposure breaks the chain alone
    assert [s.breaks_chain for s in scenario.stages] == [True, False, False, False]
    single = run([finding("f1", "WIN-001", WEB, 50)])[("CORR-HOST-003", f"asset:{WEB.lower()}")]
    assert [s.breaks_chain for s in single.stages[:3]] == [True, True, False]
    # dc01 only exposes directory services, which this chain does not cover
    assert ("CORR-HOST-003", f"asset:{DC.lower()}") not in run([finding("f3", "WIN-001", DC, 50)])


def test_finding_condition():
    hot = finding("f", "LIN-009", WEB, exploitability=0.95)
    assert corr.finding_condition_holds({"min_exploitability": 0.9}, hot)
    assert not corr.finding_condition_holds({"known_exploited": True}, hot)
    assert corr.finding_condition_holds(None, hot)


def test_existing_rules_get_tactics():
    assert set(HOST.TACTICS) == {"CORR-AD-001", "CORR-AD-002", "CORR-AD-003", "CORR-AUTH-001"}
    ad = _migration("ai_0004_correlation_rules")
    for rule_id, (_, definition) in ad.RULES.items():
        assert {s["order"] for s in definition["stages"]} == set(HOST.TACTICS[rule_id])
    assert {s["order"] for s in ad.AUTH_001_V2["stages"]} == set(HOST.TACTICS["CORR-AUTH-001"])
