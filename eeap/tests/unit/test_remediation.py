import importlib.util
import re

from conftest import ROOT, load_service_module

rem = load_service_module("ai-engine", "remediation", "ai_remediation")


def _migration():
    spec = importlib.util.spec_from_file_location(
        "ai_0005", ROOT / "services" / "ai-engine" / "migrations" / "versions" / "ai_0005_mitre_remediation.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION = _migration()
TEMPLATES = {c: rem.Template(*t) for c, t in MIGRATION.TEMPLATES.items()}


def finding(fid, control, score):
    return rem.OpenFinding(fid, control, score)


def scenario(sid, rule, score):
    return rem.ActiveScenario(sid, (rule, "org"), score, f"Scenario {sid}")


def test_catalog_is_consistent():
    for technique_id in MIGRATION.TECHNIQUES:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id)
    for control_id, entries in MIGRATION.MAPPING.items():
        assert control_id in MIGRATION.TEMPLATES
        for technique_id, rationale in entries:
            assert technique_id in MIGRATION.TECHNIQUES and rationale
    assert {t[2] for t in MIGRATION.TEMPLATES.values()} <= set(rem.EFFORT_WEIGHT)


def test_reduction_counts_findings_and_broken_scenarios():
    findings = [finding("a1", "AD-002", 80), finding("a2", "AD-002", 60), finding("n1", "NET-001", 60)]
    scenarios = [scenario("s1", "CORR-AD-001", 100)]
    keys = {("CORR-AD-001", "org")}
    items = {i.control_id: i for i in rem.build_roadmap(
        findings, scenarios, TEMPLATES, lambda c: set() if c == "AD-002" else keys)}
    # total open risk = 80 + 60 + 60 + 100 = 300
    ad = items["AD-002"]
    assert ad.expected_risk_reduction == 80  # (140 + 100) / 300
    assert ad.scenario_ids == ["s1"] and ad.finding_ids == ["a1", "a2"]
    assert ad.roadmap_phase == "Immediate"  # breaks a critical scenario
    assert ad.rationale["scenarios_broken"] == ["Scenario s1"]
    net = items["NET-001"]
    assert net.expected_risk_reduction == 20 and net.scenario_ids == []
    assert net.roadmap_phase == "Medium-term"
    assert [ad.priority, net.priority] == [1, 2]


def test_phase_thresholds():
    assert rem.phase_for(95, []) == "Immediate"
    assert rem.phase_for(50, [92]) == "Immediate"
    assert rem.phase_for(75, []) == "Short-term"
    assert rem.phase_for(20, [60]) == "Short-term"
    assert rem.phase_for(45, []) == "Medium-term"
    assert rem.phase_for(10, []) == "Long-term"


def test_value_per_effort_orders_within_phase():
    # Same phase and risk: the low-effort fix comes first.
    templates = {"X-1": rem.Template("High effort", "", "High"), "X-2": rem.Template("Low effort", "", "Low")}
    items = rem.build_roadmap([finding("f1", "X-1", 50), finding("f2", "X-2", 50)], [], templates, lambda c: set())
    assert [(i.control_id, i.priority) for i in items] == [("X-2", 1), ("X-1", 2)]


def test_zero_scores_and_unknown_controls():
    items = rem.build_roadmap([finding("f1", "AD-001", 0), finding("f2", "ZZ-9", 30)], [], TEMPLATES,
                              lambda c: set())
    assert [i.control_id for i in items] == ["ZZ-9"]
    assert items[0].title == "Remediate ZZ-9" and items[0].effort == "Medium"
    assert items[0].expected_risk_reduction == 100
