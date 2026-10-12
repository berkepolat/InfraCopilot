import importlib

import pytest
from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
verification = importlib.import_module("assessment_app.verification")
port_scan = importlib.import_module("assessment_app.collectors.port_scan")

RUN = "7a1f0f7e-2b1c-4d5e-8f90-123456789abc"


def finding(control, subject="", ip="172.20.0.2", source="server", status="FAIL", state="open", asset="IP-172-20-0-2"):
    return {"finding_id": f"{control}-{subject}", "asset_id": asset, "control_id": control, "subject_key": subject,
            "status": status, "lifecycle_state": state, "source": source, "ip": ip}


def test_network_plan_covers_controls_ips_and_non_default_ports():
    plan = verification.plan([
        finding("NET-006", "tcp:22"),
        finding("NET-008", "tcp:6379", ip="172.20.0.8"),
        finding("NET-011", "web:8081"),
        finding("LIN-009", "pkg:openssl"),
    ], port_scan.COMMON_PORTS)
    assert plan.module == "NET"
    assert plan.control_ids == ["LIN-009", "NET-006", "NET-008", "NET-011"]
    assert plan.ips == ["172.20.0.2", "172.20.0.8"]
    assert plan.ports == [8081]  # 22 and 6379 are in the common profile


def test_ad_plan():
    plan = verification.plan([finding("AD-002", "CN=svc_sql,CN=Users,DC=lab", ip=None, asset="AST-LAB"),
                              finding("AD-004", "CN=APP01,CN=Computers,DC=lab", ip=None, asset="AST-LAB")],
                             port_scan.COMMON_PORTS)
    assert (plan.module, plan.control_ids, plan.ips, plan.ports) == ("AD", ["AD-002", "AD-004"], [], [])


@pytest.mark.parametrize(("findings", "message"), [
    ([], "at least one"),
    ([finding("NET-006", "tcp:22", source="import")], "import findings are verified by a new import"),
    ([finding("NET-006", "tcp:22", status="PASS", state="resolved")], "not open"),
    ([finding("NET-006", "tcp:22", state="risk_accepted")], "risk_accepted, not open"),
    ([finding("NET-006", "tcp:22", ip=None)], "no IP address"),
    ([finding("NET-006", "tcp:22"), finding("AD-002", "CN=x", ip=None)], "separately"),
    ([finding("NET-006", f"tcp:{p}") for p in range(1, 52)], "at most 50"),
])
def test_plan_rejects(findings, message):
    with pytest.raises(verification.VerificationError, match=message):
        verification.plan(findings, port_scan.COMMON_PORTS)


@pytest.mark.parametrize(("after", "run_status", "expected"), [
    ({"status": "PASS", "last_seen_run_id": RUN}, "completed", "verified"),
    ({"status": "FAIL", "last_seen_run_id": RUN}, "completed", "still_failing"),
    ({"status": "WARNING", "last_seen_run_id": RUN}, "partially_completed", "still_failing"),
    ({"status": "FAIL", "last_seen_run_id": "00000000-0000-0000-0000-000000000000"}, "completed", "inconclusive"),
    (None, "completed", "inconclusive"),
    ({"status": "PASS", "last_seen_run_id": RUN}, "failed", "failed"),
])
def test_outcome(after, run_status, expected):
    status, summary = verification.outcome(after, RUN, run_status)
    assert status == expected and summary
