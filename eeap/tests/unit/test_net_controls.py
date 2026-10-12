import importlib
from datetime import UTC, datetime

from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
net = importlib.import_module("assessment_app.controls.net")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def host(ip: str, probes: dict) -> dict:
    return {"ip": ip, "probes": probes, "collected_at": NOW.isoformat()}


def by_control(evaluation, control_id: str):
    return [r for r in evaluation.observations if r.control_id == control_id]


def test_net_controls_detect_common_exposures():
    snapshot = {
        "hosts": [
            host("10.0.0.10", {
                "dns_axfr": {"axfr_permitted": True, "rr_count": 12, "zone": "."},
                "tls": [{"port": 443, "open": True, "negotiated_version": "TLSv1.2",
                         "tls10_accepted": True, "tls11_accepted": False, "cipher": "AES"}],
                "smb": {"open": True, "port": 445, "latency_ms": 1.2},
                "snmp": {"public_community_accepted": True, "responded": True, "port": 161},
                "ntp": {"responded": True, "port": 123, "version": 4, "mode": 4},
            }),
            host("10.0.0.11", {
                "dns_axfr": {"axfr_permitted": False, "error": "TransferError", "reachable": True},
                "tls": [{"port": 443, "open": False, "error": "TimeoutError"},
                        {"port": 8443, "open": False, "error": "TimeoutError"}],
                "smb": {"open": False, "port": 445, "error": "TimeoutError"},
                "snmp": {"public_community_accepted": False, "responded": False, "port": 161},
                "ntp": {"responded": False, "port": 123},
            }),
        ]
    }
    evaluation = net.evaluate(snapshot, None, NOW)
    assert evaluation.evaluated_controls == list(net.NET_CONTROL_IDS)
    assert {a["asset_id"] for a in evaluation.assets} == {"IP-10-0-0-10", "IP-10-0-0-11"}

    fail_statuses = {(r.control_id, r.status) for r in by_control(evaluation, "NET-001")
                     if r.asset_id == "IP-10-0-0-10"}
    assert ("NET-001", "FAIL") in fail_statuses
    assert any(r.status == "PASS" and r.asset_id == "IP-10-0-0-11" for r in by_control(evaluation, "NET-001"))

    assert any(r.status == "FAIL" and "TLS 1.0" in r.evidence["summary"]
               for r in by_control(evaluation, "NET-002") if r.asset_id == "IP-10-0-0-10")
    assert any(r.status == "FAIL" for r in by_control(evaluation, "NET-003") if r.asset_id == "IP-10-0-0-10")
    assert any(r.status == "FAIL" for r in by_control(evaluation, "NET-004") if r.asset_id == "IP-10-0-0-10")
    assert any(r.status == "WARNING" for r in by_control(evaluation, "NET-005") if r.asset_id == "IP-10-0-0-10")

    hardened = [r for r in evaluation.observations if r.asset_id == "IP-10-0-0-11"]
    assert {r.control_id: r.status for r in hardened} == {
        "NET-001": "PASS", "NET-002": "PASS", "NET-003": "PASS", "NET-004": "PASS", "NET-005": "PASS",
    }


def test_net_evaluate_subset_of_controls():
    snapshot = {"hosts": [host("192.168.1.5", {
        "smb": {"open": True, "port": 445},
    })]}
    evaluation = net.evaluate(snapshot, ["NET-003"], NOW)
    assert evaluation.evaluated_controls == ["NET-003"]
    assert len(evaluation.observations) == 1
    assert evaluation.observations[0].status == "FAIL"
