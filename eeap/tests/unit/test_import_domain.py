import json
from pathlib import Path

import pytest

from conftest import load_service_module

domain = load_service_module("assessment-service", "domain", "assessment_domain")

EXAMPLES = Path(__file__).resolve().parents[2] / "docs" / "examples"


def test_sample_json_parses_cleanly():
    result = domain.parse_import("eeap_json", (EXAMPLES / "findings-sample.json").read_bytes(), 1000)
    assert result.total == 7 and len(result.rows) == 7 and result.errors == []
    assert {r.source_tool for r in result.rows} == {"eeap-sample/1.0"}
    assert result.rows[0].evidence["min_length"] == 8


def test_sample_csv_reports_invalid_rows():
    result = domain.parse_import("eeap_csv", (EXAMPLES / "findings-sample.csv").read_bytes(), 1000)
    assert result.total == 5
    assert len(result.rows) == 3
    assert [e["row"] for e in result.errors] == [4, 5]
    ntp = next(r for r in result.rows if r.asset_id == "NTP01")
    assert ntp.severity == "Low" and ntp.evidence == {"summary": "NTP service accepts mode 6 queries from any source"}
    ws = next(r for r in result.rows if r.control_id == "WIN-003")
    assert ws.severity is None  # filled from the control catalog at upsert time


def test_bare_json_array_is_accepted():
    data = json.dumps([{"asset_id": "A1", "control_id": "AD-001", "status": "FAIL"}]).encode()
    assert len(domain.parse_import("eeap_json", data, 10).rows) == 1


@pytest.mark.parametrize("payload,message", [
    (b"{not json", "invalid JSON"),
    (b'{"items": []}', "expected a JSON array"),
    (b"\xff\xfe", "UTF-8"),
])
def test_unparseable_json_files_are_rejected(payload, message):
    with pytest.raises(domain.ImportFormatError, match=message):
        domain.parse_import("eeap_json", payload, 10)


def test_csv_without_required_columns_is_rejected():
    with pytest.raises(domain.ImportFormatError, match="header"):
        domain.parse_import("eeap_csv", b"host,check\nA,B\n", 10)


def test_row_limit_is_enforced():
    data = json.dumps([{"asset_id": "A1", "control_id": "AD-001", "status": "FAIL"}] * 3).encode()
    with pytest.raises(domain.ImportFormatError, match="limit"):
        domain.parse_import("eeap_json", data, 2)


@pytest.mark.parametrize("row,field", [
    ({"asset_id": "A1", "control_id": "AD-001", "status": "BROKEN"}, "status"),
    ({"asset_id": "A1", "control_id": "AD-001", "status": "FAIL", "severity": "Severe"}, "severity"),
    ({"asset_id": "-bad", "control_id": "AD-001", "status": "FAIL"}, "asset_id"),
    ({"asset_id": "A1", "control_id": "AD-001", "status": "FAIL", "raw_data": {"x": "y" * 70_000}}, "raw_data"),
])
def test_invalid_rows_are_reported_not_fatal(row, field):
    result = domain.parse_import("eeap_json", json.dumps([row]).encode(), 10)
    assert result.rows == []
    assert field in result.errors[0]["error"]


def test_fingerprint_is_stable_and_subject_sensitive():
    a = domain.fingerprint("SQL01", "AD-002", "CN=svc_sql")
    assert a == domain.fingerprint("SQL01", "AD-002", "CN=svc_sql")
    assert a != domain.fingerprint("SQL01", "AD-002", "CN=svc_backup")
    assert len(a) == 64


@pytest.mark.parametrize("previous,status,expected", [
    (None, "FAIL", "open"),
    (None, "PASS", "resolved"),
    ("resolved", "FAIL", "open"),
    ("resolved", "WARNING", "open"),
    ("open", "PASS", "resolved"),
    ("risk_accepted", "FAIL", "risk_accepted"),
    ("false_positive", "FAIL", "false_positive"),
    ("in_remediation", "FAIL", "in_remediation"),
    ("acknowledged", "INFO", "acknowledged"),
])
def test_lifecycle_after_observation(previous, status, expected):
    assert domain.lifecycle_after_observation(previous, status) == expected


@pytest.mark.parametrize("current,target", [("open", "acknowledged"), ("acknowledged", "in_remediation"),
                                            ("in_remediation", "open"), ("resolved", "open"),
                                            ("risk_accepted", "open"), ("open", "false_positive")])
def test_allowed_triage_transitions(current, target):
    domain.check_triage_transition(current, target)


@pytest.mark.parametrize("current,target", [("open", "open"), ("resolved", "acknowledged"),
                                            ("false_positive", "resolved"), ("open", "risk_accepted"),
                                            ("in_remediation", "resolved")])
def test_rejected_triage_transitions(current, target):
    with pytest.raises(ValueError):
        domain.check_triage_transition(current, target)
