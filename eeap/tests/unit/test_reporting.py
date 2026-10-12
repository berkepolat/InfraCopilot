import asyncio
import json

import httpx

from conftest import load_service_module

snap = load_service_module("reporting-service", "snapshot", "reporting_snapshot")
render = load_service_module("reporting-service", "render", "reporting_render")

URLS = {"ai": "http://ai", "assessment": "http://assessment"}
TOKENS = {"ai": "tok-ai", "assessment": "tok-as"}

SUMMARY = {"exposure_score": {"score": 90, "rating": "Critical"}, "active_scenarios": 1, "scoring_model": "v1",
           "open_by_rating": {"finding": {"Critical": 1, "High": 2}, "asset": {}}}
SCENARIO = {"scenario_id": "s1", "rule_id": "CORR-AD-001", "title": "Crackable <b>svc</b> to Tier 0",
            "summary": "x", "score": 93, "rating": "Critical", "first_detected_at": "2026-10-12T11:53:15+00:00",
            "stages": [{"name": "Crackable", "matched": True}, {"name": "Path", "matched": True}]}
ITEM = {"item_id": "i1", "control_id": "AD-002", "title": "Move service accounts to gMSA", "guidance": "g",
        "effort": "Medium", "expected_risk_reduction": 25, "priority": 1, "roadmap_phase": "Immediate",
        "status": "proposed", "open_findings": 3, "scenarios": [{"scenario_id": "s1", "title": "t"}],
        "techniques": [{"technique_id": "T1558.003", "name": "Kerberoasting"}]}
FINDING = {"finding_id": "f1", "asset_id": "LAB", "control_id": "AD-002", "control_name": "SPN accounts",
           "category": "Kerberos", "severity": "High", "status": "FAIL", "lifecycle_state": "open",
           "subject_key": "CN=svc_sql", "recommendation": "Use gMSA", "evidence": {"secret": "do-not-copy"},
           "first_seen_at": "2026-10-12T11:00:00+00:00", "last_seen_at": "2026-10-12T11:00:00+00:00"}


def transport(findings_status: int = 200, seen: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append((request.url.host, request.url.path, request.headers["authorization"],
                         dict(request.url.params)))
        path = request.url.path
        if path == "/findings":
            if findings_status != 200:
                return httpx.Response(findings_status, json={"detail": "missing permission findings:read"})
            if request.url.params["status"] == "WARNING":
                return httpx.Response(200, json={"items": [], "next_cursor": None})
            if "cursor" not in request.url.params:
                return httpx.Response(200, json={"items": [FINDING], "next_cursor": "c2"})
            return httpx.Response(200, json={"items": [{**FINDING, "finding_id": "f2",
                                                        "lifecycle_state": "resolved"}], "next_cursor": None})
        body = {"/risk/summary": SUMMARY, "/risk/scenarios": [SCENARIO], "/risk/remediation": {"items": [ITEM]},
                "/risk/mitre": {"techniques": [], "tactics": []}, "/risk/top-assets": {"items": []},
                "/risk/top-findings": {"items": [{"finding_id": "f1", "asset_id": "LAB", "hostname": "dc01",
                                                  "score": 88, "rating": "Critical"}]}}[path]
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


def collect(report_type, **kwargs):
    return asyncio.run(snap.collect(report_type, TOKENS, URLS, max_findings=100, timeout=5,
                                    transport=transport(**kwargs)))


def test_parse_delegation():
    assert snap.parse_delegation("ai=a.b.c, assessment=d.e.f") == {"ai": "a.b.c", "assessment": "d.e.f"}
    assert snap.parse_delegation(None) == {}
    assert snap.parse_delegation("garbage") == {}


def test_technical_snapshot_uses_each_upstream_token_and_strips_evidence():
    seen = []
    snapshot = asyncio.run(snap.collect("technical", TOKENS, URLS, max_findings=100, timeout=5,
                                        transport=transport(seen=seen)))
    assert {(host, auth) for host, _, auth, _ in seen} == {("ai", "Bearer tok-ai"), ("assessment", "Bearer tok-as")}
    findings = snapshot["data"]["findings"]
    assert [f["finding_id"] for f in findings] == ["f1"]  # resolved finding on page 2 is dropped
    assert "evidence" not in findings[0]
    assert snapshot["omitted"] == []


def test_missing_permission_omits_the_section():
    snapshot = collect("technical", findings_status=403)
    assert "findings" not in snapshot["data"]
    assert snapshot["omitted"] == ["findings (requires findings:read)"]


def test_upstream_failure_and_missing_token_raise():
    try:
        collect("technical", findings_status=500)
    except snap.SnapshotError:
        pass
    else:
        raise AssertionError("expected SnapshotError")
    try:
        asyncio.run(snap.collect("executive_summary", {}, URLS, max_findings=1, timeout=5, transport=transport()))
    except snap.SnapshotError as exc:
        assert "no delegated token" in str(exc)
    else:
        raise AssertionError("expected SnapshotError")


META = {"report_id": "r1", "title": "Exec <script>alert(1)</script>", "report_type": "executive_summary",
        "snapshot_at": "2026-10-12T12:00:00+00:00", "requested_by": "user:1", "organization": "Lab",
        "scoring_model": "v1", "template": "executive_summary v1"}


def test_every_report_type_renders_and_escapes_content():
    for report_type in snap.REPORT_TYPES:
        html = render.render_html(report_type, {**META, "report_type": report_type}, collect(report_type))
        assert "<script>" not in html and "&lt;script&gt;" in html
        assert "Overview" in html
    executive = render.render_html("executive_summary", META, collect("executive_summary"))
    assert "Move service accounts to gMSA" in executive and "Crackable &lt;b&gt;svc&lt;/b&gt; to Tier 0" in executive
    assert "2026-10-12 11:53 UTC" in executive


def test_technical_view_merges_scores_and_hostnames():
    view = render.build_view("technical", META, collect("technical"))
    assert view["findings"][0]["score"] == 88 and view["findings"][0]["hostname"] == "dc01"
    fallback = render.build_view("technical", META, collect("technical", findings_status=403))
    assert [f["finding_id"] for f in fallback["findings"]] == ["f1"]


def test_json_artifact_contains_metadata_and_data():
    payload = json.loads(render.render_json(META, collect("mitre_mapping")))
    assert payload["report"]["report_id"] == "r1"
    assert set(payload["data"]) == {"summary", "mitre", "remediation"}
