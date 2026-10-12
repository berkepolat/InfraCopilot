import asyncio
import copy
import importlib

import pytest
from conftest import load_service_package
from test_win_winrm import MEMBER_SERVER, NOW, host

load_service_package("assessment-service", "assessment_app")
win_host = importlib.import_module("assessment_app.controls.win_host")
net = importlib.import_module("assessment_app.controls.net")
vuln_feeds = importlib.import_module("assessment_app.vuln_feeds")
findings_repo = importlib.import_module("assessment_app.findings_repo")

CUMULATIVE = {"title": "2026-10 Cumulative Update for Microsoft server operating system version 21H2 (KB5070000)",
              "kbs": ["KB5070000"], "severity": "Critical", "cves": ["CVE-2026-1001", "CVE-2026-1002"],
              "categories": ["Security Updates"], "released": "2026-10-13T17:00:00Z", "is_downloaded": True}
DOTNET = {"title": "Security Update for .NET Framework (KB5070100)", "kbs": "KB5070100", "severity": "Moderate",
          "cves": "CVE-2026-2001", "categories": "Security Updates", "released": None, "is_downloaded": False}
DEFINITIONS = {"title": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602",
               "kbs": ["KB2267602"], "severity": None, "cves": [], "categories": ["Definition Updates"]}
DRIVER = {"title": "Contoso - Display - 31.0.1", "kbs": [], "severity": None, "cves": [], "categories": ["Drivers"]}


def posture(*, host_changes: dict | None = None, **updates) -> dict:
    data = copy.deepcopy(MEMBER_SERVER)
    data["host"].update(host_changes or {})
    data["updates"].update(copy.deepcopy(updates))
    return data


def rows(data: dict, controls=("WIN-010", "WIN-011", "WIN-012")) -> list:
    return net.evaluate({"hosts": [host(data)]}, list(controls), NOW).observations


def by_subject(data: dict, control: str) -> dict:
    return {r.subject_key: r for r in rows(data, (control,))}


def test_missing_security_updates_become_findings():
    found = by_subject(posture(pending=[CUMULATIVE, DOTNET, DEFINITIONS, DRIVER]), "WIN-010")
    assert set(found) == {"kb:KB5070000", "kb:KB5070100", "wu-scan"}
    cumulative = found["kb:KB5070000"]
    assert (cumulative.status, cumulative.severity) == ("FAIL", "Critical")
    assert cumulative.evidence["msrc_severity"] == "Critical" and cumulative.evidence["cve_count"] == 2
    assert "missing security update KB5070000" in cumulative.evidence["summary"]
    # Single values from PowerShell are normalised to lists.
    dotnet = found["kb:KB5070100"]
    assert (dotnet.severity, dotnet.evidence["kbs"], dotnet.evidence["cves"]) == ("Medium", ["KB5070100"],
                                                                                 ["CVE-2026-2001"])
    assert found["wu-scan"].status == "PASS"


def test_no_missing_updates_passes_and_stale_scan_warns():
    found = by_subject(posture(pending=[DEFINITIONS], last_search_success="2026-08-01T00:00:00Z"), "WIN-010")
    assert found["updates"].status == "PASS"
    assert (found["wu-scan"].status, found["wu-scan"].severity) == ("WARNING", "Low")
    assert "72 days ago" in found["wu-scan"].evidence["summary"]
    never = by_subject(posture(last_search_success=None), "WIN-010")["wu-scan"]
    assert never.status == "WARNING" and "never" in never.evidence["summary"]


def test_update_without_kb_gets_stable_subject():
    update = {**CUMULATIVE, "kbs": [], "severity": None}
    first = [s for s in by_subject(posture(pending=[update]), "WIN-010") if s.startswith("update:")]
    second = [s for s in by_subject(posture(pending=[copy.deepcopy(update)]), "WIN-010") if s.startswith("update:")]
    assert first == second and len(first) == 1
    assert by_subject(posture(pending=[update]), "WIN-010")[first[0]].severity == "Medium"


def test_known_exploited_update_raises_severity_and_scoring_context():
    update = {**DOTNET, "known_exploited": ["CVE-2026-2001"], "ransomware": False, "epss": 0.4,
              "epss_percentile": 0.97, "exploitability": 1.0}
    data = posture(pending=[update])
    probe = host(data)
    probe["probes"]["windows"]["exploit_data"] = {"kev": {"as_of": "2026-10-10T00:00:00+00:00", "version": None}}
    found = {r.subject_key: r for r in net.evaluate({"hosts": [probe]}, ["WIN-010"], NOW).observations}
    row = found["kb:KB5070100"]
    assert (row.severity, row.evidence["msrc_severity"]) == ("High", "Moderate")
    assert "actively exploited (CISA KEV): CVE-2026-2001" in row.evidence["summary"]
    assert row.evidence["exploit_data"]["kev"]["as_of"].startswith("2026-10-10")
    assert findings_repo.exploit_context(row.evidence) == (1.0, True)


@pytest.mark.parametrize(("changes", "status", "severity"), [
    ({}, "PASS", None),
    ({"hotfixes": [], "last_install_success": "2026-09-01T00:00:00Z"}, "WARNING", "Medium"),
    ({"hotfixes": [], "last_install_success": "2026-07-01T00:00:00Z"}, "FAIL", "High"),
    ({"hotfixes": [], "last_install_success": None}, "WARNING", "Low"),
    ({"reboot_required": True}, "WARNING", "Medium"),
])
def test_patch_currency(changes, status, severity):
    (row,) = rows(posture(**changes), ("WIN-011",))
    assert (row.subject_key, row.status, row.severity) == ("patch-currency", status, severity)


def test_patch_currency_uses_newest_date_and_lists_recent_hotfixes():
    hotfixes = [{"id": "KB1", "installed_on": "2026-05-01T00:00:00Z"},
                {"id": "KB2", "installed_on": None},
                {"id": "KB3", "installed_on": "2026-10-01T00:00:00Z"}]
    (row,) = rows(posture(hotfixes=hotfixes, last_install_success=None), ("WIN-011",))
    assert row.status == "PASS" and row.evidence["last_update_installed"].startswith("2026-10-01")
    assert [h["id"] for h in row.evidence["recent_hotfixes"]][:2] == ["KB3", "KB1"]
    assert row.evidence["hotfix_count"] == 3


@pytest.mark.parametrize(("host_changes", "status", "product", "eol"), [
    ({}, "PASS", "Windows Server 2022", "2031-10-14"),
    ({"os_build": "9600", "os_caption": "Microsoft Windows Server 2012 R2 Standard"}, "FAIL",
     "Windows Server 2012 R2", "2023-10-10"),
    ({"os_build": "14393"}, "WARNING", "Windows Server 2016", "2027-01-12"),
    ({"os_build": "19045", "installation_type": "Client", "product_type": 1, "edition_id": "Professional"},
     "FAIL", "Windows 10 22H2", "2025-10-14"),
    ({"os_build": "22631", "installation_type": "Client", "product_type": 1, "edition_id": "Professional"},
     "FAIL", "Windows 11 23H2", "2025-11-11"),
    ({"os_build": "22631", "installation_type": "Client", "product_type": 1, "edition_id": "Enterprise"},
     "WARNING", "Windows 11 23H2", "2026-11-10"),
    ({"os_build": "26200", "installation_type": "Client", "product_type": 1, "edition_id": "Education"},
     "PASS", "Windows 11 25H2", "2028-10-10"),
    ({"os_build": "26100", "installation_type": "Client", "product_type": 1, "edition_id": "EnterpriseS"},
     "PASS", "Windows 11 24H2", "2029-10-09"),
    ({"os_build": "19044", "installation_type": "Client", "product_type": 1, "edition_id": "IoTEnterpriseS"},
     "PASS", "Windows 10 21H2", "2032-01-13"),
    ({"os_build": "26100", "installation_type": "Client", "product_type": 1, "edition_id": "ProfessionalEducation"},
     "WARNING", "Windows 11 24H2", "2026-10-13"),
])
def test_os_lifecycle(host_changes, status, product, eol):
    (row,) = rows(posture(host_changes=host_changes), ("WIN-012",))
    assert (row.status, row.evidence["product"], row.evidence["end_of_support"]) == (status, product, eol)


def test_os_lifecycle_without_installation_type_and_unknown_builds():
    legacy = {"installation_type": None, "product_type": None, "edition_id": None}
    (row,) = rows(posture(host_changes=legacy), ("WIN-012",))
    assert row.evidence["product"] == "Windows Server 2022"  # from the caption
    assert rows(posture(host_changes={"os_build": "27000"}), ("WIN-012",)) == []


def test_old_posture_module_leaves_update_controls_unassessed():
    old = copy.deepcopy(MEMBER_SERVER)
    del old["updates"]
    evaluation = net.evaluate({"hosts": [host(old)]}, ["WIN-010", "WIN-011", "WIN-012"], NOW)
    assert [r.control_id for r in evaluation.observations] == ["WIN-012"]
    assert evaluation.unassessed == {"10.0.0.30": ["WIN-010", "WIN-011"]}
    failed_search = posture(pending=None)
    evaluation = net.evaluate({"hosts": [host(failed_search)]}, ["WIN-010", "WIN-011"], NOW)
    assert evaluation.unassessed == {"10.0.0.30": ["WIN-010"]}
    assert {r.control_id for r in evaluation.observations} == {"WIN-011"}


def test_attach_update_exploit_data(monkeypatch):
    seen = []

    async def fake_attach(conn, results):
        seen.extend(results)
        for result in results:
            result["exploit_data"] = {"kev": {"as_of": "2026-10-10"}}
            for update in result["vulnerable"]:
                update.update({"known_exploited": ["CVE-2026-1001"], "exploitability": 1.0})

    monkeypatch.setattr(vuln_feeds, "attach_exploit_data", fake_attach)
    data = posture(pending=[copy.deepcopy(CUMULATIVE), copy.deepcopy(DEFINITIONS)])
    hosts = {"10.0.0.30": {"status": "ok", "posture": data},
             "10.0.0.31": {"status": "ok", "posture": posture(pending=[])},
             "10.0.0.32": {"status": "error", "stage": "auth"}}
    asyncio.run(vuln_feeds.attach_update_exploit_data(None, hosts))
    assert len(seen) == 1 and [u["kbs"] for u in seen[0]["vulnerable"]] == [["KB5070000"]]
    assert hosts["10.0.0.30"]["exploit_data"] == {"kev": {"as_of": "2026-10-10"}}
    assert data["updates"]["pending"][0]["exploitability"] == 1.0
    assert "exploitability" not in data["updates"]["pending"][1]
    assert "exploit_data" not in hosts["10.0.0.31"]


def test_edition_classes():
    assert [win_host.edition_class(e) for e in ("Professional", "Core", "Enterprise", "EnterpriseN", "Education",
                                                 "EnterpriseS", "IoTEnterpriseS", "IoTEnterprise", None)] == [
        "consumer", "consumer", "enterprise", "enterprise", "enterprise", "ltsc", "iot_ltsc", "enterprise",
        "consumer"]
