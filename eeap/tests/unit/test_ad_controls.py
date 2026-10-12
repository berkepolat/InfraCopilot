import importlib
from datetime import UTC, datetime, timedelta

import pytest

from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
ad = importlib.import_module("assessment_app.controls.ad")
collector = importlib.import_module("assessment_app.collectors.ad_ldap")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
BASE = "DC=lab,DC=eeap,DC=local"
DOMAIN_SID = "S-1-5-21-1-2-3"


def _ago(days: int) -> str:
    return (NOW - timedelta(days=days)).isoformat()


def account(sam: str, uac: int = 0x200, *, spns=(), delegate_to=(), rbcd=False, pwd_days=10, enc=None,
            admin_count=0, ou="CN=Users") -> dict:
    return {"dn": f"CN={sam},{ou},{BASE}", "sam": sam, "sid": f"{DOMAIN_SID}-{abs(hash(sam)) % 9000 + 1000}",
            "uac": uac, "enabled": not uac & 0x2, "spns": list(spns), "pwd_last_set": _ago(pwd_days),
            "admin_count": admin_count, "encryption_types": enc, "delegate_to": list(delegate_to),
            "rbcd_configured": rbcd, "last_logon": None, "primary_group_id": 513}


def computer(name: str, os_name: str | None = "Windows Server 2022 Standard", uac: int = 0x1000, *, dc=False,
             laps=False, **kwargs) -> dict:
    base = account(f"{name}$", uac | (0x2000 if dc else 0), ou="CN=Computers", **kwargs)
    base["dn"] = f"CN={name},{'OU=Domain Controllers' if dc else 'CN=Computers'},{BASE}"
    return {**base, "name": name, "dns_host_name": f"{name.lower()}.lab.eeap.local", "os": os_name,
            "os_version": None, "is_dc": dc, "laps_legacy_managed": False, "laps_windows_managed": laps,
            "primary_group_id": 516 if dc else 515}


def member(acc: dict, kind: str = "user") -> dict:
    return {"dn": acc["dn"], "sam": acc["sam"], "sid": acc["sid"], "kind": kind, "enabled": acc["enabled"]}


def lab_snapshot(**overrides) -> dict:
    admins = [account(n) for n in ("alice", "bob", "carol", "dave", "erin")]
    frank = account("frank", 0x202)
    helpdesk = account("helpdesk1")
    svc_sql = account("svc_sql", spns=["MSSQLSvc/sql01.lab.eeap.local:1433"])
    users = admins + [frank, helpdesk, svc_sql,
                      account("krbtgt", 0x202, spns=["kadmin/changepw"]),
                      account("svc_backup", 0x200 | 0x10000, spns=["HOST/backup01.lab.eeap.local"], enc=0x18),
                      account("svc_old", spns=["HTTP/old"], pwd_days=800, enc=0x1C),
                      account("svc_web", 0x200 | 0x1000000, spns=["HTTP/intranet.lab.eeap.local"], enc=0x18,
                              delegate_to=["cifs/dc1.lab.eeap.local"]),
                      account("legacy_app", 0x200 | 0x400000),
                      account("old_preauth", 0x202 | 0x400000)]
    computers = [computer("DC1", "Windows Server 2022 Standard", dc=True, uac=0x80000),
                 computer("APP01", uac=0x1000 | 0x80000),
                 computer("SRV-LEGACY", "Windows Server 2008 R2 Standard"),
                 computer("SRV2016", "Windows Server 2016 Standard"),
                 computer("WS-1002", "Windows 11 Enterprise", rbcd=True, laps=True),
                 computer("FS01", delegate_to=["cifs/fs02.lab.eeap.local"])]
    snapshot = {
        "collector": "eeap-ad-ldap/1.0", "collected_at": NOW.isoformat(), "server": "dc1.lab.eeap.local",
        "domain": {"dn": BASE, "dns_name": "lab.eeap.local", "sid": DOMAIN_SID, "functional_level": 7,
                   "policy": {"min_password_length": 7, "password_history_length": 5, "complexity_enabled": False,
                              "reversible_encryption": False, "max_password_age_days": 0.0,
                              "min_password_age_days": 0.0, "lockout_threshold": 0, "lockout_duration_minutes": 30}},
        "users": users,
        "computers": computers,
        "privileged_groups": [
            {"sid": f"{DOMAIN_SID}-512", "name": "Domain Admins", "dn": f"CN=Domain Admins,CN=Users,{BASE}",
             "members": [member(a) for a in admins + [frank, svc_sql]]},
            {"sid": f"{DOMAIN_SID}-518", "name": "Schema Admins", "dn": f"CN=Schema Admins,CN=Users,{BASE}",
             "members": []},
            {"sid": "S-1-5-32-548", "name": "Account Operators", "dn": f"CN=Account Operators,CN=Builtin,{BASE}",
             "members": [member(helpdesk)]},
        ],
        "laps_schema": {"legacy": False, "windows": False},
    }
    snapshot.update(overrides)
    return snapshot


def run(snapshot=None, controls=None):
    return ad.evaluate(snapshot or lab_snapshot(), controls, NOW)


def by_control(evaluation, control_id):
    return [o for o in evaluation.observations if o.control_id == control_id]


# ------------------------------------------------------------------------------------------- collector guardrails

def test_allowlist_excludes_secret_attributes():
    assert not collector.ALLOWED_ATTRIBUTES & collector.DENIED_ATTRIBUTES
    for secret in ("unicodePwd", "ms-Mcs-AdmPwd", "msLAPS-Password", "msDS-ManagedPassword", "*"):
        with pytest.raises(collector.AdCollectionError):
            collector.check_attributes(["sAMAccountName", secret])
    with pytest.raises(collector.AdCollectionError):
        collector.check_attributes(["description"])  # not on the allowlist either
    assert collector.check_attributes(collector.COMPUTER_ATTRIBUTES) == list(collector.COMPUTER_ATTRIBUTES)


def test_laps_expiry_attributes_allowed_but_not_password_values():
    allowed = collector.ALLOWED_ATTRIBUTES
    assert "ms-mcs-admpwdexpirationtime" in allowed and "ms-mcs-admpwd" not in allowed
    assert "mslaps-passwordexpirationtime" in allowed and "mslaps-password" not in allowed


def test_plaintext_ldap_is_refused():
    target = collector.AdTarget("ldap://dc1.lab.eeap.local", None, "reader", "x", None, 5, 100)
    with pytest.raises(collector.AdCollectionError, match="ldaps"):
        collector.connect(target)


def test_value_parsing():
    sid = bytes([1, 4, 0, 0, 0, 0, 0, 5]) + (21).to_bytes(4, "little") + (1).to_bytes(4, "little") \
        + (2).to_bytes(4, "little") + (512).to_bytes(4, "little")
    assert collector.sid_to_str(sid) == "S-1-5-21-1-2-512"
    assert collector.filetime_to_iso(0) is None and collector.filetime_to_iso(0x7FFFFFFFFFFFFFFF) is None
    assert collector.filetime_to_iso(116444736000000000) == "1970-01-01T00:00:00+00:00"
    assert collector.interval_days(-36288000000000) == 42.0
    assert collector.interval_days(-0x8000000000000000) == 0.0
    assert collector.dn_to_dns("CN=x,DC=Lab,DC=eeap,DC=local") == "Lab.eeap.local"


# ------------------------------------------------------------------------------------------- evaluators

def test_all_controls_evaluated_and_rows_are_valid():
    evaluation = run()
    assert evaluation.evaluated_controls == list(ad.AD_CONTROL_IDS)
    assert evaluation.domain_asset_id == "LAB.EEAP.LOCAL"
    fingerprints = [(o.asset_id, o.control_id, o.subject_key) for o in evaluation.observations]
    assert len(fingerprints) == len(set(fingerprints))
    assert all(o.source_tool == ad.SOURCE_TOOL and o.raw_data == {"domain": "lab.eeap.local"}
               for o in evaluation.observations)


def test_control_selection():
    evaluation = run(controls=["AD-001", "AD-009"])
    assert evaluation.evaluated_controls == ["AD-001", "AD-009"]
    assert {o.control_id for o in evaluation.observations} == {"AD-001", "AD-009"}


def test_ad001_weak_policy_fails_high():
    [row] = by_control(run(), "AD-001")
    assert row.status == "FAIL" and row.severity == "High"
    assert any("lockout is disabled" in i for i in row.evidence["issues"])


def test_ad001_baseline_policy_passes():
    snapshot = lab_snapshot()
    snapshot["domain"]["policy"].update(min_password_length=14, password_history_length=24,
                                        complexity_enabled=True, lockout_threshold=5)
    [row] = by_control(run(snapshot), "AD-001")
    assert row.status == "PASS"


def test_ad002_service_accounts():
    rows = {r.evidence["account"]: r for r in by_control(run(), "AD-002")}
    assert "krbtgt" not in rows
    assert rows["svc_sql"].status == "FAIL" and rows["svc_sql"].severity == "Critical"
    assert rows["svc_old"].status == "FAIL" and "800 days" in rows["svc_old"].evidence["summary"]
    assert rows["svc_backup"].status == "WARNING"
    assert "svc_web" not in rows  # AES enabled, fresh password, not privileged
    assert all(r.asset_id == "LAB.EEAP.LOCAL" for r in rows.values())


def test_ad003_preauth():
    rows = {r.evidence["account"]: r for r in by_control(run(), "AD-003")}
    assert rows["legacy_app"].status == "FAIL"
    assert rows["old_preauth"].status == "WARNING" and rows["old_preauth"].severity == "Low"


def test_ad004_unconstrained_excludes_domain_controllers():
    rows = by_control(run(), "AD-004")
    assert [(r.asset_id, r.status) for r in rows] == [("APP01", "FAIL")]


def test_ad005_constrained_delegation():
    rows = {r.evidence["account"]: r for r in by_control(run(), "AD-005")}
    assert rows["svc_web"].status == "FAIL" and rows["svc_web"].severity == "Critical"
    assert rows["svc_web"].evidence["protocol_transition"] is True
    assert rows["FS01$"].status == "WARNING" and rows["FS01$"].asset_id == "FS01"


def test_ad006_rbcd():
    [row] = by_control(run(), "AD-006")
    assert row.asset_id == "WS-1002" and row.status == "WARNING"


def test_ad007_privileged_groups():
    rows = {r.evidence["group"]: r for r in by_control(run(), "AD-007")}
    da = rows["Domain Admins"]
    assert da.status == "FAIL" and da.subject_key == f"{DOMAIN_SID}-512"
    assert "6 enabled members" in da.evidence["summary"]
    assert "svc_sql" in da.evidence["summary"] and da.evidence["disabled_members"] == ["frank"]
    assert rows["Account Operators"].status == "WARNING"
    assert "Schema Admins" not in rows  # empty group


def test_ad008_laps_schema_missing_is_one_domain_finding():
    [row] = by_control(run(), "AD-008")
    assert row.asset_id == "LAB.EEAP.LOCAL" and row.subject_key == "laps-schema" and row.status == "FAIL"


def test_ad008_per_computer_when_schema_present():
    rows = by_control(run(lab_snapshot(laps_schema={"legacy": False, "windows": True})), "AD-008")
    assert sorted(r.asset_id for r in rows) == ["APP01", "FS01", "SRV-LEGACY", "SRV2016"]  # DC1 excluded, WS has LAPS


def test_ad009_end_of_support():
    rows = {r.asset_id: r for r in by_control(run(), "AD-009")}
    assert rows["SRV-LEGACY"].status == "FAIL"
    assert rows["SRV2016"].status == "WARNING"  # support ends within 180 days
    assert "WS-1002" not in rows and "APP01" not in rows


def test_ad010_tier0_discovery():
    rows = by_control(run(), "AD-010")
    assert all(r.status == "INFO" for r in rows)
    assert ("DC1", "domain-controller") in {(r.asset_id, r.subject_key) for r in rows}
    accounts = {r.evidence.get("account") for r in rows}
    assert {"alice", "svc_sql", "helpdesk1"} <= accounts and "frank" not in accounts


def test_discovered_assets():
    assets = {a["asset_id"]: a for a in run().assets}
    assert assets["LAB.EEAP.LOCAL"]["asset_type"] == "Identity" and "ad:domain" in assets["LAB.EEAP.LOCAL"]["tags"]
    assert assets["DC1"]["asset_type"] == "DomainController"
    assert assets["WS-1002"]["asset_type"] == "Workstation"
    assert assets["SRV-LEGACY"]["os_family"] == "Windows"
    assert {"id_type": "ad_dn", "value": f"CN=APP01,CN=Computers,{BASE}"} in assets["APP01"]["identifiers"]


def test_asset_id_sanitizing():
    assert ad.asset_id_for("ws 01") == "WS-01"
    assert ad.asset_id_for("_x") == "H_X"
