import copy
import importlib
import json
import socket
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
config = importlib.import_module("assessment_app.config")
winrm = importlib.import_module("assessment_app.collectors.winrm_posture")
win_host = importlib.import_module("assessment_app.controls.win_host")
net = importlib.import_module("assessment_app.controls.net")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)

MEMBER_SERVER = {
    "schema": "eeap.windows.posture/1",
    "host": {"computer_name": "APP01", "dns_domain": "corp.example", "domain_role": 3,
             "is_domain_controller": False, "os_caption": "Microsoft Windows Server 2022 Standard",
             "os_version": "10.0.20348", "os_build": "20348"},
    "ntlm": {"lm_compatibility_level": 5, "no_lm_hash": 1, "restrict_sending_ntlm": None,
             "restrict_receiving_ntlm": None, "ntlm_min_server_sec": 537395200},
    "ldap": None,
    "local_admins": [
        {"name": "APP01\\Administrator", "sid": "S-1-5-21-1-2-3-500", "object_class": "User", "source": "Local"},
        {"name": "CORP\\Domain Admins", "sid": "S-1-5-21-9-8-7-512", "object_class": "Group",
         "source": "ActiveDirectory"},
    ],
    "endpoint_protection": {
        "defender": {"service_enabled": True, "real_time_protection": True,
                     "signature_last_updated": "2026-10-11T22:00:00Z"},
        "services": [{"name": "WinDefend", "status": "Running"}],
    },
    "errors": [],
}

DOMAIN_CONTROLLER = {
    **copy.deepcopy(MEMBER_SERVER),
    "host": {**MEMBER_SERVER["host"], "computer_name": "DC01", "domain_role": 5, "is_domain_controller": True},
    "ldap": {"server_integrity": 1, "enforce_channel_binding": None},
    "local_admins": None,
}

TARGET = config.WinrmTarget(username="CORP\\svc-eeap", password="x", auth="kerberos", port=5986, use_tls=True,
                            ca_file=None, configuration_name="EEAP.Posture", timeout_seconds=5,
                            realm="corp.example", kdc=None)


def host(posture: dict | None, status: str = "ok") -> dict:
    probe = {"status": status, "hostname": "app01.corp.example"}
    if posture is not None:
        probe["posture"] = posture
    return {"ip": "10.0.0.30", "collected_at": NOW.isoformat(), "probes": {"windows": probe}}


def results(posture: dict, *, allowed: list[str] | None = None) -> dict[str, tuple[str, str, str | None]]:
    evaluation = net.evaluate({"hosts": [host(posture)]}, list(win_host.WINRM_CONTROLS), NOW,
                              local_admins_allowed=allowed)
    return {r.control_id: (r.subject_key, r.status, r.severity) for r in evaluation.observations}


def with_changes(base: dict, **sections) -> dict:
    data = copy.deepcopy(base)
    for section, values in sections.items():
        data[section] = {**(data.get(section) or {}), **values} if isinstance(values, dict) else values
    return data


def test_hardened_member_server_passes():
    found = results(MEMBER_SERVER)
    assert {c: (s, st) for c, (s, st, _) in found.items()} == {
        "WIN-003": ("ntlm", "PASS"), "WIN-007": ("local-administrators", "PASS"),
        "WIN-009": ("endpoint-protection", "PASS")}


@pytest.mark.parametrize(("ntlm", "status", "severity"), [
    ({"lm_compatibility_level": 2}, "FAIL", "High"),
    ({"lm_compatibility_level": 5, "no_lm_hash": 0}, "FAIL", "High"),
    ({"lm_compatibility_level": None}, "WARNING", "Medium"),
    ({"lm_compatibility_level": 4}, "WARNING", "Medium"),
])
def test_ntlm_levels(ntlm, status, severity):
    _, found_status, found_severity = results(with_changes(MEMBER_SERVER, ntlm=ntlm))["WIN-003"]
    assert (found_status, found_severity) == (status, severity)


def test_domain_controller_ldap_controls():
    found = results(DOMAIN_CONTROLLER)
    assert found["WIN-004"] == ("ldap-signing", "FAIL", "High")
    assert found["WIN-005"] == ("ldap-channel-binding", "FAIL", "Medium")
    assert "WIN-007" not in found
    hardened = results(with_changes(DOMAIN_CONTROLLER, ldap={"server_integrity": 2, "enforce_channel_binding": 1}))
    assert hardened["WIN-004"][1] == "PASS" and hardened["WIN-005"][1] == "WARNING"
    assert results(with_changes(DOMAIN_CONTROLLER, ldap={"enforce_channel_binding": 2}))["WIN-005"][1] == "PASS"


def test_ldap_controls_skip_member_servers():
    found = results(MEMBER_SERVER)
    assert "WIN-004" not in found and "WIN-005" not in found


def test_unexpected_local_admins_and_allowlist():
    extra = {"name": "CORP\\helpdesk-ops", "sid": "S-1-5-21-9-8-7-4410", "object_class": "Group",
             "source": "ActiveDirectory"}
    posture = with_changes(MEMBER_SERVER, local_admins=[*MEMBER_SERVER["local_admins"], extra])
    assert results(posture)["WIN-007"] == ("local-administrators", "WARNING", "Medium")
    assert results(posture, allowed=["corp\\helpdesk-*"])["WIN-007"][1] == "PASS"
    assert results(posture, allowed=["S-1-5-21-9-8-7-4410"])["WIN-007"][1] == "PASS"


def test_endpoint_protection():
    disabled = with_changes(MEMBER_SERVER, endpoint_protection={
        "defender": {"service_enabled": True, "real_time_protection": False}, "services": []})
    assert results(disabled)["WIN-009"] == ("endpoint-protection", "FAIL", "High")
    stale = with_changes(MEMBER_SERVER, endpoint_protection={
        "defender": {**MEMBER_SERVER["endpoint_protection"]["defender"],
                     "signature_last_updated": "2026-09-20T00:00:00Z"},
        "services": [{"name": "WinDefend", "status": "Running"}]})
    assert results(stale)["WIN-009"] == ("endpoint-protection", "WARNING", "Medium")
    edr = with_changes(disabled, endpoint_protection={
        "defender": {"service_enabled": False}, "services": [{"name": "CSFalconService", "status": "Running"}]})
    assert results(edr)["WIN-009"][1] == "PASS"


def test_failed_collection_leaves_controls_unassessed():
    failed = {"ip": "10.0.0.31", "collected_at": NOW.isoformat(),
              "probes": {"windows": {"status": "error", "stage": "auth", "error": "denied"}}}
    absent = {"ip": "10.0.0.32", "collected_at": NOW.isoformat(), "probes": {}}
    evaluation = net.evaluate({"hosts": [failed, absent]}, list(win_host.WINRM_CONTROLS), NOW)
    assert evaluation.observations == []
    assert evaluation.unassessed == {"10.0.0.31": list(win_host.WINRM_CONTROLS),
                                     "10.0.0.32": list(win_host.WINRM_CONTROLS)}
    assert net.evaluate({"hosts": [host(MEMBER_SERVER)]}, list(win_host.WINRM_CONTROLS), NOW).unassessed == {}


def test_asset_details_from_posture():
    assert win_host.asset_details(host(DOMAIN_CONTROLLER)) == {
        "hostname": "DC01", "fqdn": "app01.corp.example", "os_family": "Windows",
        "os_version": "Microsoft Windows Server 2022 Standard 20348", "domain": "corp.example",
        "asset_type": "DomainController"}
    assert win_host.asset_details(host(None, status="error")) == {}
    asset = net.discovered_assets([host(MEMBER_SERVER)])[0]
    assert "winrm:assessed" in asset["tags"]


def test_parse_posture():
    assert winrm.parse_posture(["noise", json.dumps(MEMBER_SERVER)])["host"]["computer_name"] == "APP01"
    for output in ([], ["not json"], [json.dumps({"schema": "other"})]):
        with pytest.raises(winrm.WinrmError) as exc:
            winrm.parse_posture(output)
        assert exc.value.stage == "parse"


def test_krb5_config():
    text = winrm.krb5_config("corp.example", "dc01.corp.example")
    assert "default_realm = CORP.EXAMPLE" in text and "kdc = dc01.corp.example" in text
    assert "[realms]" not in winrm.krb5_config("corp.example", None)


def test_collect_host_outcomes(monkeypatch):
    monkeypatch.setattr(winrm, "resolve_hostname", lambda ip: None)
    assert winrm.collect_host("10.0.0.30", TARGET, invoke=lambda *_: MEMBER_SERVER)["stage"] == "dns"

    monkeypatch.setattr(winrm, "resolve_hostname", lambda ip: "app01.corp.example")
    seen = []

    def invoke(server, target):
        seen.append(server)
        return MEMBER_SERVER

    assert winrm.collect_host("10.0.0.30", TARGET, invoke=invoke) == {
        "status": "ok", "hostname": "app01.corp.example", "posture": MEMBER_SERVER}
    assert seen == ["app01.corp.example"]

    def denied(server, target):
        raise winrm.WinrmError("auth", "access denied")

    assert winrm.collect_host("10.0.0.30", TARGET, invoke=denied)["stage"] == "auth"

    def broken(server, target):
        raise RuntimeError("boom")

    assert winrm.collect_host("10.0.0.30", TARGET, invoke=broken)["stage"] == "unexpected"


def test_collect_hosts_tags_collector(monkeypatch, tmp_path):
    monkeypatch.setattr(winrm, "KRB5_CONFIG_PATH", str(tmp_path / "krb5.conf"))
    monkeypatch.delenv("KRB5_CONFIG", raising=False)
    monkeypatch.setattr(winrm, "resolve_hostname", lambda ip: f"host-{ip}")
    collected = winrm.collect_hosts(["10.0.0.30", "10.0.0.31"], TARGET, concurrency=2,
                                    invoke=lambda *_: MEMBER_SERVER)
    assert {ip: (r["collector"], r["status"]) for ip, r in collected.items()} == {
        "10.0.0.30": ("win.winrm_posture", "ok"), "10.0.0.31": ("win.winrm_posture", "ok")}
    assert "CORP.EXAMPLE" in (tmp_path / "krb5.conf").read_text()


class _RejectingWsman(BaseHTTPRequestHandler):
    """WinRM listener that rejects every authentication attempt."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Negotiate")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def ntlm_target(port: int) -> object:
    return config.WinrmTarget(username="svc-eeap", password="wrong", auth="ntlm", port=port, use_tls=False,
                              ca_file=None, configuration_name="EEAP.Posture", timeout_seconds=3,
                              realm=None, kdc=None)


def test_invoke_maps_rejected_authentication_against_fake_listener():
    pytest.importorskip("pypsrp")
    server = HTTPServer(("127.0.0.1", 0), _RejectingWsman)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with pytest.raises(winrm.WinrmError) as exc:
            winrm._invoke("127.0.0.1", ntlm_target(server.server_address[1]))
    finally:
        server.shutdown()
        server.server_close()
    assert exc.value.stage == "auth"


def test_invoke_maps_closed_port_to_connect():
    pytest.importorskip("pypsrp")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(winrm.WinrmError) as exc:
        winrm._invoke("127.0.0.1", ntlm_target(port))
    assert exc.value.stage == "connect"


def test_winrm_target_settings(tmp_path):
    secret = tmp_path / "winrm_password"
    secret.write_text("s3cret\n")
    settings = config.AssessmentSettings(winrm_username="CORP\\svc-eeap", winrm_password_file=str(secret),
                                         winrm_auth="Kerberos", winrm_realm="corp.example",
                                         win_local_admins_allowed=" CORP\\helpdesk-* , S-1-5-21-1 ")
    target = settings.winrm_target()
    assert (target.auth, target.password, target.port, target.use_tls) == ("kerberos", "s3cret", 5986, True)
    assert settings.local_admins_allowed() == ["CORP\\helpdesk-*", "S-1-5-21-1"]
    assert config.AssessmentSettings(winrm_username="").winrm_target() is None
    with pytest.raises(ValueError):
        config.AssessmentSettings(winrm_username="u", winrm_password_file=str(secret),
                                  winrm_auth="basic").winrm_target()
