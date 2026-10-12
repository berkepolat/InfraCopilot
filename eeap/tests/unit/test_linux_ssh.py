import copy
import importlib
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
config = importlib.import_module("assessment_app.config")
ssh = importlib.import_module("assessment_app.collectors.ssh_posture")
linux_host = importlib.import_module("assessment_app.controls.linux_host")
net = importlib.import_module("assessment_app.controls.net")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
POSTURE_SCRIPT = Path(__file__).resolve().parents[2] / "infrastructure" / "linux" / "eeap-posture.sh"

HARDENED_OUTPUT = "\n".join("\t".join(r) for r in [
    ("schema", "version", "eeap.linux.posture/1"),
    ("host", "hostname", "app01"), ("host", "fqdn", "app01.corp.example"), ("host", "os_id", "debian"),
    ("host", "os_version_id", "12"), ("host", "os_pretty", "Debian GNU/Linux 12 (bookworm)"),
    ("sshd", "available", "1"), ("sshd", "permitrootlogin", "without-password"),
    ("sshd", "passwordauthentication", "no"), ("sshd", "permitemptypasswords", "no"),
    ("sshd", "kbdinteractiveauthentication", "no"), ("sshd", "maxauthtries", "4"),
    ("sshd", "ciphers", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr"),
    ("sshd", "macs", "hmac-sha2-256-etm@openssh.com,hmac-sha2-512"),
    ("sshd", "kexalgorithms", "sntrup761x25519-sha512@openssh.com,curve25519-sha256"),
    ("updates", "manager", "apt"), ("updates", "pending", "3"), ("updates", "security", "0"),
    ("updates", "metadata_age_days", "1"), ("updates", "reboot_required", "0"),
    ("accounts", "shadow_readable", "1"), ("accounts", "pass_max_days", "365"),
    ("sudo", "group_member", "sudo:alice"),
    ("firewall", "nft_input_chains", "1"), ("firewall", "nft_input_rules", "4"),
    ("firewall", "nft_input_policy", "drop"),
    ("sysctl", "kernel.randomize_va_space", "2"), ("sysctl", "net.ipv4.ip_forward", "0"),
    ("sysctl", "net.ipv4.conf.all.send_redirects", "0"), ("sysctl", "kernel.kptr_restrict", "1"),
    ("files", "mode", "/etc/passwd 644 root root"), ("files", "mode", "/etc/shadow 640 root shadow"),
    ("files", "mode", "/etc/sudoers 440 root root"),
    ("schema", "complete", "1"),
])
HARDENED = ssh.parse_posture(HARDENED_OUTPUT)

TARGET = config.LinuxSshTarget(username="eeap-scan", private_key="unused", port=22, known_hosts_file=None,
                               timeout_seconds=5)


def changed(**sections) -> dict:
    data = copy.deepcopy(HARDENED)
    for section, values in sections.items():
        data[section] = {**data.get(section, {}), **values}
    return data


def results(posture: dict, *, allowed: list[str] | None = None) -> dict[str, tuple[str, str, str | None]]:
    host = {"ip": "10.0.0.40", "probes": {"linux": {"status": "ok", "posture": posture}}}
    evaluation = net.evaluate({"hosts": [host]}, list(linux_host.LINUX_CONTROLS), NOW, linux_admins_allowed=allowed)
    return {r.control_id: (r.subject_key, r.status, r.severity) for r in evaluation.observations}


def test_parse_posture_lists_and_completeness():
    assert HARDENED["sudo"]["group_member"] == ["sudo:alice"]
    assert len(HARDENED["files"]["mode"]) == 3
    with pytest.raises(ssh.SshError) as exc:
        ssh.parse_posture(HARDENED_OUTPUT.replace("schema\tcomplete\t1", ""))
    assert exc.value.stage == "parse"
    with pytest.raises(ssh.SshError):
        ssh.parse_posture("schema\tversion\tother/1\nschema\tcomplete\t1")


def test_hardened_host_passes_with_allowlisted_admin():
    found = results(HARDENED, allowed=["ali*"])
    assert {c: s for c, (_, s, _) in found.items()} == {f"LIN-00{n}": "PASS" for n in range(1, 9)}
    assert found["LIN-001"][0] == "sshd" and found["LIN-008"][0] == "os-lifecycle"


def test_unlisted_admin_is_a_warning():
    assert results(HARDENED)["LIN-003"] == ("privileged-access", "WARNING", "Medium")


def test_sshd_findings():
    weak = changed(sshd={"permitrootlogin": "yes", "passwordauthentication": "yes",
                         "ciphers": "aes128-ctr,aes128-cbc", "kexalgorithms": "diffie-hellman-group14-sha1"})
    assert results(weak, allowed=["*"])["LIN-001"] == ("sshd", "FAIL", "High")
    passwords = changed(sshd={"passwordauthentication": "yes"})
    assert results(passwords, allowed=["*"])["LIN-001"] == ("sshd", "WARNING", "Medium")
    assert "LIN-001" not in results(changed(sshd={"available": "0"}), allowed=["*"])


def test_update_findings():
    assert results(changed(updates={"security": "2"}), allowed=["*"])["LIN-002"] == (
        "package-updates", "FAIL", "High")
    assert results(changed(updates={"reboot_required": "1"}), allowed=["*"])["LIN-002"][1:] == ("WARNING", "Medium")
    assert results(changed(updates={"metadata_age_days": "90"}), allowed=["*"])["LIN-002"][1:] == ("WARNING", "Low")
    apk = changed(updates={"manager": "apk", "pending": "5", "security": ""})
    assert results(apk, allowed=["*"])["LIN-002"][1:] == ("WARNING", "Medium")
    assert "LIN-002" not in results(changed(updates={"metadata_age_days": ""}), allowed=["*"])


def test_privileged_access_and_accounts():
    risky = changed(accounts={"uid0": ["toor"], "empty_password": ["svc"]},
                    sudo={"nopasswd": ["%wheel ALL=(ALL) NOPASSWD: ALL"]})
    found = results(risky, allowed=["*"])
    assert found["LIN-003"] == ("privileged-access", "FAIL", "High")
    assert found["LIN-005"] == ("local-accounts", "FAIL", "High")
    assert results(changed(accounts={"pass_max_days": "99999"}), allowed=["*"])["LIN-005"][1:] == ("WARNING", "Low")


def test_firewall_detection():
    open_host = copy.deepcopy(HARDENED)
    open_host["firewall"] = {"iptables_input_policy": "ACCEPT", "iptables_input_rules": "0"}
    assert results(open_host, allowed=["*"])["LIN-004"] == ("host-firewall", "FAIL", "Medium")
    open_host["firewall"] = {"ufw": "active"}
    assert results(open_host, allowed=["*"])["LIN-004"][1] == "PASS"


def test_kernel_and_file_permissions():
    kernel = changed(sysctl={"kernel.randomize_va_space": "0"})
    assert results(kernel, allowed=["*"])["LIN-006"] == ("kernel-hardening", "WARNING", "Medium")
    shadow = changed(files={"mode": ["/etc/shadow 644 root root"]})
    assert results(shadow, allowed=["*"])["LIN-007"] == ("file-permissions", "FAIL", "High")
    writable = changed(files={"world_writable": ["/etc/app.conf"]})
    assert results(writable, allowed=["*"])["LIN-007"] == ("file-permissions", "FAIL", "Medium")


@pytest.mark.parametrize(("os_id", "version", "pretty", "status"), [
    ("alpine", "3.20.10", "Alpine Linux v3.20", "FAIL"),
    ("debian", "11", "Debian 11", "FAIL"),
    ("alpine", "3.21.4", "Alpine Linux v3.21", "WARNING"),
    ("ubuntu", "22.04", "Ubuntu 22.04.5 LTS", "PASS"),
    ("rocky", "9.3", "Rocky Linux 9.3", "PASS"),
    ("centos", "8", "CentOS Stream 8", "FAIL"),
    ("amzn", "2", "Amazon Linux 2", "FAIL"),
])
def test_os_lifecycle(os_id, version, pretty, status):
    posture = changed(host={"os_id": os_id, "os_version_id": version, "os_pretty": pretty})
    assert results(posture, allowed=["*"])["LIN-008"][1] == status


def test_unknown_release_is_not_assessed():
    posture = changed(host={"os_id": "gentoo", "os_version_id": "2.15"})
    assert "LIN-008" not in results(posture, allowed=["*"])


def test_failed_or_skipped_collection_leaves_controls_unassessed():
    failed = {"ip": "10.0.0.41", "probes": {"linux": {"status": "error", "stage": "hostkey", "error": "x"}}}
    skipped = {"ip": "10.0.0.42", "probes": {}}
    evaluation = net.evaluate({"hosts": [failed, skipped]}, list(linux_host.LINUX_CONTROLS), NOW)
    assert evaluation.observations == []
    assert evaluation.unassessed == {ip: list(linux_host.LINUX_CONTROLS) for ip in ("10.0.0.41", "10.0.0.42")}


def test_asset_details_and_tags():
    host = {"ip": "10.0.0.40", "probes": {"linux": {"status": "ok", "posture": HARDENED}}}
    asset = net.discovered_assets([host])[0]
    assert (asset["hostname"], asset["fqdn"], asset["os_family"], asset["asset_type"]) == (
        "app01", "app01.corp.example", "Linux", "Server")
    assert asset["tags"] == ["net:scanned", "ssh:assessed"]


def test_collect_hosts_outcomes():
    def invoke(ip, target, pkey, pinned):
        if ip == "10.0.0.41":
            raise ssh.SshError("hostkey", "host key changed")
        return HARDENED, {"key_type": "ssh-ed25519", "fingerprint": "SHA256:x", "trust": "first-use"}

    collected = ssh.collect_hosts(["10.0.0.40", "10.0.0.41"], TARGET, {}, invoke=invoke, load_key=lambda _: object())
    assert collected["10.0.0.40"]["status"] == "ok" and collected["10.0.0.40"]["collector"] == "linux.ssh_posture"
    assert (collected["10.0.0.41"]["status"], collected["10.0.0.41"]["stage"]) == ("error", "hostkey")

    def bad_key(_):
        raise ssh.SshError("config", "bad key")

    assert ssh.collect_hosts(["10.0.0.40"], TARGET, {}, load_key=bad_key)["10.0.0.40"]["stage"] == "config"
    assert ssh.collect_hosts([], TARGET, {}) == {}


def test_expected_keys_from_pin_and_known_hosts(tmp_path):
    paramiko = pytest.importorskip("paramiko")
    key = paramiko.Ed25519Key.from_private_key(__import__("io").StringIO(_ed25519_private_key()))
    pinned = {"key_type": "ssh-ed25519", "fingerprint": ssh.fingerprint(key)}
    assert ssh._expected_keys("10.0.0.40", TARGET, pinned) == ({"ssh-ed25519": pinned["fingerprint"]}, "pinned")
    assert ssh._expected_keys("10.0.0.40", TARGET, None) == (None, "first-use")
    known = tmp_path / "known_hosts"
    known.write_text(f"10.0.0.40 ssh-ed25519 {key.get_base64()}\n")
    strict = config.LinuxSshTarget(username="eeap-scan", private_key="", port=22, known_hosts_file=str(known),
                                   timeout_seconds=5)
    assert ssh._expected_keys("10.0.0.40", strict, None) == ({"ssh-ed25519": pinned["fingerprint"]}, "known_hosts")
    with pytest.raises(ssh.SshError) as exc:
        ssh._expected_keys("10.0.0.99", strict, None)
    assert exc.value.stage == "hostkey"


def _ed25519_private_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()


def test_load_private_key_accepts_openssh_ed25519():
    pytest.importorskip("paramiko")
    assert ssh.load_private_key(_ed25519_private_key()).get_name() == "ssh-ed25519"
    with pytest.raises(ssh.SshError):
        ssh.load_private_key("not a key")


def test_posture_script_is_read_only():
    script = POSTURE_SCRIPT.read_text()
    assert "apt-get -s " in script and " -C " in script
    for forbidden in (r"\brm\s", r"\bchmod\s", r"\bchown\s", r"\buseradd\b", r"\bsystemctl\s", r">\s*/(etc|var|usr)",
                      r"\b(apt-get|dnf|yum) (install|upgrade|update)\b", r"\bapk (add|upgrade|update)\b"):
        assert not re.search(forbidden, script), forbidden


def test_linux_settings(tmp_path):
    key = tmp_path / "linux_ssh_key"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
    settings = config.AssessmentSettings(linux_ssh_username="eeap-scan", linux_ssh_key_file=str(key),
                                         linux_admins_allowed=" alice , ops-* ")
    target = settings.linux_target()
    assert (target.username, target.port, target.known_hosts_file) == ("eeap-scan", 22, None)
    assert target.private_key.endswith("-----END OPENSSH PRIVATE KEY-----\n")
    assert settings.linux_admins() == ["alice", "ops-*"]
    assert config.AssessmentSettings(linux_ssh_username="").linux_target() is None
