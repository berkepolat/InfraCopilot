import importlib
import socket
import struct
import threading
from datetime import UTC, datetime

from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
smb = importlib.import_module("assessment_app.collectors.smb_negotiate")
net = importlib.import_module("assessment_app.controls.net")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def smb2_response(security_mode: int, dialect: int = 0x0302, status: int = 0) -> bytes:
    header = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, status, 0, 1, 1, 0, 0, 0, 0, 0) + b"\x00" * 16
    body = struct.pack("<HHH", 65, security_mode, dialect) + b"\x00" * 58
    return struct.pack(">I", len(header + body)) + header + body


def smb1_response(dialect_index: int, security_mode: int = 0x03) -> bytes:
    header = b"\xffSMB" + struct.pack("<BIBHH8sHHHHH", 0x72, 0, 0x98, 0xC001, 0, b"\x00" * 8, 0, 0, 0, 0, 0)
    body = bytes([17]) + struct.pack("<HB", dialect_index, security_mode) + b"\x00" * 31
    return struct.pack(">I", len(header + body)) + header + body


def test_negotiate_requests_are_well_formed():
    smb2 = smb.smb2_negotiate_request()
    assert struct.unpack(">I", smb2[:4])[0] == len(smb2) - 4
    assert smb2[4:8] == b"\xfeSMB" and smb2[4 + 64:4 + 66] == struct.pack("<H", 36)
    smb1 = smb.smb1_negotiate_request()
    assert smb1[4:9] == b"\xffSMB\x72" and smb1.endswith(b"NT LM 0.12\x00")


def test_parse_smb2_signing_modes():
    assert smb.parse_smb2_negotiate(smb2_response(0x03)) == {
        "dialect": "3.0.2", "signing_enabled": True, "signing_required": True}
    assert smb.parse_smb2_negotiate(smb2_response(0x01, 0x0210))["signing_required"] is False
    assert smb.parse_smb2_negotiate(smb2_response(0x01, status=0xC0000022)) == {"status": "0xc0000022"}
    assert smb.parse_smb2_negotiate(b"\x00\x00\x00\x04junk") is None


def test_parse_smb1_dialect_acceptance():
    assert smb.parse_smb1_negotiate(smb1_response(0, 0x03)) == {"accepted": True, "signing_required": False}
    assert smb.parse_smb1_negotiate(smb1_response(0, 0x0F))["signing_required"] is True
    assert smb.parse_smb1_negotiate(smb1_response(0xFFFF)) == {"accepted": False}


def test_probe_against_local_smb_responder():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]

    def serve():
        for reply in (smb2_response(0x01), None):  # SMB2 without required signing, then reset the SMB1 attempt
            conn, _ = server.accept()
            with conn:
                conn.recv(4096)
                if reply:
                    conn.sendall(reply)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    original = smb.SMB_PORT
    smb.SMB_PORT = port
    try:
        result = smb.probe("127.0.0.1", 2.0)
    finally:
        smb.SMB_PORT = original
        worker.join(2)
        server.close()
    assert result["open"] is True
    assert result["smb2"]["signing_required"] is False
    assert result["smb1"] == {"accepted": False}


def host(probes: dict) -> dict:
    return {"ip": "10.0.0.20", "collected_at": NOW.isoformat(), "probes": probes}


def rows(evaluation) -> set[tuple[str, str, str]]:
    return {(r.control_id, r.subject_key, r.status) for r in evaluation.observations}


def test_win_controls_from_network_observations():
    probes = {
        "smb_negotiate": {"open": True, "smb2": {"dialect": "2.1", "signing_enabled": True, "signing_required": False},
                          "smb1": {"accepted": True, "signing_required": False}},
        "ports": {"open": [{"port": 3389, "service": "rdp", "nla_required": False, "legacy_rdp_security": True},
                           {"port": 5985, "service": "winrm"}, {"port": 5986, "service": "winrm-https"}]},
    }
    evaluation = net.evaluate({"hosts": [host(probes)]}, list(net.WIN_NETWORK_CONTROLS), NOW)
    assert rows(evaluation) == {("WIN-001", "smb:445", "FAIL"), ("WIN-002", "smb:445", "FAIL"),
                                ("WIN-006", "tcp:3389", "FAIL"), ("WIN-008", "tcp:5985", "FAIL")}


def test_win_controls_pass_on_hardened_host():
    probes = {
        "smb_negotiate": {"open": True, "smb2": {"dialect": "3.0.2", "signing_enabled": True, "signing_required": True},
                          "smb1": {"accepted": False}},
        "ports": {"open": [{"port": 3389, "service": "rdp", "nla_required": True}, {"port": 5986, "service": "winrm-https"}]},
    }
    evaluation = net.evaluate({"hosts": [host(probes)]}, list(net.WIN_NETWORK_CONTROLS), NOW)
    assert rows(evaluation) == {("WIN-001", "smb:445", "PASS"), ("WIN-002", "smb:445", "PASS"),
                                ("WIN-006", "tcp:3389", "PASS"), ("WIN-008", "tcp:5985", "PASS")}


def test_win_controls_silent_when_services_absent():
    probes = {"smb_negotiate": {"open": False, "smb2": None, "smb1": None}, "ports": {"open": []}}
    evaluation = net.evaluate({"hosts": [host(probes)]}, list(net.WIN_NETWORK_CONTROLS), NOW)
    assert evaluation.observations == []
