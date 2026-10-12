import asyncio
import importlib
import socket
from datetime import UTC, datetime

import pytest
from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
port_scan = importlib.import_module("assessment_app.collectors.port_scan")
net = importlib.import_module("assessment_app.controls.net")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def test_parse_ports_ranges_and_excludes_common_ports():
    assert port_scan.parse_ports(None) == []
    assert port_scan.parse_ports(["8081", " 9001-9003 ", "22"]) == [8081, 9001, 9002, 9003]
    assert 22 in port_scan.scan_ports([]) and 8081 in port_scan.scan_ports([8081])


@pytest.mark.parametrize("spec", ["abc", "0", "70000", "10-5", "1-2000", "22;rm"])
def test_parse_ports_rejects_invalid_specs(spec):
    with pytest.raises(port_scan.PortSpecError):
        port_scan.parse_ports([spec])


def test_identify_banner_products():
    assert port_scan.identify_banner(22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n") == \
        {"service": "ssh", "product": "OpenSSH", "version": "9.6p1"}
    assert port_scan.identify_banner(21, b"220 (vsFTPd 3.0.5)\r\n")["product"] == "vsFTPd"
    assert port_scan.identify_banner(25, b"220 mail.corp.local ESMTP Postfix\r\n")["service"] == "smtp"
    assert port_scan.identify_banner(23, b"\xff\xfd\x18")["service"] == "telnet"
    assert port_scan.identify_banner(5900, b"RFB 003.008\n") == {"service": "vnc", "product": None,
                                                                   "version": "003.008"}
    mysql = b"\x4a\x00\x00\x00\x0a8.0.36-0ubuntu0\x00rest"
    assert port_scan.identify_banner(3306, mysql) == {"service": "mysql", "product": "MySQL", "version": "8.0.36"}
    assert port_scan.identify_banner(4444, b"") == {}


def test_identify_http_server_headers():
    response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n"
    assert port_scan.identify_http(80, response) == {"service": "http", "http_status": 200,
                                                     "http_server": "nginx/1.25.3", "product": "nginx",
                                                     "version": "1.25.3"}
    docker = b"HTTP/1.1 200 OK\r\nApi-Version: 1.45\r\nServer: Docker/26.1.0 (linux)\r\n\r\n"
    assert port_scan.identify_http(2375, docker)["service"] == "docker"
    winrm = b"HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n"
    assert port_scan.identify_http(5985, winrm)["service"] == "winrm"
    assert port_scan.identify_http(80, b"garbage") == {}


def _rdp_reply(kind: int, value: int) -> bytes:
    return bytes.fromhex("030000130ed00000123400") + bytes([kind, 0, 8, 0]) + value.to_bytes(4, "little")


def test_parse_rdp_negotiation():
    assert port_scan.parse_rdp_negotiation(_rdp_reply(0x02, 1))["nla_required"] is False
    assert port_scan.parse_rdp_negotiation(_rdp_reply(0x03, 5))["nla_required"] is True
    assert port_scan.parse_rdp_negotiation(_rdp_reply(0x03, 2))["legacy_rdp_security"] is True
    assert port_scan.parse_rdp_negotiation(b"") == {}


def _host(open_services: list[dict]) -> dict:
    return {"ip": "10.0.0.5", "collected_at": NOW.isoformat(),
            "probes": {"ports": {"ports_scanned": 60, "open": open_services}}}


def test_port_scan_controls_classify_exposures():
    services = [
        {"port": 22, "transport": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.6p1"},
        {"port": 3389, "transport": "tcp", "service": "rdp", "nla_required": False},
        {"port": 23, "transport": "tcp", "service": "telnet"},
        {"port": 6379, "transport": "tcp", "service": "redis"},
        {"port": 2375, "transport": "tcp", "service": "docker"},
        {"port": 6443, "transport": "tcp", "service": "kubernetes-api", "tls_version": "TLSv1.3"},
    ]
    evaluation = net.evaluate({"hosts": [_host(services)]}, list(net.PORT_SCAN_CONTROLS), NOW)
    rows = {(r.control_id, r.subject_key): (r.status, r.severity) for r in evaluation.observations}
    assert rows == {
        ("NET-006", "tcp:22"): ("WARNING", "Medium"),
        ("NET-006", "tcp:3389"): ("WARNING", "Medium"),
        ("WIN-006", "tcp:3389"): ("FAIL", "Medium"),
        ("NET-007", "tcp:23"): ("FAIL", "High"),
        ("NET-008", "tcp:6379"): ("WARNING", "Medium"),
        ("NET-009", "tcp:2375"): ("FAIL", "High"),
        ("NET-009", "tcp:6443"): ("WARNING", "Medium"),
    }


def test_port_scan_controls_pass_without_exposure():
    evaluation = net.evaluate({"hosts": [_host([{"port": 443, "transport": "tcp", "service": "https"}])]},
                              list(net.PORT_SCAN_CONTROLS), NOW)
    assert {(r.control_id, r.status, r.subject_key) for r in evaluation.observations} == {
        ("NET-006", "PASS", "remote-admin"), ("NET-007", "PASS", "cleartext"),
        ("NET-008", "PASS", "data-stores"), ("NET-009", "PASS", "control-planes")}


def test_scan_hosts_finds_local_listener_and_reads_banner():
    async def scenario():
        async def greet(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(greet, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        with socket.socket() as probe:  # a port that is very likely closed
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        async with server:
            return port, await port_scan.scan_hosts(["127.0.0.1"], [port, closed_port], timeout=1.0,
                                                    identify_timeout=2.0)

    port, hosts = asyncio.run(scenario())
    result = hosts["127.0.0.1"]
    assert result["ports_scanned"] == 2
    assert [s["port"] for s in result["open"]] == [port]
    assert result["open"][0]["service"] == "ssh" and result["open"][0]["product"] == "OpenSSH"


def test_scan_hosts_enforces_connection_budget():
    ips = [f"10.0.{i // 256}.{i % 256}" for i in range(1000)]
    with pytest.raises(port_scan.PortSpecError):
        asyncio.run(port_scan.scan_hosts(ips, list(range(1, 100))))
