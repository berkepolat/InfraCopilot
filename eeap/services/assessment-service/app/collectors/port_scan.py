"""TCP port discovery and service identification for NET-006..NET-009 (ADR-0011).

Read-only: full TCP connects (no raw packets), then at most one standard protocol greeting per
open port to name the service: the server's own banner, an HTTP `HEAD /`, a TLS handshake (no
client certificate, certificate not trusted) or an RDP connection negotiation. No
authentication attempts, no credentials, no exploit payloads, no commands to data stores.
"""
from __future__ import annotations

import asyncio
import re
import ssl
import time
from datetime import UTC, datetime
from typing import Any

COLLECTOR_ID = "net.port_scan"
COLLECTOR_VERSION = "1.0"

# Curated enterprise exposure profile; every port used by NET-006..009 is part of it, so those
# findings are always re-evaluated (extra ports are only added on top).
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
    464: "kpasswd", 465: "smtps", 512: "rexec", 513: "rlogin", 514: "rsh", 587: "submission", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1883: "mqtt", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 2379: "etcd", 3268: "globalcatalog", 3269: "globalcatalog-tls",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    5985: "winrm", 5986: "winrm-https", 6379: "redis", 6443: "kubernetes-api", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch-transport", 10250: "kubelet", 11211: "memcached",
    15672: "rabbitmq-management", 27017: "mongodb",
}
HTTP_PORTS = {80, 2375, 5601, 5984, 5985, 8000, 8080, 8888, 9000, 9090, 9200, 15672}
HTTPS_PORTS = {443, 2376, 5986, 6443, 8443, 10250}
TLS_ONLY_PORTS = {465, 636, 993, 995, 3269}
MAYBE_TLS_PORTS = {2379}  # etcd: plain HTTP or TLS depending on configuration
BANNER_BYTES = 512
USER_AGENT = "EEAP-assessment/1.0 (read-only exposure check)"

MAX_EXTRA_PORTS = 1024
MAX_CONNECTIONS_PER_RUN = 60_000
_PORT_RANGE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


class PortSpecError(ValueError):
    pass


def parse_ports(specs: list[str] | None) -> list[int]:
    """'8081', '9000-9010' -> sorted extra ports (common ports are always scanned)."""
    ports: set[int] = set()
    for spec in specs or []:
        match = _PORT_RANGE.match(str(spec).strip())
        if not match:
            raise PortSpecError(f"invalid port or range {spec!r}")
        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
        if not 1 <= low <= high <= 65535:
            raise PortSpecError(f"port range {spec!r} must be within 1-65535")
        ports.update(range(low, high + 1))
        if len(ports) > MAX_EXTRA_PORTS:
            raise PortSpecError(f"at most {MAX_EXTRA_PORTS} extra ports per run")
    return sorted(ports - set(COMMON_PORTS))


def scan_ports(extra: list[int]) -> list[int]:
    return sorted(set(COMMON_PORTS) | set(extra))


# ------------------------------------------------------------------------------------- identification

def _printable(data: bytes, limit: int = 200) -> str:
    text = data.decode("latin-1")
    return re.sub(r"[^\x20-\x7e]+", " ", text).strip()[:limit]


_BANNER_PRODUCTS = (
    (re.compile(r"^SSH-[\d.]+-(?P<product>[A-Za-z]+)[_-](?P<version>[\w.]+)"), "ssh"),
    (re.compile(r"^SSH-[\d.]+-(?P<product>\S+)"), "ssh"),
    (re.compile(r"^220.*?(?P<product>vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service)"
                r"(?:\s+v?(?P<version>[\d.]+\w*))?", re.IGNORECASE), "ftp"),
    (re.compile(r"^220.*?\bESMTP\b\s*(?P<product>Postfix|Exim|Sendmail|Microsoft ESMTP MAIL Service)?"
                r"(?:\s+(?P<version>[\d.]+))?", re.IGNORECASE), "smtp"),
    (re.compile(r"^220[ -]"), "ftp-or-smtp"),
    (re.compile(r"^\+OK"), "pop3"),
    (re.compile(r"^\* OK"), "imap"),
    (re.compile(r"^RFB (?P<version>\d{3}\.\d{3})"), "vnc"),
)


def identify_banner(port: int, banner: bytes) -> dict[str, Any]:
    if not banner:
        return {}
    if banner[0] == 0xFF:
        return {"service": "telnet"}
    # MySQL/MariaDB initial handshake: 3-byte length, sequence 0, protocol version 10, version string.
    if len(banner) > 6 and banner[3] == 0 and banner[4] == 10:
        version = banner[5:].split(b"\x00", 1)[0].decode("latin-1", "replace")
        return {"service": "mysql", "product": "MariaDB" if "mariadb" in version.lower() else "MySQL",
                "version": version.split("-", 1)[0]}
    text = _printable(banner)
    for pattern, service in _BANNER_PRODUCTS:
        match = pattern.match(text)
        if match:
            groups = match.groupdict()
            if service == "ftp-or-smtp":
                service = "smtp" if port in (25, 465, 587) else "ftp"
            return {"service": service, "product": groups.get("product"), "version": groups.get("version")}
    return {}


_SERVER_HEADER = re.compile(r"^(?P<product>[^/\s]+)(?:/(?P<version>[^\s(]+))?")


def identify_http(port: int, response: bytes) -> dict[str, Any]:
    text = response.decode("latin-1", "replace")
    if not text.startswith("HTTP/"):
        return {}
    lines = text.split("\r\n")
    status = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    result: dict[str, Any] = {"service": "http", "http_status": int(status[1]) if len(status) > 1
                              and status[1].isdigit() else None}
    server = headers.get("server", "")
    if server:
        result["http_server"] = server[:120]
        match = _SERVER_HEADER.match(server)
        if match:
            result["product"], result["version"] = match.group("product"), match.group("version")
    if "x-elastic-product" in headers:
        result.update(service="elasticsearch", product=headers["x-elastic-product"])
    elif server.startswith("Docker/") or "api-version" in headers and "docker" in server.lower():
        result["service"] = "docker"
    elif server.startswith("Microsoft-HTTPAPI") and port in (5985, 5986):
        result["service"] = "winrm"
    elif server.startswith("MinIO"):
        result["service"] = "minio"
    elif "couchdb" in server.lower():
        result["service"] = "couchdb"
    return result


def parse_rdp_negotiation(response: bytes) -> dict[str, Any]:
    """Server reply to an X.224 Connection Request that offers TLS only (no CredSSP/NLA)."""
    if len(response) < 19 or response[0] != 0x03 or response[5] != 0xD0:
        return {"service": "rdp"} if response[:1] == b"\x03" else {}
    kind = response[11]
    value = int.from_bytes(response[15:19], "little")
    if kind == 0x02:  # RDP_NEG_RSP: TLS accepted without CredSSP -> NLA not required
        return {"service": "rdp", "nla_required": False, "selected_protocol": value}
    if kind == 0x03:  # RDP_NEG_FAILURE
        if value == 0x05:  # HYBRID_REQUIRED_BY_SERVER
            return {"service": "rdp", "nla_required": True}
        if value == 0x02:  # SSL_NOT_ALLOWED_BY_SERVER: legacy RDP security only
            return {"service": "rdp", "nla_required": False, "legacy_rdp_security": True}
    return {"service": "rdp"}


RDP_NEGOTIATION_REQUEST = bytes.fromhex("030000130ee000000000000100080001000000")


def describe_certificate(der: bytes | None) -> dict[str, Any]:
    if not der:
        return {}
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        return {"certificate_presented": True}
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return {"certificate_presented": True}

    def cn(name) -> str | None:
        values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(values[0].value) if values else name.rfc4514_string()[:120] or None

    not_after = cert.not_valid_after_utc
    return {"certificate_presented": True, "subject_cn": cn(cert.subject), "issuer_cn": cn(cert.issuer),
            "self_signed": cert.subject == cert.issuer, "not_after": not_after.isoformat(),
            "expired": not_after < datetime.now(UTC)}


# ------------------------------------------------------------------------------------------ probing

def _tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _exchange(ip: str, port: int, timeout: float, *, send: bytes | None = None, tls: bool = False,
                    read_bytes: int = BANNER_BYTES) -> tuple[bytes, dict[str, Any]]:
    """Connects, optionally sends one request, reads one response. Returns (data, tls info)."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=_tls_context() if tls else None,
                                server_hostname="" if tls else None), timeout)
    tls_info: dict[str, Any] = {}
    try:
        if tls:
            ssl_object = writer.get_extra_info("ssl_object")
            tls_info = {"tls_version": ssl_object.version(),
                        **describe_certificate(ssl_object.getpeercert(binary_form=True))}
        if send:
            writer.write(send)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(read_bytes), timeout)
        except TimeoutError:
            data = b""
        return data, tls_info
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        except (TimeoutError, OSError, ssl.SSLError):
            pass


def _http_request(ip: str) -> bytes:
    return (f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n").encode()


async def _identify(ip: str, port: int, timeout: float) -> dict[str, Any]:
    info: dict[str, Any] = {"service": COMMON_PORTS.get(port, "unknown")}
    try:
        if port == 3389:
            data, _ = await _exchange(ip, port, timeout, send=RDP_NEGOTIATION_REQUEST)
            info.update(parse_rdp_negotiation(data))
        elif port in HTTPS_PORTS:
            data, tls_info = await _exchange(ip, port, timeout, send=_http_request(ip), tls=True, read_bytes=4096)
            info.update(tls_info, **identify_http(port, data))
        elif port in TLS_ONLY_PORTS:
            data, tls_info = await _exchange(ip, port, timeout, tls=True)
            info.update(tls_info, **identify_banner(port, data))
        elif port in MAYBE_TLS_PORTS:
            try:
                data, tls_info = await _exchange(ip, port, timeout, send=_http_request(ip), tls=True,
                                                 read_bytes=4096)
                info.update(tls_info)
            except (ssl.SSLError, ConnectionError, TimeoutError):
                data, _ = await _exchange(ip, port, timeout, send=_http_request(ip), read_bytes=4096)
                info["tls_version"] = None
            info.update({k: v for k, v in identify_http(port, data).items() if k != "service"})
        elif port in HTTP_PORTS:
            data, _ = await _exchange(ip, port, timeout, send=_http_request(ip), read_bytes=4096)
            info.update(identify_http(port, data))
        else:
            data, _ = await _exchange(ip, port, timeout)  # wait for a server greeting only
            if data:
                info["banner"] = _printable(data)
                info.update(identify_banner(port, data))
            elif port not in COMMON_PORTS:
                data, _ = await _exchange(ip, port, timeout, send=_http_request(ip), read_bytes=4096)
                info.update(identify_http(port, data))
    except (OSError, TimeoutError, ssl.SSLError, ValueError) as exc:
        info["identify_error"] = exc.__class__.__name__
    if info.get("service") in (None, ""):
        info["service"] = COMMON_PORTS.get(port, "unknown")
    return {k: v for k, v in info.items() if v is not None}


async def _connect_open(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, TimeoutError):
        return False
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except (TimeoutError, OSError):
        pass
    return True


async def scan_hosts(ips: list[str], ports: list[int], *, timeout: float = 1.0, identify_timeout: float = 3.0,
                     concurrency: int = 100) -> dict[str, dict[str, Any]]:
    """Returns {ip: {"ports_scanned": n, "open": [service dicts], "duration_ms": ms}}."""
    if len(ips) * len(ports) > MAX_CONNECTIONS_PER_RUN:
        raise PortSpecError(f"{len(ips)} hosts x {len(ports)} ports exceeds {MAX_CONNECTIONS_PER_RUN} connections")
    limiter = asyncio.Semaphore(concurrency)

    async def check(ip: str, port: int) -> tuple[str, int, bool]:
        async with limiter:
            return ip, port, await _connect_open(ip, port, timeout)

    started = time.monotonic()
    results = await asyncio.gather(*(check(ip, port) for ip in ips for port in ports))
    open_ports = [(ip, port) for ip, port, is_open in results if is_open]

    async def identify(ip: str, port: int) -> tuple[str, dict[str, Any]]:
        async with limiter:
            return ip, {"port": port, "transport": "tcp", **(await _identify(ip, port, identify_timeout))}

    identified = await asyncio.gather(*(identify(ip, port) for ip, port in open_ports))
    duration = round((time.monotonic() - started) * 1000)
    hosts = {ip: {"ports_scanned": len(ports), "open": [], "duration_ms": duration} for ip in ips}
    for ip, service in identified:
        hosts[ip]["open"].append(service)
    for host in hosts.values():
        host["open"].sort(key=lambda s: s["port"])
    return hosts
