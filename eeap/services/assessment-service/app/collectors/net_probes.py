"""Read-only network configuration probes for NET-001..NET-005, WIN-001 and WIN-002 (ADR-0011).

Probes observe service exposure and protocol configuration only: TCP/TLS handshakes,
DNS AXFR policy, SNMP community response, NTP version replies. No authentication
bypass, brute force, exploit payloads or lateral movement.
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
import time
from datetime import UTC, datetime
from typing import Any

from . import smb_negotiate

logger = logging.getLogger("eeap.assessment.collectors.net")

COLLECTOR_ID = "net.probes"
COLLECTOR_VERSION = "1.0"
SOURCE_TOOL = f"eeap-net-probes/{COLLECTOR_VERSION}"

DEFAULT_TIMEOUT = 3.0
TLS_PORTS = (443, 8443)
SMB_PORT = 445
SNMP_PORT = 161
NTP_PORT = 123
DNS_PORT = 53


class NetCollectionError(Exception):
    """Raised when a run-level probe failure prevents assessment (misconfiguration)."""


def _deadline(timeout: float) -> float:
    return time.monotonic() + timeout


def _tcp_connect(ip: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {"open": True, "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except TimeoutError:
        return {"open": False, "error": "timeout", "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except OSError as exc:
        return {"open": False, "error": exc.__class__.__name__, "detail": str(exc)[:200],
                "latency_ms": round((time.monotonic() - started) * 1000, 1)}


def _probe_tls(ip: str, port: int, timeout: float) -> dict[str, Any]:
    result: dict[str, Any] = {"port": port, "open": False}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
            try:
                with context.wrap_socket(raw, server_hostname=ip) as tls:
                    result["open"] = True
                    result["negotiated_version"] = tls.version()
                    result["cipher"] = (tls.cipher() or (None, None, None))[0]
                    cert = tls.getpeercert()
                    result["certificate_presented"] = bool(cert) or bool(tls.getpeercert(binary_form=True))
                    if cert:
                        result["certificate_subject"] = dict(x[0] for x in cert.get("subject", ()) if x)
                        result["not_after"] = cert.get("notAfter")
            except ssl.SSLError as exc:
                result["open"] = True  # TCP reached; TLS failed
                result["tls_error"] = exc.__class__.__name__
                result["detail"] = str(exc)[:300]
    except OSError as exc:
        result["error"] = exc.__class__.__name__
        result["detail"] = str(exc)[:200]
        return result

    # Separate check: does the server still accept TLS 1.0 or 1.1?
    for legacy in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        label = "tls10_accepted" if legacy == ssl.TLSVersion.TLSv1 else "tls11_accepted"
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = legacy
            ctx.maximum_version = legacy
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip):
                    result[label] = True
        except Exception:
            result[label] = False
    return result


def _probe_smb(ip: str, timeout: float) -> dict[str, Any]:
    """TCP reachability of SMB (445). No authentication, share enum or null-session abuse."""
    probe = _tcp_connect(ip, SMB_PORT, timeout)
    return {"port": SMB_PORT, **probe}


def _snmp_get_public(ip: str, timeout: float) -> dict[str, Any]:
    """SNMPv2c GET sysDescr.0 with community 'public' — detects default community exposure."""
    # Minimal SNMPv2c GET PDU for 1.3.6.1.2.1.1.1.0 (sysDescr).
    community = b"public"
    # SNMP message: SEQUENCE { version INT 1, community OCTET STRING, GetRequest-PDU }
    oid = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # 1.3.6.1.2.1.1.1.0
    varbind = _asn1_seq(_asn1_oid(oid) + _asn1_null())
    varbind_list = _asn1_seq(varbind)
    pdu = _asn1_seq(
        _asn1_int(0x01)  # request-id
        + _asn1_int(0)   # error-status
        + _asn1_int(0)   # error-index
        + varbind_list,
        tag=0xA0,  # GetRequest
    )
    message = _asn1_seq(_asn1_int(1) + _asn1_octet(community) + pdu)
    sock = socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(message, (ip, SNMP_PORT))
        data, _ = sock.recvfrom(65535)
        return {"port": SNMP_PORT, "responded": True, "response_bytes": len(data),
                "public_community_accepted": True}
    except TimeoutError:
        return {"port": SNMP_PORT, "responded": False, "public_community_accepted": False}
    except OSError as exc:
        return {"port": SNMP_PORT, "responded": False, "error": exc.__class__.__name__,
                "detail": str(exc)[:200], "public_community_accepted": False}
    finally:
        sock.close()


def _asn1_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _asn1_seq(body: bytes, tag: int = 0x30) -> bytes:
    return bytes([tag]) + _asn1_len(len(body)) + body


def _asn1_int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        length = max(1, (value.bit_length() + 8) // 8)
        body = value.to_bytes(length, "big", signed=True)
        if body[0] & 0x80:
            body = b"\x00" + body
    return b"\x02" + _asn1_len(len(body)) + body


def _asn1_octet(value: bytes) -> bytes:
    return b"\x04" + _asn1_len(len(value)) + value


def _asn1_null() -> bytes:
    return b"\x05\x00"


def _asn1_oid(body: bytes) -> bytes:
    return b"\x06" + _asn1_len(len(body)) + body


def _probe_ntp(ip: str, timeout: float) -> dict[str, Any]:
    """Standard NTP client mode query (mode 3). Also notes whether any reply is received."""
    # LI=0, VN=4, Mode=3 (client)
    packet = bytearray(48)
    packet[0] = 0x23
    sock = socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, NTP_PORT))
        data, _ = sock.recvfrom(512)
        mode = data[0] & 0x07 if data else None
        version = (data[0] >> 3) & 0x07 if data else None
        return {"port": NTP_PORT, "responded": True, "version": version, "mode": mode,
                "response_bytes": len(data)}
    except TimeoutError:
        return {"port": NTP_PORT, "responded": False}
    except OSError as exc:
        return {"port": NTP_PORT, "responded": False, "error": exc.__class__.__name__,
                "detail": str(exc)[:200]}
    finally:
        sock.close()


def _probe_dns_axfr(ip: str, timeout: float) -> dict[str, Any]:
    """Checks whether the DNS server permits AXFR for a probe zone ('.' root).

    A refusal/not-auth is the hardened outcome; a successful transfer (even empty/partial)
    indicates zone-transfer exposure. Uses dnspython when available.
    """
    result: dict[str, Any] = {"port": DNS_PORT, "axfr_attempted": True, "zone": "."}
    try:
        import dns.exception
        import dns.query
        import dns.zone
    except ImportError:
        # Fallback: TCP/53 reachability only.
        tcp = _tcp_connect(ip, DNS_PORT, timeout)
        result.update({"library": "none", "tcp": tcp, "axfr_permitted": None,
                       "note": "dnspython not installed; AXFR policy not evaluated"})
        return result

    try:
        # Root zone AXFR: open resolvers that allow AXFR will answer; hardened servers refuse.
        xfr = dns.query.xfr(ip, ".", lifetime=timeout, relativize=False)
        zone = dns.zone.from_xfr(xfr, relativize=False)
        result["axfr_permitted"] = True
        result["rr_count"] = sum(1 for _ in zone.iterate_rdatasets())
    except dns.exception.FormError:
        result["axfr_permitted"] = True
        result["note"] = "AXFR stream returned malformed data (treated as permitted)"
    except Exception as exc:  # includes TransferError, Timeout, ConnectionRefused
        name = exc.__class__.__name__
        result["axfr_permitted"] = False
        result["error"] = name
        result["detail"] = str(exc)[:300]
        # Distinguish "port closed" from "refused AXFR"
        if "timeout" in name.lower() or "timeout" in str(exc).lower():
            result["reachable"] = False
        else:
            result["reachable"] = True
    return result


def collect_host(ip: str, *, control_ids: list[str], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Collects probe results for one IP. Only runs probes required by the selected controls."""
    wanted = set(control_ids)
    probes: dict[str, Any] = {}
    if "NET-001" in wanted:
        probes["dns_axfr"] = _probe_dns_axfr(ip, timeout)
    if "NET-002" in wanted:
        probes["tls"] = [_probe_tls(ip, port, timeout) for port in TLS_PORTS]
    if "NET-003" in wanted:
        probes["smb"] = _probe_smb(ip, timeout)
    if "NET-004" in wanted:
        probes["snmp"] = _snmp_get_public(ip, timeout)
    if "NET-005" in wanted:
        probes["ntp"] = _probe_ntp(ip, timeout)
    if wanted & {"WIN-001", "WIN-002"}:
        probes["smb_negotiate"] = smb_negotiate.probe(ip, timeout)
    return {
        "collector": COLLECTOR_ID,
        "collector_version": COLLECTOR_VERSION,
        "ip": ip,
        "collected_at": datetime.now(UTC).isoformat(),
        "probes": probes,
    }


def collect_targets(ips: list[str], *, control_ids: list[str], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    hosts = [collect_host(ip, control_ids=control_ids, timeout=timeout) for ip in ips]
    return {
        "collector": COLLECTOR_ID,
        "collector_version": COLLECTOR_VERSION,
        "collected_at": datetime.now(UTC).isoformat(),
        "control_ids": list(control_ids),
        "hosts": hosts,
    }


def snapshot_json(snapshot: dict) -> bytes:
    return json.dumps(snapshot, sort_keys=True).encode()
