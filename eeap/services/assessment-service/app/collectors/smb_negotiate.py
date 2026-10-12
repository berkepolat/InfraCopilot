"""SMB protocol negotiation probe for WIN-001 (signing) and WIN-002 (SMBv1) (ADR-0011).

Sends only NEGOTIATE requests, the first message of every SMB connection, and reads the
server's advertised dialect and security mode. No session setup, authentication, share
enumeration or null sessions.
"""
from __future__ import annotations

import socket
import struct
import uuid
from typing import Any

SMB_PORT = 445
SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)
DIALECT_NAMES = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
SMB2_SIGNING_ENABLED, SMB2_SIGNING_REQUIRED = 0x01, 0x02
SMB1_SIGNATURES_ENABLED, SMB1_SIGNATURES_REQUIRED = 0x04, 0x08


def _netbios(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def smb2_negotiate_request() -> bytes:
    header = (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0xFEFF, 0, 0) + b"\x00" * 16)
    body = (struct.pack("<HHHHI", 36, len(SMB2_DIALECTS), SMB2_SIGNING_ENABLED, 0, 0) + uuid.uuid4().bytes
            + b"\x00" * 8 + b"".join(struct.pack("<H", d) for d in SMB2_DIALECTS))
    return _netbios(header + body)


def smb1_negotiate_request() -> bytes:
    dialects = b"\x02NT LM 0.12\x00"
    header = b"\xffSMB" + struct.pack("<BIBHH8sHHHHH", 0x72, 0, 0x18, 0x4001, 0, b"\x00" * 8, 0, 0, 0xFEFF, 0, 0)
    return _netbios(header + b"\x00" + struct.pack("<H", len(dialects)) + dialects)


def parse_smb2_negotiate(data: bytes) -> dict[str, Any] | None:
    """Security mode and dialect from an SMB2 NEGOTIATE response (after the 4-byte NetBIOS header)."""
    smb = data[4:]
    if len(smb) < 64 + 6 or smb[:4] != b"\xfeSMB":
        return None
    status = struct.unpack_from("<I", smb, 8)[0]
    if status != 0:
        return {"status": f"0x{status:08x}"}
    security_mode, dialect = struct.unpack_from("<HH", smb, 64 + 2)
    return {"dialect": DIALECT_NAMES.get(dialect, f"0x{dialect:04x}"),
            "signing_enabled": bool(security_mode & SMB2_SIGNING_ENABLED),
            "signing_required": bool(security_mode & SMB2_SIGNING_REQUIRED)}


def parse_smb1_negotiate(data: bytes) -> dict[str, Any] | None:
    """Whether the server accepted the SMB1 'NT LM 0.12' dialect."""
    smb = data[4:]
    if len(smb) < 32 + 3 or smb[:4] != b"\xffSMB" or smb[4] != 0x72:
        return None
    status = struct.unpack_from("<I", smb, 5)[0]
    dialect_index = struct.unpack_from("<H", smb, 33)[0]
    accepted = status == 0 and dialect_index != 0xFFFF
    result: dict[str, Any] = {"accepted": accepted}
    if accepted and len(smb) > 35:
        mode = smb[35]
        result["signing_required"] = bool(mode & SMB1_SIGNATURES_REQUIRED)
    return result


def _exchange(ip: str, request: bytes, timeout: float) -> bytes:
    with socket.create_connection((ip, SMB_PORT), timeout=timeout) as sock:
        sock.sendall(request)
        header = _recv_exact(sock, 4)
        length = struct.unpack(">I", header)[0] & 0x00FFFFFF
        return header + _recv_exact(sock, min(length, 65536))


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def probe(ip: str, timeout: float) -> dict[str, Any]:
    """{"open": bool, "smb2": {...} | None, "smb1": {"accepted": bool} | None, "error"?: str}."""
    result: dict[str, Any] = {"port": SMB_PORT, "open": False, "smb2": None, "smb1": None}
    try:
        result["smb2"] = parse_smb2_negotiate(_exchange(ip, smb2_negotiate_request(), timeout))
        result["open"] = True
    except (OSError, struct.error) as exc:
        result["error"] = exc.__class__.__name__
        if isinstance(exc, (ConnectionRefusedError, TimeoutError)) or "timed out" in str(exc):
            return result
        result["open"] = True
    try:
        result["smb1"] = parse_smb1_negotiate(_exchange(ip, smb1_negotiate_request(), timeout)) \
            or {"accepted": False}
    except (OSError, struct.error):
        # Servers without SMB1 typically reset or close the connection on an SMB1-only negotiate.
        result["smb1"] = {"accepted": False}
    return result
