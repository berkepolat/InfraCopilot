"""Read-only Linux posture over SSH (LIN-001 … LIN-008) (ADR-0018).

Targets accept the scanner key only with a forced command (infrastructure/linux/install-eeap-posture.sh):
whatever the client asks for, sshd runs ``sudo -n /usr/local/libexec/eeap/eeap-posture``. Only public-key
authentication is used. The server's host key is verified before authenticating, against
LINUX_SSH_KNOWN_HOSTS_FILE when configured, otherwise against the key pinned on first use.
"""
from __future__ import annotations

import base64
import hashlib
import io
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..config import LinuxSshTarget

COLLECTOR_ID = "linux.ssh_posture"
COLLECTOR_VERSION = "1.0"
POSTURE_SCHEMA = "eeap.linux.posture/1"
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
LIST_KEYS = {("accounts", "uid0"), ("accounts", "empty_password"), ("sudo", "group_member"),
             ("sudo", "nopasswd"), ("files", "mode"), ("files", "world_writable"), ("packages", "pkg")}
RSA_ALGORITHMS = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]


class SshError(Exception):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def load_private_key(text: str):
    import paramiko

    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except (paramiko.SSHException, ValueError):
            continue
    raise SshError("config", "the scanner key is not an unencrypted OpenSSH or PEM private key")


def parse_posture(text: str) -> dict[str, Any]:
    data: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        section, key, value = parts
        if (section, key) in LIST_KEYS:
            data.setdefault(section, {}).setdefault(key, []).append(value)
        else:
            data.setdefault(section, {})[key] = value
    schema = data.get("schema") or {}
    if schema.get("version") != POSTURE_SCHEMA:
        raise SshError("parse", f"unexpected posture schema {schema.get('version')!r}")
    if schema.get("complete") != "1":
        raise SshError("parse", "posture output is incomplete")
    return data


def _key_algorithms(key_type: str) -> list[str]:
    return RSA_ALGORITHMS if key_type == "ssh-rsa" else [key_type]


def _expected_keys(ip: str, target: LinuxSshTarget, pinned: dict | None) -> tuple[dict[str, str] | None, str]:
    """Allowed key type -> fingerprint for this host, or None to pin on first use."""
    if target.known_hosts_file:
        import paramiko

        name = ip if target.port == 22 else f"[{ip}]:{target.port}"
        entry = paramiko.HostKeys(target.known_hosts_file).lookup(name)
        if not entry:
            raise SshError("hostkey", f"{name} is not in LINUX_SSH_KNOWN_HOSTS_FILE")
        return {key_type: fingerprint(entry[key_type]) for key_type in entry}, "known_hosts"
    if pinned:
        return {pinned["key_type"]: pinned["fingerprint"]}, "pinned"
    return None, "first-use"


def _invoke(ip: str, target: LinuxSshTarget, pkey, pinned: dict | None) -> tuple[dict, dict]:
    import paramiko

    expected, trust = _expected_keys(ip, target, pinned)
    try:
        sock = socket.create_connection((ip, target.port), timeout=target.timeout_seconds)
    except OSError as exc:
        raise SshError("connect", f"{exc.__class__.__name__}: {str(exc)[:200]}") from exc
    transport = paramiko.Transport(sock)
    transport.banner_timeout = transport.auth_timeout = target.timeout_seconds
    try:
        if expected:
            transport.get_security_options().key_types = [
                algorithm for key_type in expected for algorithm in _key_algorithms(key_type)]
        transport.start_client(timeout=target.timeout_seconds)
        key = transport.get_remote_server_key()
        host_key = {"key_type": key.get_name(), "fingerprint": fingerprint(key), "trust": trust}
        if expected is not None and expected.get(key.get_name()) != host_key["fingerprint"]:
            raise SshError("hostkey", f"host key {host_key['fingerprint']} does not match the "
                                      f"{'known_hosts entry' if trust == 'known_hosts' else 'pinned key'}")
        transport.auth_publickey(target.username, pkey)
        channel = transport.open_session(timeout=target.timeout_seconds)
        channel.settimeout(target.timeout_seconds)
        channel.exec_command("eeap-posture")
        chunks, size = [], 0
        while data := channel.recv(65536):
            size += len(data)
            if size > MAX_OUTPUT_BYTES:
                raise SshError("parse", f"posture output exceeds {MAX_OUTPUT_BYTES} bytes")
            chunks.append(data)
        status = channel.recv_exit_status()
        if status != 0:
            stderr = channel.recv_stderr(4096).decode(errors="replace").strip()
            raise SshError("command", f"posture command exited with {status}: {stderr[:200]}")
    except paramiko.AuthenticationException as exc:
        raise SshError("auth", str(exc)[:200] or "public key rejected") from exc
    except paramiko.SSHException as exc:
        # A server that no longer offers the expected key type fails negotiation.
        stage = "hostkey" if expected and "host key" in str(exc).lower() else "ssh"
        raise SshError(stage, str(exc)[:200]) from exc
    except OSError as exc:
        raise SshError("connect", f"{exc.__class__.__name__}: {str(exc)[:200]}") from exc
    finally:
        transport.close()
    return parse_posture(b"".join(chunks).decode(errors="replace")), host_key


def collect_host(ip: str, target: LinuxSshTarget, pkey, pinned: dict | None, *, invoke=_invoke) -> dict[str, Any]:
    """{"status": "ok", "host_key", "posture"} or {"status": "error", "stage", "error"}."""
    try:
        posture, host_key = invoke(ip, target, pkey, pinned)
    except SshError as exc:
        return {"status": "error", "stage": exc.stage, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — one host must not fail the run
        return {"status": "error", "stage": "unexpected", "error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
    return {"status": "ok", "host_key": host_key, "posture": posture}


def collect_hosts(ips: list[str], target: LinuxSshTarget, pins: dict[str, dict], *, concurrency: int = 16,
                  invoke=_invoke, load_key=load_private_key) -> dict[str, dict]:
    meta = {"collector": COLLECTOR_ID, "version": COLLECTOR_VERSION}
    if not ips:
        return {}
    try:
        pkey = load_key(target.private_key)
    except SshError as exc:
        return {ip: {**meta, "status": "error", "stage": exc.stage, "error": str(exc)} for ip in ips}
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(ips)))) as pool:
        results = pool.map(lambda ip: collect_host(ip, target, pkey, pins.get(ip), invoke=invoke), ips)
        return {ip: {**meta, **result} for ip, result in zip(ips, results, strict=True)}
