"""Credentialed, read-only Windows posture over WinRM (WIN-003, 004, 005, 007, 009) (ADR-0017).

Connects to the EEAP.Posture JEA endpoint and invokes its only command, Get-EeapSecurityPosture
(infrastructure/windows/jea). The session cannot run anything else. Kerberos needs the host name
(SPN), so each IP is resolved through its PTR record first.
"""
from __future__ import annotations

import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..config import WinrmTarget

COLLECTOR_ID = "win.winrm_posture"
COLLECTOR_VERSION = "1.0"
POSTURE_COMMAND = "Get-EeapSecurityPosture"
POSTURE_SCHEMA = "eeap.windows.posture/1"
KRB5_CONFIG_PATH = "/tmp/eeap-krb5.conf"


class WinrmError(Exception):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def krb5_config(realm: str, kdc: str | None) -> str:
    lines = ["[libdefaults]", f"  default_realm = {realm.upper()}", "  dns_lookup_kdc = true",
             "  dns_lookup_realm = false", "  rdns = false", "  dns_canonicalize_hostname = false",
             "  udp_preference_limit = 0"]
    if kdc:
        lines += ["[realms]", f"  {realm.upper()} = {{", f"    kdc = {kdc}", "  }"]
    return "\n".join(lines) + "\n"


def configure_kerberos(target: WinrmTarget) -> None:
    if target.auth == "ntlm" or not target.realm:
        return
    with open(KRB5_CONFIG_PATH, "w", encoding="ascii") as handle:
        handle.write(krb5_config(target.realm, target.kdc))
    os.environ["KRB5_CONFIG"] = KRB5_CONFIG_PATH
    os.environ.setdefault("KRB5CCNAME", "MEMORY:eeap-winrm")


def resolve_hostname(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return name.rstrip(".") or None


def parse_posture(output: list[Any]) -> dict[str, Any]:
    if not output:
        raise WinrmError("parse", f"{POSTURE_COMMAND} returned no output")
    try:
        posture = json.loads(str(output[-1]))
    except ValueError as exc:
        raise WinrmError("parse", f"{POSTURE_COMMAND} returned invalid JSON") from exc
    if not isinstance(posture, dict) or posture.get("schema") != POSTURE_SCHEMA:
        raise WinrmError("parse", f"unexpected posture schema {posture.get('schema') if isinstance(posture, dict) else None!r}")
    return posture


def _invoke(server: str, target: WinrmTarget) -> dict[str, Any]:
    from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError
    from pypsrp.powershell import PowerShell, RunspacePool
    from pypsrp.wsman import WSMan

    wsman = WSMan(server, port=target.port, ssl=target.use_tls, username=target.username,
                  password=target.password, auth=target.auth, cert_validation=target.ca_file or True,
                  connection_timeout=target.timeout_seconds, operation_timeout=target.timeout_seconds,
                  read_timeout=target.timeout_seconds + 10, encryption="always" if not target.use_tls else "auto")
    try:
        with RunspacePool(wsman, configuration_name=target.configuration_name) as pool:
            shell = PowerShell(pool)
            shell.add_cmdlet(POSTURE_COMMAND)
            output = shell.invoke()
            if shell.had_errors:
                errors = "; ".join(str(e) for e in shell.streams.error)[:300]
                raise WinrmError("endpoint", f"{POSTURE_COMMAND} failed: {errors}")
    except AuthenticationError as exc:
        raise WinrmError("auth", str(exc)[:300]) from exc
    except WSManFaultError as exc:
        stage = "endpoint" if "configuration" in str(exc).lower() or "access" in str(exc).lower() else "wsman"
        raise WinrmError(stage, str(exc)[:300]) from exc
    except WinRMTransportError as exc:
        raise WinrmError("auth" if exc.code == 401 else "transport", str(exc)[:300]) from exc
    except (OSError, ConnectionError) as exc:
        raise WinrmError("connect", f"{exc.__class__.__name__}: {str(exc)[:200]}") from exc
    return parse_posture(output)


def collect_host(ip: str, target: WinrmTarget, *, invoke=_invoke) -> dict[str, Any]:
    """{"status": "ok", "hostname", "posture"} or {"status": "error", "stage", "error"}."""
    hostname = resolve_hostname(ip)
    if hostname is None and target.auth == "kerberos":
        return {"status": "error", "stage": "dns",
                "error": f"no PTR record for {ip}; Kerberos needs the host name (SPN)"}
    try:
        posture = invoke(hostname or ip, target)
    except WinrmError as exc:
        return {"status": "error", "stage": exc.stage, "hostname": hostname, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — one host must not fail the run
        return {"status": "error", "stage": "unexpected", "hostname": hostname,
                "error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
    return {"status": "ok", "hostname": hostname, "posture": posture}


def collect_hosts(ips: list[str], target: WinrmTarget, *, concurrency: int = 8, invoke=_invoke) -> dict[str, dict]:
    configure_kerberos(target)
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(ips)))) as pool:
        results = pool.map(lambda ip: collect_host(ip, target, invoke=invoke), ips)
        return {ip: {"collector": COLLECTOR_ID, "version": COLLECTOR_VERSION, **result}
                for ip, result in zip(ips, results, strict=True)}
