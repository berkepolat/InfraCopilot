"""WIN-003, 004, 005, 007, 009 evaluators over the WinRM posture document (pure functions)."""
from __future__ import annotations

import fnmatch
from datetime import datetime, timedelta
from typing import Any

WINRM_CONTROLS = ("WIN-003", "WIN-004", "WIN-005", "WIN-007", "WIN-009")
SIGNATURE_MAX_AGE = timedelta(days=7)
# Default when LmCompatibilityLevel is not set (Windows Vista / Server 2008 and later).
DEFAULT_LM_COMPATIBILITY = 3
DEFENDER_SERVICES = {"WinDefend"}


def posture(ctx) -> dict[str, Any] | None:
    probe = ctx.host["probes"].get("windows") or {}
    return probe.get("posture") if probe.get("status") == "ok" else None


def win003_ntlm(ctx) -> None:
    data = posture(ctx)
    if data is None:
        return
    ntlm = data.get("ntlm") or {}
    configured = ntlm.get("lm_compatibility_level")
    level = DEFAULT_LM_COMPATIBILITY if configured is None else int(configured)
    details = {"lm_compatibility_level": configured, "effective_level": level,
               "no_lm_hash": ntlm.get("no_lm_hash"), "restrict_receiving_ntlm": ntlm.get("restrict_receiving_ntlm")}
    if level <= 2 or ntlm.get("no_lm_hash") == 0:
        reasons = []
        if level <= 2:
            reasons.append(f"sends LM/NTLMv1 responses (LmCompatibilityLevel {level})")
        if ntlm.get("no_lm_hash") == 0:
            reasons.append("stores LM password hashes")
        ctx.emit("WIN-003", "FAIL", subject="ntlm", severity="High",
                 summary=f"{ctx.ip} {' and '.join(reasons)}", **details)
    elif level < 5:
        ctx.emit("WIN-003", "WARNING", subject="ntlm", severity="Medium",
                 summary=f"{ctx.ip} still accepts LM/NTLMv1 authentication (LmCompatibilityLevel {level}"
                         f"{', default' if configured is None else ''}); set 5 to accept NTLMv2 only", **details)
    else:
        ctx.emit("WIN-003", "PASS", subject="ntlm", summary=f"{ctx.ip} accepts NTLMv2 only", **details)


def _ldap(ctx) -> dict[str, Any] | None:
    data = posture(ctx)
    if data is None or not (data.get("host") or {}).get("is_domain_controller"):
        return None
    return data.get("ldap") or {}


def win004_ldap_signing(ctx) -> None:
    ldap = _ldap(ctx)
    if ldap is None:
        return
    value = ldap.get("server_integrity")
    if value is not None and int(value) >= 2:
        ctx.emit("WIN-004", "PASS", subject="ldap-signing",
                 summary=f"Domain controller {ctx.ip} requires LDAP signing", ldap_server_integrity=value)
    else:
        ctx.emit("WIN-004", "FAIL", subject="ldap-signing", severity="High",
                 summary=f"Domain controller {ctx.ip} does not require LDAP signing "
                         f"(LDAPServerIntegrity {value if value is not None else 'not set'})",
                 ldap_server_integrity=value)


def win005_channel_binding(ctx) -> None:
    ldap = _ldap(ctx)
    if ldap is None:
        return
    value = ldap.get("enforce_channel_binding")
    level = 0 if value is None else int(value)
    if level >= 2:
        ctx.emit("WIN-005", "PASS", subject="ldap-channel-binding",
                 summary=f"Domain controller {ctx.ip} always enforces LDAPS channel binding",
                 ldap_enforce_channel_binding=value)
    elif level == 1:
        ctx.emit("WIN-005", "WARNING", subject="ldap-channel-binding", severity="Medium",
                 summary=f"Domain controller {ctx.ip} enforces LDAPS channel binding only when supported",
                 ldap_enforce_channel_binding=value)
    else:
        ctx.emit("WIN-005", "FAIL", subject="ldap-channel-binding", severity="Medium",
                 summary=f"Domain controller {ctx.ip} does not enforce LDAPS channel binding",
                 ldap_enforce_channel_binding=value)


def _expected_admin(member: dict[str, Any], allowed: list[str]) -> bool:
    sid = str(member.get("sid") or "")
    if sid.endswith(("-500", "-512")):  # built-in Administrator, Domain Admins
        return True
    name = str(member.get("name") or "").lower()
    return any(sid == pattern or fnmatch.fnmatchcase(name, pattern.lower()) for pattern in allowed)


def win007_local_admins(ctx, allowed: list[str]) -> None:
    data = posture(ctx)
    if data is None or (data.get("host") or {}).get("is_domain_controller"):
        return
    members = data.get("local_admins")
    if members is None:
        return
    unexpected = [m for m in members if not _expected_admin(m, allowed)]
    listing = [{"name": m.get("name"), "sid": m.get("sid"), "type": m.get("object_class"),
                "source": m.get("source")} for m in members]
    if unexpected:
        names = ", ".join(str(m.get("name")) for m in unexpected[:10])
        ctx.emit("WIN-007", "WARNING", subject="local-administrators", severity="Medium",
                 summary=f"{len(unexpected)} unexpected member(s) of local Administrators on {ctx.ip}: {names}",
                 members=listing, unexpected=[m.get("name") for m in unexpected])
    else:
        ctx.emit("WIN-007", "PASS", subject="local-administrators",
                 summary=f"Local Administrators on {ctx.ip} contains only expected members", members=listing)


def win009_endpoint_protection(ctx, now: datetime) -> None:
    data = posture(ctx)
    if data is None:
        return
    protection = data.get("endpoint_protection") or {}
    defender = protection.get("defender") or {}
    running = [s["name"] for s in protection.get("services") or [] if s.get("status") == "Running"]
    third_party = [name for name in running if name not in DEFENDER_SERVICES]
    defender_active = bool(defender.get("real_time_protection")) and bool(defender.get("service_enabled"))
    details = {"running_services": running, "defender": defender or None}
    if not defender_active and not third_party:
        ctx.emit("WIN-009", "FAIL", subject="endpoint-protection", severity="High",
                 summary=f"No active antivirus or EDR protection observed on {ctx.ip}", **details)
        return
    updated = defender.get("signature_last_updated")
    if defender_active and not third_party and updated:
        age = now - datetime.fromisoformat(updated)
        if age > SIGNATURE_MAX_AGE:
            ctx.emit("WIN-009", "WARNING", subject="endpoint-protection", severity="Medium",
                     summary=f"Microsoft Defender signatures on {ctx.ip} are {age.days} days old", **details)
            return
    product = ", ".join(third_party) if third_party else "Microsoft Defender real-time protection"
    ctx.emit("WIN-009", "PASS", subject="endpoint-protection",
             summary=f"Endpoint protection active on {ctx.ip}: {product}", **details)


def unassessed(host: dict, selected: list[str]) -> list[str]:
    """WinRM controls that could not be evaluated on this host (their open findings stay open)."""
    probe = host["probes"].get("windows")
    if probe is not None and probe.get("status") == "ok":
        return []
    return [c for c in selected if c in WINRM_CONTROLS]


def asset_details(host: dict) -> dict[str, Any]:
    probe = host["probes"].get("windows") or {}
    data = probe.get("posture") if probe.get("status") == "ok" else None
    if not data:
        return {}
    info = data.get("host") or {}
    fqdn = probe.get("hostname")
    role = int(info.get("domain_role") or 0)
    asset_type = "DomainController" if role >= 4 else "Server" if role >= 2 else "Workstation"
    return {"hostname": info.get("computer_name") or fqdn, "fqdn": fqdn, "os_family": "Windows",
            "os_version": " ".join(str(v) for v in (info.get("os_caption"), info.get("os_build")) if v) or None,
            "domain": info.get("dns_domain"), "asset_type": asset_type}
