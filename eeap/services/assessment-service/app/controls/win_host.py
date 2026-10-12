"""WIN-003, 004, 005, 007, 009 … 012 evaluators over the WinRM posture document (pure functions)."""
from __future__ import annotations

import fnmatch
import hashlib
from datetime import date, datetime, timedelta
from typing import Any

from .. import vulns
from .linux_host import _emit

WINRM_CONTROLS = ("WIN-003", "WIN-004", "WIN-005", "WIN-007", "WIN-009", "WIN-010", "WIN-011", "WIN-012")
UPDATE_CONTROLS = ("WIN-010", "WIN-011")
SIGNATURE_MAX_AGE = timedelta(days=7)
# Default when LmCompatibilityLevel is not set (Windows Vista / Server 2008 and later).
DEFAULT_LM_COMPATIBILITY = 3
DEFENDER_SERVICES = {"WinDefend"}

MSRC_SEVERITY = {"critical": "Critical", "important": "High", "moderate": "Medium", "low": "Low"}
UNRATED_SECURITY_SEVERITY = "Medium"
KEV_MIN_SEVERITY = "High"
WU_SCAN_MAX_AGE_DAYS = 30
PATCH_WARNING_AGE_DAYS = 35
PATCH_FAIL_AGE_DAYS = 60
EOL_WARNING = timedelta(days=180)
MAX_EVIDENCE_CVES = 100

# End of security updates per build (extended paid support / ESU is not considered).
# Server builds map to one date; client builds per servicing class (see edition_class).
SERVER_LIFECYCLE: dict[str, tuple[str, date]] = {
    "7601": ("Windows Server 2008 R2", date(2020, 1, 14)),
    "9200": ("Windows Server 2012", date(2023, 10, 10)),
    "9600": ("Windows Server 2012 R2", date(2023, 10, 10)),
    "14393": ("Windows Server 2016", date(2027, 1, 12)),
    "17763": ("Windows Server 2019", date(2029, 1, 9)),
    "20348": ("Windows Server 2022", date(2031, 10, 14)),
    "26100": ("Windows Server 2025", date(2034, 10, 10)),
}
CLIENT_LIFECYCLE: dict[str, tuple[str, dict[str, date]]] = {
    "7601": ("Windows 7", {"consumer": date(2020, 1, 14)}),
    "9600": ("Windows 8.1", {"consumer": date(2023, 1, 10)}),
    "14393": ("Windows 10 1607", {"consumer": date(2018, 4, 10), "enterprise": date(2019, 4, 9),
                                  "ltsc": date(2026, 10, 13)}),
    "17763": ("Windows 10 1809", {"consumer": date(2020, 11, 10), "enterprise": date(2021, 5, 11),
                                  "ltsc": date(2029, 1, 9)}),
    "19041": ("Windows 10 2004", {"consumer": date(2021, 12, 14)}),
    "19042": ("Windows 10 20H2", {"consumer": date(2022, 5, 10), "enterprise": date(2023, 5, 9)}),
    "19043": ("Windows 10 21H1", {"consumer": date(2022, 12, 13)}),
    "19044": ("Windows 10 21H2", {"consumer": date(2023, 6, 13), "enterprise": date(2024, 6, 11),
                                  "ltsc": date(2027, 1, 12), "iot_ltsc": date(2032, 1, 13)}),
    "19045": ("Windows 10 22H2", {"consumer": date(2025, 10, 14)}),
    "22000": ("Windows 11 21H2", {"consumer": date(2023, 10, 10), "enterprise": date(2024, 10, 8)}),
    "22621": ("Windows 11 22H2", {"consumer": date(2024, 10, 8), "enterprise": date(2025, 10, 14)}),
    "22631": ("Windows 11 23H2", {"consumer": date(2025, 11, 11), "enterprise": date(2026, 11, 10)}),
    "26100": ("Windows 11 24H2", {"consumer": date(2026, 10, 13), "enterprise": date(2027, 10, 12),
                                  "ltsc": date(2029, 10, 9), "iot_ltsc": date(2034, 10, 10)}),
    "26200": ("Windows 11 25H2", {"consumer": date(2027, 10, 12), "enterprise": date(2028, 10, 10)}),
}
SERVER_INSTALLATION_TYPES = {"server", "server core", "nano server"}


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


def _list(value) -> list:
    """PowerShell serialises one-element and empty arrays inconsistently."""
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _date(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value)) if value else None
    except ValueError:
        return None


def is_security_update(update: dict[str, Any]) -> bool:
    categories = {str(c) for c in _list(update.get("categories"))}
    if "Definition Updates" in categories:
        return False  # antivirus signatures belong to WIN-009
    return bool(update.get("severity")) or "Security Updates" in categories


def security_updates(data: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    """Missing security updates from the posture (normalised in place), or None when not collected."""
    updates = (data or {}).get("updates") or {}
    if updates.get("pending") is None:
        return None
    missing = [u for u in _list(updates["pending"]) if isinstance(u, dict) and is_security_update(u)]
    for update in missing:
        update["kbs"] = [str(k) for k in _list(update.get("kbs"))]
        update["cves"] = sorted({str(c) for c in _list(update.get("cves"))})
        update["categories"] = [str(c) for c in _list(update.get("categories"))]
    return missing


def _update_subject(update: dict[str, Any]) -> str:
    if update["kbs"]:
        return f"kb:{update['kbs'][0]}"
    return "update:" + hashlib.sha256(str(update.get("title")).encode()).hexdigest()[:12]


def win010_missing_updates(ctx, now: datetime) -> None:
    data = posture(ctx)
    missing = security_updates(data)
    if missing is None:
        return
    updates = data["updates"]
    exploit_context = (ctx.host["probes"].get("windows") or {}).get("exploit_data")
    for update in missing:
        msrc = update.get("severity")
        severity = MSRC_SEVERITY.get(str(msrc).lower(), UNRATED_SECURITY_SEVERITY)
        exploited = update.get("known_exploited") or []
        if exploited and vulns.SEVERITY_ORDER.get(severity, 0) < vulns.SEVERITY_ORDER[KEV_MIN_SEVERITY]:
            severity = KEV_MIN_SEVERITY
        cves = update["cves"]
        name = update["kbs"][0] if update["kbs"] else "update"
        summary = f"{ctx.ip}: missing security update {name} ({update.get('title')})"
        if cves:
            summary += f" fixing {len(cves)} CVE(s)"
        if exploited:
            summary += f"; actively exploited (CISA KEV): {', '.join(exploited[:5])}"
        details = {k: v for k, v in update.items() if k not in ("severity", "cves")}
        ctx.emit("WIN-010", "FAIL", subject=_update_subject(update), severity=severity, summary=summary,
                 msrc_severity=msrc, cves=cves[:MAX_EVIDENCE_CVES], cve_count=len(cves),
                 exploit_data=exploit_context, **details)
    if not missing:
        ctx.emit("WIN-010", "PASS", subject="updates",
                 summary=f"{ctx.ip}: no missing security updates in the Windows Update scan results")
    last_search = _date(updates.get("last_search_success"))
    age = (now - last_search).days if last_search else None
    if age is None or age > WU_SCAN_MAX_AGE_DAYS:
        when = f"{age} days ago" if age is not None else "never (or unknown)"
        ctx.emit("WIN-010", "WARNING", subject="wu-scan", severity="Low",
                 summary=f"{ctx.ip}: Windows Update last searched for updates {when}; "
                         "the missing update list may be incomplete",
                 last_search_success=updates.get("last_search_success"),
                 pending_truncated=bool(updates.get("pending_truncated")))
    else:
        ctx.emit("WIN-010", "PASS", subject="wu-scan",
                 summary=f"{ctx.ip}: Windows Update searched for updates {age} days ago",
                 last_search_success=updates.get("last_search_success"),
                 pending_truncated=bool(updates.get("pending_truncated")))


def win011_patch_currency(ctx, now: datetime) -> None:
    data = posture(ctx)
    updates = (data or {}).get("updates")
    if updates is None:
        return
    hotfixes = [h for h in _list(updates.get("hotfixes")) if isinstance(h, dict)]
    installed = [d for d in (_date(h.get("installed_on")) for h in hotfixes) if d]
    last_install = _date(updates.get("last_install_success"))
    latest = max(installed + ([last_install] if last_install else []), default=None)
    recent = sorted(hotfixes, key=lambda h: str(h.get("installed_on") or ""), reverse=True)[:10]
    details = {"last_update_installed": latest.isoformat() if latest else None,
               "last_install_success": updates.get("last_install_success"),
               "hotfix_count": len(hotfixes), "recent_hotfixes": recent,
               "reboot_required": bool(updates.get("reboot_required")),
               "last_boot": (data.get("host") or {}).get("last_boot")}
    failures: list[str] = []
    warnings: list[tuple[str, str]] = []
    age = (now - latest).days if latest else None
    if age is None:
        warnings.append(("no update installation date found", "Low"))
    elif age > PATCH_FAIL_AGE_DAYS:
        failures.append(f"no update installed for {age} days")
    elif age > PATCH_WARNING_AGE_DAYS:
        warnings.append((f"no update installed for {age} days", "Medium"))
    if updates.get("reboot_required"):
        warnings.append(("installed updates wait for a reboot to take effect", "Medium"))
    ok = f"last update installed {age} days ago" if age is not None else "updates current"
    _emit(ctx, "WIN-011", "patch-currency", failures, warnings, ok, **details)


def edition_class(edition_id: str | None) -> str:
    edition = (edition_id or "").lower()
    if edition.startswith("iotenterprises"):
        return "iot_ltsc"
    if edition.startswith("enterprises"):
        return "ltsc"
    if edition.startswith(("enterprise", "education", "iotenterprise", "serverrdsh")):
        return "enterprise"
    return "consumer"


def lifecycle(host: dict[str, Any]) -> tuple[str, date] | None:
    """Product name and end of security updates for this Windows build, or None when unknown."""
    build = str(host.get("os_build") or "").strip()
    installation = str(host.get("installation_type") or "").lower()
    is_server = (installation in SERVER_INSTALLATION_TYPES if installation
                 else int(host.get("product_type") or 1) != 1 or "server" in str(host.get("os_caption")).lower())
    if is_server:
        return SERVER_LIFECYCLE.get(build)
    entry = CLIENT_LIFECYCLE.get(build)
    if entry is None:
        return None
    name, dates = entry
    servicing = edition_class(host.get("edition_id"))
    fallback = {"iot_ltsc": ("ltsc", "enterprise"), "ltsc": ("enterprise",), "enterprise": ()}
    for key in (servicing, *fallback.get(servicing, ()), "consumer"):
        if key in dates:
            return name, dates[key]
    return None


def win012_os_lifecycle(ctx, now: datetime) -> None:
    host = (posture(ctx) or {}).get("host") or {}
    known = lifecycle(host)
    if known is None:
        return  # unknown build (Insider, semi-annual Server) or posture not collected
    product, eol = known
    name = host.get("os_caption") or product
    details = {"os": name, "product": product, "build": host.get("os_build"), "ubr": host.get("os_ubr"),
               "edition_id": host.get("edition_id"), "servicing": edition_class(host.get("edition_id")),
               "end_of_support": eol.isoformat()}
    today = now.date()
    if eol <= today:
        ctx.emit("WIN-012", "FAIL", subject="os-lifecycle", severity="High",
                 summary=f"{ctx.ip}: {name} ({product}) stopped receiving security updates on {eol.isoformat()}",
                 **details)
    elif eol - today <= EOL_WARNING:
        ctx.emit("WIN-012", "WARNING", subject="os-lifecycle", severity="Medium",
                 summary=f"{ctx.ip}: {name} ({product}) stops receiving security updates on {eol.isoformat()}",
                 **details)
    else:
        ctx.emit("WIN-012", "PASS", subject="os-lifecycle",
                 summary=f"{ctx.ip}: {name} ({product}) receives security updates until {eol.isoformat()}",
                 **details)


def unassessed(host: dict, selected: list[str]) -> list[str]:
    """WinRM controls that could not be evaluated on this host (their open findings stay open)."""
    probe = host["probes"].get("windows")
    if probe is not None and probe.get("status") == "ok":
        updates = (probe.get("posture") or {}).get("updates")
        if updates is None:  # posture module older than 1.1.0
            return [c for c in selected if c in UPDATE_CONTROLS]
        return ["WIN-010"] if updates.get("pending") is None and "WIN-010" in selected else []
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
    build = info.get("os_build")
    if build and info.get("os_ubr") is not None:
        build = f"{build}.{info['os_ubr']}"
    return {"hostname": info.get("computer_name") or fqdn, "fqdn": fqdn, "os_family": "Windows",
            "os_version": " ".join(str(v) for v in (info.get("os_caption"), build) if v) or None,
            "domain": info.get("dns_domain"), "asset_type": asset_type}
