"""LIN-001 … LIN-008 evaluators over the SSH posture records (pure functions)."""
from __future__ import annotations

import fnmatch
from datetime import date, datetime, timedelta
from typing import Any

LINUX_CONTROLS = tuple(f"LIN-{n:03d}" for n in range(1, 9))
EOL_WARNING = timedelta(days=180)
METADATA_MAX_AGE_DAYS = 30
MAX_AUTH_TRIES = 6
PASS_MAX_DAYS = 365

WEAK_CIPHER_MARKERS = ("-cbc", "arcfour", "3des", "blowfish", "cast128")
WEAK_MAC_MARKERS = ("md5", "-96", "ripemd")
WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
            "gss-group1-sha1-", "gss-group14-sha1-", "gss-gex-sha1-"}

# End of free security support per release (extended paid support is not considered).
EOL_DATES: dict[str, dict[str, date]] = {
    "alpine": {"3.15": date(2023, 11, 1), "3.16": date(2024, 5, 23), "3.17": date(2024, 11, 22),
               "3.18": date(2025, 5, 9), "3.19": date(2025, 11, 1), "3.20": date(2026, 4, 1),
               "3.21": date(2026, 11, 1), "3.22": date(2027, 5, 1)},
    "ubuntu": {"16.04": date(2021, 4, 30), "18.04": date(2023, 5, 31), "20.04": date(2025, 5, 31),
               "22.04": date(2027, 4, 30), "24.04": date(2029, 4, 30)},
    "debian": {"9": date(2022, 6, 30), "10": date(2024, 6, 30), "11": date(2026, 8, 31), "12": date(2028, 6, 30),
               "13": date(2030, 6, 30)},
    "rhel": {"7": date(2024, 6, 30), "8": date(2029, 5, 31), "9": date(2032, 5, 31)},
    "centos": {"7": date(2024, 6, 30), "8": date(2021, 12, 31), "stream-8": date(2024, 5, 31),
               "stream-9": date(2027, 5, 31)},
    "amzn": {"2": date(2026, 6, 30), "2023": date(2029, 6, 30)},
}
RHEL_REBUILDS = {"rocky", "almalinux", "ol"}


def posture(ctx) -> dict[str, Any] | None:
    probe = ctx.host["probes"].get("linux") or {}
    return probe.get("posture") if probe.get("status") == "ok" else None


def _int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _emit(ctx, control_id: str, subject: str, failures: list[str], warnings: list[tuple[str, str]],
          ok_summary: str, fail_severity: str = "High", **details) -> None:
    """FAIL when there are failures, WARNING at the highest warning severity, otherwise PASS."""
    if failures:
        reasons = failures + [text for text, _ in warnings]
        ctx.emit(control_id, "FAIL", subject=subject, severity=fail_severity,
                 summary=f"{ctx.ip}: {'; '.join(reasons)}", **details)
    elif warnings:
        severity = "Medium" if any(level == "Medium" for _, level in warnings) else "Low"
        ctx.emit(control_id, "WARNING", subject=subject, severity=severity,
                 summary=f"{ctx.ip}: {'; '.join(text for text, _ in warnings)}", **details)
    else:
        ctx.emit(control_id, "PASS", subject=subject, summary=f"{ctx.ip}: {ok_summary}", **details)


def _weak_algorithms(value: str | None, *, markers=(), names=frozenset()) -> list[str]:
    algorithms = [a for a in (value or "").split(",") if a]
    return [a for a in algorithms if a in names or any(m in a for m in markers)
            or any(a.startswith(n) for n in names if n.endswith("-"))]


def lin001_sshd(ctx) -> None:
    data = posture(ctx)
    sshd = (data or {}).get("sshd") or {}
    if sshd.get("available") != "1":
        return
    failures, warnings = [], []
    if sshd.get("permitemptypasswords") == "yes":
        failures.append("sshd permits empty passwords")
    if sshd.get("permitrootlogin") == "yes":
        failures.append("sshd permits direct root login (PermitRootLogin yes)")
    if "yes" in (sshd.get("passwordauthentication"), sshd.get("kbdinteractiveauthentication")):
        warnings.append(("sshd accepts password logins", "Medium"))
    weak = (_weak_algorithms(sshd.get("ciphers"), markers=WEAK_CIPHER_MARKERS)
            + _weak_algorithms(sshd.get("macs"), markers=WEAK_MAC_MARKERS)
            + _weak_algorithms(sshd.get("kexalgorithms"), names=WEAK_KEX))
    if weak:
        warnings.append((f"weak sshd algorithms enabled ({', '.join(weak[:6])})", "Medium"))
    tries = _int(sshd.get("maxauthtries"))
    if tries is not None and tries > MAX_AUTH_TRIES:
        warnings.append((f"MaxAuthTries {tries}", "Low"))
    settings = {k: sshd.get(k) for k in ("permitrootlogin", "passwordauthentication", "permitemptypasswords",
                                         "kbdinteractiveauthentication", "maxauthtries")}
    _emit(ctx, "LIN-001", "sshd", failures, warnings, "sshd allows key-based logins only with strong algorithms",
          sshd=settings, weak_algorithms=weak)


def lin002_updates(ctx) -> None:
    data = posture(ctx)
    updates = (data or {}).get("updates") or {}
    age = _int(updates.get("metadata_age_days"))
    if age is None:
        return  # no package metadata on the host: pending updates cannot be determined
    manager = updates.get("manager")
    security, pending = _int(updates.get("security")), _int(updates.get("pending"))
    failures, warnings = [], []
    if security:
        failures.append(f"{security} security update(s) pending ({manager})")
    elif pending and manager == "apk":
        warnings.append((f"{pending} package update(s) pending (apk has no security classification)", "Medium"))
    if updates.get("reboot_required") == "1":
        warnings.append(("a reboot is required to load installed updates", "Medium"))
    if age > METADATA_MAX_AGE_DAYS:
        warnings.append((f"package metadata is {age} days old, so pending updates may be missing", "Low"))
    _emit(ctx, "LIN-002", "package-updates", failures, warnings, "no security updates pending",
          manager=manager, security_updates=security, pending_updates=pending, metadata_age_days=age,
          reboot_required=updates.get("reboot_required") == "1")


def lin003_privileged(ctx, allowed: list[str]) -> None:
    data = posture(ctx)
    if data is None:
        return
    accounts, sudo = data.get("accounts") or {}, data.get("sudo") or {}
    uid0 = accounts.get("uid0") or []
    nopasswd = sudo.get("nopasswd") or []
    members = [m.split(":", 1) for m in sudo.get("group_member") or [] if ":" in m]
    unexpected = sorted({user for _, user in members if user != "root"
                         and not any(fnmatch.fnmatchcase(user, pattern) for pattern in allowed)})
    failures = [f"accounts other than root with UID 0: {', '.join(uid0)}"] if uid0 else []
    warnings = []
    if nopasswd:
        warnings.append((f"{len(nopasswd)} sudo rule(s) without password (NOPASSWD)", "Medium"))
    if unexpected:
        warnings.append((f"unexpected members of sudo/wheel/admin: {', '.join(unexpected[:10])}", "Medium"))
    _emit(ctx, "LIN-003", "privileged-access", failures, warnings, "privileged access is limited to expected accounts",
          uid0_accounts=uid0, nopasswd_rules=nopasswd[:20], admin_group_members=[f"{g}:{u}" for g, u in members])


def lin004_firewall(ctx) -> None:
    data = posture(ctx)
    if data is None:
        return
    fw = data.get("firewall") or {}
    active = []
    if fw.get("ufw") == "active":
        active.append("ufw")
    if fw.get("firewalld") == "running":
        active.append("firewalld")
    if fw.get("nft_input_policy") == "drop" or (_int(fw.get("nft_input_rules")) or 0) > 0:
        active.append("nftables input chain")
    if fw.get("iptables_input_policy") in ("DROP", "REJECT") or (_int(fw.get("iptables_input_rules")) or 0) > 0:
        active.append("iptables INPUT chain")
    if active:
        ctx.emit("LIN-004", "PASS", subject="host-firewall",
                 summary=f"{ctx.ip}: inbound traffic is filtered by {', '.join(active)}", firewall=fw)
    else:
        ctx.emit("LIN-004", "FAIL", subject="host-firewall", severity="Medium",
                 summary=f"{ctx.ip}: no host firewall filters inbound traffic", firewall=fw)


def lin005_accounts(ctx) -> None:
    data = posture(ctx)
    accounts = (data or {}).get("accounts") or {}
    if data is None or not accounts:
        return
    empty = accounts.get("empty_password") or []
    max_days = _int(accounts.get("pass_max_days"))
    failures = [f"accounts with an empty password: {', '.join(empty)}"] if empty else []
    warnings = []
    if max_days is not None and max_days > PASS_MAX_DAYS:
        warnings.append((f"PASS_MAX_DAYS {max_days} (passwords never expire)", "Low"))
    _emit(ctx, "LIN-005", "local-accounts", failures, warnings, "no local account has an empty password",
          empty_password_accounts=empty, pass_max_days=max_days,
          shadow_checked=accounts.get("shadow_readable") == "1")


KERNEL_CHECKS = (
    # sysctl, bad value predicate, message, severity
    ("kernel.randomize_va_space", lambda v: v != "2", "ASLR is not fully enabled", "Medium"),
    ("net.ipv4.conf.all.accept_source_route", lambda v: v == "1", "source-routed packets are accepted", "Medium"),
    ("fs.protected_symlinks", lambda v: v == "0", "symlink protection is disabled", "Medium"),
    ("fs.protected_hardlinks", lambda v: v == "0", "hardlink protection is disabled", "Medium"),
    ("net.ipv4.conf.all.accept_redirects", lambda v: v == "1", "IPv4 ICMP redirects are accepted", "Low"),
    ("net.ipv6.conf.all.accept_redirects", lambda v: v == "1", "IPv6 ICMP redirects are accepted", "Low"),
    ("net.ipv4.tcp_syncookies", lambda v: v == "0", "TCP SYN cookies are disabled", "Low"),
    ("kernel.kptr_restrict", lambda v: v == "0", "kernel pointers are exposed (kptr_restrict 0)", "Low"),
    ("kernel.dmesg_restrict", lambda v: v == "0", "unprivileged users can read the kernel log", "Low"),
    ("fs.suid_dumpable", lambda v: v not in ("0", ""), "set-uid programs can dump core", "Low"),
    ("kernel.yama.ptrace_scope", lambda v: v == "0", "any process can ptrace processes of the same user", "Low"),
)


def lin006_kernel(ctx) -> None:
    data = posture(ctx)
    sysctl = (data or {}).get("sysctl") or {}
    if not sysctl:
        return
    warnings = [(message, severity) for key, bad, message, severity in KERNEL_CHECKS
                if key in sysctl and bad(sysctl[key])]
    if sysctl.get("net.ipv4.conf.all.send_redirects") == "1" and sysctl.get("net.ipv4.ip_forward") == "0":
        warnings.append(("ICMP redirects are sent although the host does not route", "Low"))
    _emit(ctx, "LIN-006", "kernel-hardening", [], warnings, "kernel hardening settings are in place", sysctl=sysctl)


def _file_modes(files: dict) -> dict[str, tuple[int, str, str]]:
    modes = {}
    for entry in files.get("mode") or []:
        parts = entry.split()
        if len(parts) == 4 and (mode := _int_octal(parts[1])) is not None:
            modes[parts[0]] = (mode, parts[2], parts[3])
    return modes


def _int_octal(value: str) -> int | None:
    try:
        return int(value, 8)
    except ValueError:
        return None


def lin007_file_permissions(ctx) -> None:
    data = posture(ctx)
    files = (data or {}).get("files") or {}
    if not files:
        return
    issues, critical = [], False
    for path, (mode, owner, _group) in _file_modes(files).items():
        if owner != "root":
            issues.append(f"{path} is owned by {owner}")
        if path in ("/etc/shadow", "/etc/gshadow") and mode & 0o007:
            issues.append(f"{path} is accessible by all users ({mode:o})")
            critical = True
        elif mode & 0o002:
            issues.append(f"{path} is world-writable ({mode:o})")
            critical = critical or path in ("/etc/passwd", "/etc/sudoers")
        elif mode & 0o020 and path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"):
            issues.append(f"{path} is group-writable ({mode:o})")
    writable = files.get("world_writable") or []
    if writable:
        issues.append(f"{len(writable)} world-writable file(s) under /etc ({', '.join(writable[:5])})")
    _emit(ctx, "LIN-007", "file-permissions", issues, [], "sensitive files have restrictive permissions",
          fail_severity="High" if critical else "Medium", world_writable=writable[:50],
          modes={p: f"{m:o} {o}:{g}" for p, (m, o, g) in _file_modes(files).items()})


def release(host: dict) -> tuple[str, str] | None:
    """(distribution family, release key) used for EOL_DATES."""
    os_id, version = (host.get("os_id") or "").lower(), host.get("os_version_id") or ""
    major = version.split(".")[0]
    if os_id == "alpine":
        return "alpine", ".".join(version.split(".")[:2])
    if os_id in ("ubuntu", "amzn"):
        return os_id, version
    if os_id == "debian":
        return "debian", major
    if os_id == "rhel" or os_id in RHEL_REBUILDS:
        return "rhel", major
    if os_id == "centos":
        stream = "stream" in (host.get("os_pretty") or "").lower()
        return "centos", f"stream-{major}" if stream else major
    return None


def lin008_lifecycle(ctx, now: datetime) -> None:
    data = posture(ctx)
    host = (data or {}).get("host") or {}
    key = release(host)
    eol = EOL_DATES.get(key[0], {}).get(key[1]) if key else None
    if eol is None:
        return  # unknown distribution or release
    name = host.get("os_pretty") or f"{key[0]} {key[1]}"
    today = now.date()
    if eol <= today:
        ctx.emit("LIN-008", "FAIL", subject="os-lifecycle", severity="High",
                 summary=f"{ctx.ip}: {name} reached the end of security support on {eol.isoformat()}",
                 os=name, end_of_support=eol.isoformat())
    elif eol - today <= EOL_WARNING:
        ctx.emit("LIN-008", "WARNING", subject="os-lifecycle", severity="Medium",
                 summary=f"{ctx.ip}: {name} reaches the end of security support on {eol.isoformat()}",
                 os=name, end_of_support=eol.isoformat())
    else:
        ctx.emit("LIN-008", "PASS", subject="os-lifecycle",
                 summary=f"{ctx.ip}: {name} is supported until {eol.isoformat()}",
                 os=name, end_of_support=eol.isoformat())


def unassessed(host: dict, selected: list[str]) -> list[str]:
    """Linux controls that could not be evaluated on this host (their open findings stay open)."""
    probe = host["probes"].get("linux")
    if probe is not None and probe.get("status") == "ok":
        return []
    return [c for c in selected if c in LINUX_CONTROLS]


def asset_details(host: dict) -> dict[str, Any]:
    probe = host["probes"].get("linux") or {}
    data = probe.get("posture") if probe.get("status") == "ok" else None
    if not data:
        return {}
    info = data.get("host") or {}
    fqdn = info.get("fqdn") if "." in (info.get("fqdn") or "") else None
    return {"hostname": info.get("hostname"), "fqdn": fqdn, "os_family": "Linux",
            "os_version": info.get("os_pretty") or None, "asset_type": "Server"}
