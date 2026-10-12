"""Network run evaluators: NET-001..NET-012, the WIN controls (on the wire and over WinRM) and the
LIN controls (over SSH).

Pure functions over net_probes / smb_negotiate / port_scan / web_probe / winrm / ssh snapshots.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..domain import ImportRow
from ..targets import asset_id_for_ip
from . import linux_host, win_host

SOURCE_TOOL = "eeap-net-probes/1.0"
NET_CONTROL_IDS = tuple(f"NET-{n:03d}" for n in range(1, 13))
# Web checks run on HTTP(S) services found by the port scan (collectors/web_probe.py).
WEB_CONTROLS = ("NET-010", "NET-011", "NET-012")
# Windows configuration visible on the wire; the remaining WIN controls need WinRM (win_host).
WIN_NETWORK_CONTROLS = ("WIN-001", "WIN-002", "WIN-006", "WIN-008")
NETWORK_RUN_CONTROLS = (NET_CONTROL_IDS + WIN_NETWORK_CONTROLS + win_host.WINRM_CONTROLS
                        + linux_host.LINUX_CONTROLS)
PORT_SCAN_CONTROLS = ("NET-006", "NET-007", "NET-008", "NET-009", "WIN-006", "WIN-008") + WEB_CONTROLS

# control -> port -> (label, severity when exposed, status when exposed); all ports are in COMMON_PORTS.
REMOTE_ADMIN = {22: "SSH", 3389: "RDP", 5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 5900: "VNC"}
CLEARTEXT = {21: ("FTP", "Medium"), 23: ("Telnet", "High"), 512: ("rexec", "High"), 513: ("rlogin", "High"),
             514: ("rsh", "High")}
DATA_STORES = {1433: "Microsoft SQL Server", 1521: "Oracle", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
               5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch HTTP", 9300: "Elasticsearch transport",
               11211: "Memcached", 27017: "MongoDB"}
CONTROL_PLANES = {2375: "Docker Engine API", 2376: "Docker Engine API (TLS)", 2379: "etcd",
                  6443: "Kubernetes API server", 10250: "Kubelet API"}


@dataclass
class Evaluation:
    observations: list[ImportRow] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    evaluated_controls: list[str] = field(default_factory=list)
    # ip -> controls that could not be evaluated there (collection failed); their findings stay open.
    unassessed: dict[str, list[str]] = field(default_factory=dict)


class _HostContext:
    def __init__(self, host: dict, now: datetime):
        self.host = host
        self.ip = host["ip"]
        self.now = now
        self.asset_id = asset_id_for_ip(self.ip)
        self.rows: list[ImportRow] = []

    def emit(self, control_id: str, status: str, *, subject: str, summary: str,
             severity: str | None = None, **details) -> None:
        self.rows.append(ImportRow(
            asset_id=self.asset_id, control_id=control_id, status=status, severity=severity,
            subject_key=subject, evidence={"summary": summary, **details},
            raw_data={"ip": self.ip}, source_tool=SOURCE_TOOL))


def _net001_dns_axfr(ctx: _HostContext) -> None:
    probe = ctx.host["probes"].get("dns_axfr") or {}
    if probe.get("axfr_permitted") is True:
        ctx.emit("NET-001", "FAIL", subject="dns-axfr", severity="Medium",
                 summary=f"DNS server {ctx.ip} permitted a zone transfer (AXFR)",
                 rr_count=probe.get("rr_count"), zone=probe.get("zone"))
    elif probe.get("axfr_permitted") is False:
        ctx.emit("NET-001", "PASS", subject="dns-axfr",
                 summary=f"DNS server {ctx.ip} refused or did not complete AXFR",
                 error=probe.get("error"), reachable=probe.get("reachable"))
    else:
        # Library missing or inconclusive — do not invent a pass.
        tcp = (probe.get("tcp") or {})
        if tcp.get("open"):
            ctx.emit("NET-001", "WARNING", subject="dns-axfr", severity="Low",
                     summary=f"DNS TCP/53 is reachable on {ctx.ip} but AXFR policy could not be evaluated",
                     note=probe.get("note"))
        else:
            ctx.emit("NET-001", "PASS", subject="dns-axfr",
                     summary=f"No DNS AXFR exposure observed on {ctx.ip} (TCP/53 not open or not evaluated)")


def _net002_tls(ctx: _HostContext) -> None:
    probes = ctx.host["probes"].get("tls") or []
    any_open = False
    for probe in probes:
        port = probe.get("port")
        subject = f"tls:{port}"
        if not probe.get("open") and not probe.get("tls_error"):
            continue
        any_open = True
        issues = []
        if probe.get("tls10_accepted"):
            issues.append("TLS 1.0 accepted")
        if probe.get("tls11_accepted"):
            issues.append("TLS 1.1 accepted")
        version = probe.get("negotiated_version") or ""
        if version in ("TLSv1", "TLSv1.1"):
            issues.append(f"negotiated {version}")
        if issues:
            ctx.emit("NET-002", "FAIL", subject=subject, severity="Medium",
                     summary=f"TLS on {ctx.ip}:{port} allows weak protocol(s): {', '.join(issues)}",
                     negotiated_version=version, cipher=probe.get("cipher"),
                     certificate_presented=probe.get("certificate_presented"))
        elif probe.get("tls_error"):
            ctx.emit("NET-002", "WARNING", subject=subject, severity="Low",
                     summary=f"TLS handshake to {ctx.ip}:{port} failed after TCP connect",
                     detail=probe.get("detail"), tls_error=probe.get("tls_error"))
        else:
            ctx.emit("NET-002", "PASS", subject=subject,
                     summary=f"TLS on {ctx.ip}:{port} negotiated {version or 'a modern protocol'}",
                     negotiated_version=version, cipher=probe.get("cipher"))
    if not any_open:
        ctx.emit("NET-002", "PASS", subject="tls",
                 summary=f"No TLS service observed on {ctx.ip} ports 443/8443")


def _net003_smb(ctx: _HostContext) -> None:
    probe = ctx.host["probes"].get("smb") or {}
    if probe.get("open"):
        ctx.emit("NET-003", "FAIL", subject="smb:445", severity="Medium",
                 summary=f"SMB (TCP/445) is reachable on {ctx.ip}",
                 latency_ms=probe.get("latency_ms"))
    else:
        ctx.emit("NET-003", "PASS", subject="smb:445",
                 summary=f"SMB (TCP/445) is not reachable on {ctx.ip}",
                 error=probe.get("error"))


def _net004_snmp(ctx: _HostContext) -> None:
    probe = ctx.host["probes"].get("snmp") or {}
    if probe.get("public_community_accepted"):
        ctx.emit("NET-004", "FAIL", subject="snmp:public", severity="Medium",
                 summary=f"SNMP on {ctx.ip} accepted the default 'public' community",
                 response_bytes=probe.get("response_bytes"))
    elif probe.get("responded"):
        ctx.emit("NET-004", "WARNING", subject="snmp", severity="Low",
                 summary=f"SNMP on {ctx.ip} responded but not with community 'public'",
                 detail=probe.get("detail"))
    else:
        ctx.emit("NET-004", "PASS", subject="snmp",
                 summary=f"No SNMP response to community 'public' on {ctx.ip}")


def _net005_ntp(ctx: _HostContext) -> None:
    probe = ctx.host["probes"].get("ntp") or {}
    if probe.get("responded"):
        ctx.emit("NET-005", "WARNING", subject="ntp:123", severity="Low",
                 summary=f"NTP service on {ctx.ip} responds to client queries (confirm access is intended)",
                 version=probe.get("version"), mode=probe.get("mode"))
    else:
        ctx.emit("NET-005", "PASS", subject="ntp:123",
                 summary=f"No NTP response observed on {ctx.ip}")


def _open_services(ctx: _HostContext, ports) -> list[dict]:
    services = (ctx.host["probes"].get("ports") or {}).get("open") or []
    return [s for s in services if s["port"] in ports]


def _service_details(service: dict) -> dict:
    keys = ("service", "product", "version", "tls_version", "subject_cn", "self_signed", "nla_required",
            "http_server")
    return {k: service[k] for k in keys if k in service}


def _net006_remote_admin(ctx: _HostContext) -> None:
    exposed = _open_services(ctx, REMOTE_ADMIN)
    for s in exposed:
        label, port = REMOTE_ADMIN[s["port"]], s["port"]
        ctx.emit("NET-006", "WARNING", subject=f"tcp:{port}", severity="Medium",
                 summary=f"{label} remote administration is reachable on {ctx.ip}:{port}; restrict it to "
                         "management networks", **_service_details(s))
    if not exposed:
        ctx.emit("NET-006", "PASS", subject="remote-admin",
                 summary=f"No remote administration service (SSH, RDP, WinRM, VNC) reachable on {ctx.ip}")


def _net007_cleartext(ctx: _HostContext) -> None:
    exposed = _open_services(ctx, CLEARTEXT)
    for s in exposed:
        label, severity = CLEARTEXT[s["port"]]
        ctx.emit("NET-007", "FAIL", subject=f"tcp:{s['port']}", severity=severity,
                 summary=f"{label} on {ctx.ip}:{s['port']} transmits credentials and data in clear text",
                 **_service_details(s))
    if not exposed:
        ctx.emit("NET-007", "PASS", subject="cleartext",
                 summary=f"No cleartext legacy protocol (FTP, Telnet, r-services) reachable on {ctx.ip}")


def _net008_data_stores(ctx: _HostContext) -> None:
    exposed = _open_services(ctx, DATA_STORES)
    for s in exposed:
        label = DATA_STORES[s["port"]]
        ctx.emit("NET-008", "WARNING", subject=f"tcp:{s['port']}", severity="Medium",
                 summary=f"{label} is reachable on {ctx.ip}:{s['port']}; data stores should only accept "
                         "connections from their application tier", **_service_details(s))
    if not exposed:
        ctx.emit("NET-008", "PASS", subject="data-stores",
                 summary=f"No database or cache service reachable on {ctx.ip}")


def _net009_control_planes(ctx: _HostContext) -> None:
    exposed = _open_services(ctx, CONTROL_PLANES)
    for s in exposed:
        label, port = CONTROL_PLANES[s["port"]], s["port"]
        unencrypted = port == 2375 or (port == 2379 and not s.get("tls_version"))
        if unencrypted:
            ctx.emit("NET-009", "FAIL", subject=f"tcp:{port}", severity="High",
                     summary=f"{label} on {ctx.ip}:{port} is reachable without TLS; such endpoints commonly "
                             "grant full control of the host or cluster", **_service_details(s))
        else:
            ctx.emit("NET-009", "WARNING", subject=f"tcp:{port}", severity="Medium",
                     summary=f"{label} is reachable on {ctx.ip}:{port}; restrict it to administrators' networks",
                     **_service_details(s))
    if not exposed:
        ctx.emit("NET-009", "PASS", subject="control-planes",
                 summary=f"No container or orchestration control plane reachable on {ctx.ip}")


# WIN controls only report on hosts that expose the service; no observation means "not applicable".

def _win001_smb_signing(ctx: _HostContext) -> None:
    probe = ctx.host["probes"].get("smb_negotiate") or {}
    smb2, smb1 = probe.get("smb2") or {}, probe.get("smb1") or {}
    if "signing_required" in smb2:
        required, dialect = smb2["signing_required"], smb2.get("dialect")
    elif smb1.get("accepted") and "signing_required" in smb1:
        required, dialect = smb1["signing_required"], "NT LM 0.12"
    else:
        return
    if required:
        ctx.emit("WIN-001", "PASS", subject="smb:445",
                 summary=f"SMB on {ctx.ip} requires message signing", dialect=dialect)
    else:
        ctx.emit("WIN-001", "FAIL", subject="smb:445", severity="High",
                 summary=f"SMB on {ctx.ip} does not require message signing; relayed authentication "
                         "would be accepted", dialect=dialect, signing_enabled=smb2.get("signing_enabled"))


def _win002_smbv1(ctx: _HostContext) -> None:
    probe = ctx.host["probes"].get("smb_negotiate") or {}
    if not probe.get("open") or probe.get("smb1") is None:
        return
    if probe["smb1"].get("accepted"):
        ctx.emit("WIN-002", "FAIL", subject="smb:445", severity="High",
                 summary=f"SMB on {ctx.ip} accepts the SMBv1 dialect (NT LM 0.12)")
    else:
        ctx.emit("WIN-002", "PASS", subject="smb:445",
                 summary=f"SMB on {ctx.ip} rejected an SMBv1-only negotiation",
                 smb2_dialect=(probe.get("smb2") or {}).get("dialect"))


def _win006_rdp_nla(ctx: _HostContext) -> None:
    for s in _open_services(ctx, {3389}):
        if s.get("nla_required") is True:
            ctx.emit("WIN-006", "PASS", subject="tcp:3389",
                     summary=f"RDP on {ctx.ip} requires Network Level Authentication")
        elif s.get("nla_required") is False:
            legacy = " and still offers legacy RDP security" if s.get("legacy_rdp_security") else ""
            ctx.emit("WIN-006", "FAIL", subject="tcp:3389", severity="Medium",
                     summary=f"RDP on {ctx.ip} accepts connections without Network Level Authentication{legacy}",
                     **_service_details(s))


def _win008_winrm(ctx: _HostContext) -> None:
    listeners = {s["port"]: s for s in _open_services(ctx, {5985, 5986})}
    if 5985 in listeners:
        ctx.emit("WIN-008", "FAIL", subject="tcp:5985", severity="Medium",
                 summary=f"WinRM HTTP listener (5985) is reachable on {ctx.ip}; use HTTPS listeners only",
                 **_service_details(listeners[5985]))
    elif 5986 in listeners:
        ctx.emit("WIN-008", "PASS", subject="tcp:5985",
                 summary=f"WinRM on {ctx.ip} is reachable over HTTPS (5986) only")


def _web_results(ctx: _HostContext) -> list[dict] | None:
    probe = ctx.host["probes"].get("web")
    return None if probe is None else [r for r in probe.get("services") or [] if "root" in r]


def _web_report(ctx: _HostContext, control_id: str, port: int, failures: list[tuple[str, str]],
                warnings: list[tuple[str, str]], ok: str, **details) -> None:
    order = {"Low": 0, "Medium": 1, "High": 2}
    subject = f"web:{port}"
    if failures or warnings:
        items = failures or warnings
        severity = max((s for _, s in items), key=order.__getitem__)
        ctx.emit(control_id, "FAIL" if failures else "WARNING", subject=subject, severity=severity,
                 summary=f"Web server {ctx.ip}:{port}: {'; '.join(t for t, _ in failures + warnings)}", **details)
    else:
        ctx.emit(control_id, "PASS", subject=subject, summary=f"Web server {ctx.ip}:{port}: {ok}", **details)


def _net010_headers(ctx: _HostContext) -> None:
    results = _web_results(ctx)
    if results is None:
        return
    pages = [r for r in results if r["root"].get("html")]
    for r in pages:
        root, warnings = r["root"], []
        if r["tls"] and not root.get("hsts"):
            warnings.append(("no Strict-Transport-Security header", "Low"))
        if not root.get("nosniff"):
            warnings.append(("no X-Content-Type-Options: nosniff", "Low"))
        if not root.get("frame_protection"):
            warnings.append(("no clickjacking protection (X-Frame-Options or CSP frame-ancestors)", "Low"))
        if re.search(r"\d", root.get("server") or ""):
            warnings.append((f"Server header discloses the version ({root['server']})", "Low"))
        _web_report(ctx, "NET-010", r["port"], [], warnings, "security headers are set",
                    server=root.get("server"), hsts=root.get("hsts"), nosniff=root.get("nosniff"),
                    frame_protection=root.get("frame_protection"), csp=root.get("csp"))
    if not pages:
        ctx.emit("NET-010", "PASS", subject="web", summary=f"No HTML web pages observed on {ctx.ip}")


def _web_unassessed(host: dict, selected: list[str]) -> list[str]:
    """Web controls stay unresolved on a host where a web service could not be fetched."""
    probe = host["probes"].get("web")
    if probe is None or all("root" in r for r in probe.get("services") or []):
        return []
    return [c for c in WEB_CONTROLS if c in selected]


EXPOSURE = {
    "git_repository": ("Git repository metadata is downloadable (/.git/)", "High", True),
    "phpinfo": ("phpinfo() page is public", "Medium", True),
    "server_status": ("server status page is public", "Medium", True),
    "server_info": ("Apache server-info page is public", "Medium", True),
    "tomcat_manager": ("Tomcat Manager console is reachable", "Medium", False),
    "spring_actuator": ("Spring Boot actuator endpoints are public", "Medium", False),
}


def _net011_exposure(ctx: _HostContext) -> None:
    results = _web_results(ctx)
    if results is None:
        return
    for r in results:
        failures, warnings = [], []
        if r["root"].get("directory_listing"):
            failures.append(("directory listing is enabled at /", "Medium"))
        for item in r.get("exposed") or []:
            text, severity, is_failure = EXPOSURE[item["indicator"]]
            (failures if is_failure else warnings).append((text, severity))
        if r["root"].get("default_page"):
            warnings.append((f"{r['root']['default_page']} is served", "Low"))
        _web_report(ctx, "NET-011", r["port"], failures, warnings, "no common sensitive content is exposed",
                    exposed=r.get("exposed") or [], title=r["root"].get("title"))
    if not results:
        ctx.emit("NET-011", "PASS", subject="web", summary=f"No web services observed on {ctx.ip}")


CERT_EXPIRY_WARNING_DAYS = 30


def _net012_transport(ctx: _HostContext) -> None:
    results = _web_results(ctx)
    if results is None:
        return
    for r in results:
        root, failures, warnings = r["root"], [], []
        if not r["tls"]:
            if root.get("password_form"):
                failures.append(("login form served over cleartext HTTP", "High"))
            elif not root.get("redirect_to_https") and root.get("status", 500) < 400:
                warnings.append(("content served over cleartext HTTP without redirecting to HTTPS", "Medium"))
        else:
            cert = r.get("certificate") or {}
            not_after = cert.get("not_after")
            days = (datetime.fromisoformat(not_after) - ctx.now).days if not_after else None
            if cert.get("expired") or (days is not None and days < 0):
                failures.append(("TLS certificate has expired", "High"))
            elif days is not None and days <= CERT_EXPIRY_WARNING_DAYS:
                warnings.append((f"TLS certificate expires in {days} days", "Medium"))
            if cert.get("self_signed"):
                warnings.append(("TLS certificate is self-signed", "Low"))
        _web_report(ctx, "NET-012", r["port"], failures, warnings,
                    "served over HTTPS with a valid certificate" if r["tls"] else "redirects to HTTPS",
                    tls=r["tls"], certificate=r.get("certificate"), redirect_to_https=root.get("redirect_to_https"))
    if not results:
        ctx.emit("NET-012", "PASS", subject="web", summary=f"No web services observed on {ctx.ip}")


EVALUATORS: dict[str, Callable[[_HostContext], None]] = {
    "NET-001": _net001_dns_axfr,
    "NET-002": _net002_tls,
    "NET-003": _net003_smb,
    "NET-004": _net004_snmp,
    "NET-005": _net005_ntp,
    "NET-006": _net006_remote_admin,
    "NET-007": _net007_cleartext,
    "NET-008": _net008_data_stores,
    "NET-009": _net009_control_planes,
    "NET-010": _net010_headers,
    "NET-011": _net011_exposure,
    "NET-012": _net012_transport,
    "WIN-001": _win001_smb_signing,
    "WIN-002": _win002_smbv1,
    "WIN-006": _win006_rdp_nla,
    "WIN-008": _win008_winrm,
    "WIN-003": win_host.win003_ntlm,
    "WIN-004": win_host.win004_ldap_signing,
    "WIN-005": win_host.win005_channel_binding,
    "LIN-001": linux_host.lin001_sshd,
    "LIN-002": linux_host.lin002_updates,
    "LIN-004": linux_host.lin004_firewall,
    "LIN-005": linux_host.lin005_accounts,
    "LIN-006": linux_host.lin006_kernel,
    "LIN-007": linux_host.lin007_file_permissions,
}


def discovered_assets(hosts: list[dict]) -> list[dict]:
    assets = []
    for host in hosts:
        ip = host["ip"]
        windows, linux = win_host.asset_details(host), linux_host.asset_details(host)
        details = windows or linux
        assets.append({
            "asset_id": asset_id_for_ip(ip),
            "hostname": details.get("hostname") or ip,
            "fqdn": details.get("fqdn"),
            "asset_type": details.get("asset_type", "NetworkDevice"),
            "os_family": details.get("os_family"),
            "os_version": details.get("os_version"),
            "domain": details.get("domain"),
            "tags": ["net:scanned"] + (["winrm:assessed"] if windows else []) + (["ssh:assessed"] if linux else []),
            "identifiers": [{"id_type": "ip", "value": ip}],
        })
    return assets


def evaluate(snapshot: dict, control_ids: list[str] | None, now: datetime, *,
             local_admins_allowed: list[str] | None = None,
             linux_admins_allowed: list[str] | None = None) -> Evaluation:
    selected = [c for c in NETWORK_RUN_CONTROLS if control_ids is None or c in control_ids]
    evaluators: dict[str, Callable[[_HostContext], None]] = {
        **EVALUATORS,
        "WIN-007": lambda ctx: win_host.win007_local_admins(ctx, local_admins_allowed or []),
        "WIN-009": lambda ctx: win_host.win009_endpoint_protection(ctx, now),
        "LIN-003": lambda ctx: linux_host.lin003_privileged(ctx, linux_admins_allowed or []),
        "LIN-008": lambda ctx: linux_host.lin008_lifecycle(ctx, now),
    }
    observations: list[ImportRow] = []
    unassessed: dict[str, list[str]] = {}
    for host in snapshot.get("hosts") or []:
        ctx = _HostContext(host, now)
        for control_id in selected:
            if control_id in PORT_SCAN_CONTROLS and "ports" not in host["probes"]:
                continue
            if control_id in win_host.WINRM_CONTROLS and "windows" not in host["probes"]:
                continue
            if control_id in linux_host.LINUX_CONTROLS and "linux" not in host["probes"]:
                continue
            evaluators[control_id](ctx)
        observations.extend(ctx.rows)
        if skipped := (win_host.unassessed(host, selected) + linux_host.unassessed(host, selected)
                       + _web_unassessed(host, selected)):
            unassessed[host["ip"]] = skipped
    return Evaluation(observations=observations, assets=discovered_assets(snapshot.get("hosts") or []),
                      evaluated_controls=selected, unassessed=unassessed)
