"""Network run evaluators: NET-001..NET-009 plus the WIN controls observable without credentials.

Pure functions over net_probes / smb_negotiate / port_scan snapshots.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..domain import ImportRow
from ..targets import asset_id_for_ip

SOURCE_TOOL = "eeap-net-probes/1.0"
NET_CONTROL_IDS = tuple(f"NET-{n:03d}" for n in range(1, 10))
# Windows configuration visible on the wire; the remaining WIN controls need host access.
WIN_NETWORK_CONTROLS = ("WIN-001", "WIN-002", "WIN-006", "WIN-008")
NETWORK_RUN_CONTROLS = NET_CONTROL_IDS + WIN_NETWORK_CONTROLS
PORT_SCAN_CONTROLS = ("NET-006", "NET-007", "NET-008", "NET-009", "WIN-006", "WIN-008")

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
    "WIN-001": _win001_smb_signing,
    "WIN-002": _win002_smbv1,
    "WIN-006": _win006_rdp_nla,
    "WIN-008": _win008_winrm,
}


def discovered_assets(hosts: list[dict]) -> list[dict]:
    assets = []
    for host in hosts:
        ip = host["ip"]
        asset_id = asset_id_for_ip(ip)
        assets.append({
            "asset_id": asset_id,
            "hostname": ip,
            "fqdn": None,
            "asset_type": "NetworkDevice",
            "os_family": None,
            "os_version": None,
            "domain": None,
            "tags": ["net:scanned"],
            "identifiers": [{"id_type": "ip", "value": ip}],
        })
    return assets


def evaluate(snapshot: dict, control_ids: list[str] | None, now: datetime) -> Evaluation:
    selected = [c for c in NETWORK_RUN_CONTROLS if control_ids is None or c in control_ids]
    observations: list[ImportRow] = []
    for host in snapshot.get("hosts") or []:
        ctx = _HostContext(host, now)
        for control_id in selected:
            if control_id in PORT_SCAN_CONTROLS and "ports" not in host["probes"]:
                continue
            EVALUATORS[control_id](ctx)
        observations.extend(ctx.rows)
    return Evaluation(observations=observations, assets=discovered_assets(snapshot.get("hosts") or []),
                      evaluated_controls=selected)
