"""IP target parsing and authorization for server-side network assessments (ADR-0011 §6)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


MAX_TARGETS = 256

# Never probe these even when covered by an allow-list (loopback of the worker, metadata, etc.).
_BLOCKED = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


@dataclass(frozen=True)
class TargetError(Exception):
    detail: str

    def __str__(self) -> str:
        return self.detail


def parse_allowed_cidrs(raw: str | None) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for part in (raw or "").split(","):
        token = part.strip()
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            raise TargetError(f"invalid SCAN_ALLOWED_CIDRS entry {token!r}: {exc}") from exc
    return networks


def parse_targets(raw: list[str] | None) -> list[str]:
    """Normalizes a list of IP literals (IPv4/IPv6). Hostnames are rejected (resolve via inventory later)."""
    if not raw:
        raise TargetError("targets must list at least one IP address")
    if len(raw) > MAX_TARGETS:
        raise TargetError(f"at most {MAX_TARGETS} targets per run")
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        token = (item or "").strip()
        if not token:
            raise TargetError("targets contain an empty value")
        if "/" in token:
            raise TargetError(f"{token!r} looks like a CIDR; pass individual IP addresses in targets "
                              "(authorize ranges with SCAN_ALLOWED_CIDRS)")
        try:
            addr = ipaddress.ip_address(token)
        except ValueError as exc:
            raise TargetError(f"not an IP address: {token!r}") from exc
        if any(addr in net for net in _BLOCKED):
            raise TargetError(f"target {addr} is not scannable (loopback, link-local, multicast or unspecified)")
        key = addr.compressed
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    if not out:
        raise TargetError("targets must list at least one IP address")
    return out


def authorize_targets(ips: list[str], allowed_cidrs_raw: str | None) -> list[str]:
    """Ensures every IP is covered by SCAN_ALLOWED_CIDRS (explicit assessment scope)."""
    networks = parse_allowed_cidrs(allowed_cidrs_raw)
    if not networks:
        raise TargetError(
            "network assessments require SCAN_ALLOWED_CIDRS (comma-separated CIDRs the platform may probe)")
    unauthorized = []
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not any(addr in net for net in networks):
            unauthorized.append(ip)
    if unauthorized:
        sample = ", ".join(unauthorized[:5])
        more = f" (+{len(unauthorized) - 5} more)" if len(unauthorized) > 5 else ""
        raise TargetError(f"target(s) outside SCAN_ALLOWED_CIDRS: {sample}{more}")
    return ips


def asset_id_for_ip(ip: str) -> str:
    """Stable business key for a scanned IP (fits ASSET_ID_PATTERN)."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return "IP-" + addr.exploded.replace(".", "-")
    # Compress IPv6 into a hostname-safe token.
    return "IP6-" + addr.compressed.replace(":", "-").replace("--", "z")[:60]
