"""Read-only checks of web services found by the port scan (NET-010 … NET-012) (ADR-0011).

Per web service: ``GET /`` and a fixed list of well-known paths, one request each. GET only, no query
parameters, no form submission, no credentials, redirects are not followed. At most 64 KiB of each body
is read, used for pattern checks and discarded; only indicators are kept in the evidence.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Callable
from typing import Any

COLLECTOR_ID = "net.web_probe"
COLLECTOR_VERSION = "1.0"
USER_AGENT = "EEAP-assessment/1.0 (read-only exposure check)"
MAX_BODY_BYTES = 64 * 1024
# APIs and data stores have their own controls (NET-008, NET-009, WIN-008); they are not web sites.
NON_WEB_SERVICES = {"winrm", "winrm-https", "docker", "docker-tls", "kubernetes-api", "kubelet", "etcd",
                    "elasticsearch", "couchdb", "minio"}

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PASSWORD_INPUT = re.compile(rb"<input[^>]+type\s*=\s*[\"']?password", re.IGNORECASE)
_DIRECTORY_LISTING = (b"<title>Index of /", b"<h1>Index of /", b"Directory listing for /")
DEFAULT_PAGES = {
    b"Welcome to nginx!": "nginx default page",
    b"Apache2 Debian Default Page": "Apache default page",
    b"Apache2 Ubuntu Default Page": "Apache default page",
    b"<html><body><h1>It works!</h1>": "Apache default page",
    b"Test Page for the Apache HTTP Server": "Apache test page",
    b"<title>IIS Windows Server</title>": "IIS default page",
    b"If you're seeing this, you've successfully installed Tomcat": "Tomcat default page",
}


def _manager_realm(status: int, headers: dict, body: bytes) -> bool:
    realm = headers.get("www-authenticate", "")
    return (status == 401 and "Tomcat Manager" in realm) or (status == 200 and b"Tomcat Web Application Manager" in body)


# path -> (indicator, matcher(status, headers, body))
PATH_CHECKS: dict[str, tuple[str, Callable[[int, dict, bytes], bool]]] = {
    "/.git/HEAD": ("git_repository", lambda s, h, b: s == 200 and re.match(rb"^(ref: refs/|[0-9a-f]{40}\s*$)", b) is not None),
    "/server-status": ("server_status", lambda s, h, b: s == 200 and (b"Apache Server Status" in b
                                                                      or b"Active connections:" in b)),
    "/server-info": ("server_info", lambda s, h, b: s == 200 and b"Apache Server Information" in b),
    "/phpinfo.php": ("phpinfo", lambda s, h, b: s == 200 and b"phpinfo()" in b),
    "/manager/html": ("tomcat_manager", _manager_realm),
    "/actuator": ("spring_actuator", lambda s, h, b: s == 200 and b'"_links"' in b and b"actuator" in b),
}


def web_services(open_services: list[dict]) -> list[dict]:
    """Port-scan results that answered HTTP and are web sites rather than management APIs."""
    return [s for s in open_services if "http_status" in s and s.get("service") not in NON_WEB_SERVICES]


def analyze_root(status: int, headers: dict[str, str], body: bytes, *, tls: bool) -> dict[str, Any]:
    content_type = headers.get("content-type", "").lower()
    title = _TITLE.search(body)
    csp = headers.get("content-security-policy", "")
    location = headers.get("location", "")
    result: dict[str, Any] = {
        "status": status,
        "html": "html" in content_type,
        "title": re.sub(rb"\s+", b" ", title.group(1)).decode("utf-8", "replace").strip()[:120] if title else None,
        "server": headers.get("server", "")[:120] or None,
        "hsts": "strict-transport-security" in headers if tls else None,
        "nosniff": headers.get("x-content-type-options", "").lower() == "nosniff",
        "frame_protection": "x-frame-options" in headers or "frame-ancestors" in csp,
        "csp": bool(csp),
        "redirect_to_https": 300 <= status < 400 and location.lower().startswith("https://"),
        "directory_listing": status == 200 and any(marker in body for marker in _DIRECTORY_LISTING),
        "password_form": bool(_PASSWORD_INPUT.search(body)),
        "default_page": next((name for marker, name in DEFAULT_PAGES.items() if marker in body), None),
    }
    return result


def _url(ip: str, port: int, tls: bool, path: str) -> str:
    host = f"[{ip}]" if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address) else ip
    return f"{'https' if tls else 'http'}://{host}:{port}{path}"


async def _get(client, url: str) -> tuple[int, dict[str, str], bytes]:
    async with client.stream("GET", url) as response:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) >= MAX_BODY_BYTES:
                break
        headers = {k.lower(): v for k, v in response.headers.items()}
        return response.status_code, headers, bytes(body[:MAX_BODY_BYTES])


async def probe_service(client, ip: str, service: dict) -> dict[str, Any]:
    port, tls = service["port"], "tls_version" in service
    result: dict[str, Any] = {"port": port, "tls": tls}
    if tls:
        result["certificate"] = {k: service.get(k) for k in ("self_signed", "not_after", "expired", "subject_cn")}
    try:
        status, headers, body = await _get(client, _url(ip, port, tls, "/"))
    except Exception as exc:  # noqa: BLE001 — record and continue with the next service
        return {**result, "error": exc.__class__.__name__}
    result["root"] = analyze_root(status, headers, body, tls=tls)
    exposed = []
    for path, (indicator, matches) in PATH_CHECKS.items():
        try:
            if matches(*await _get(client, _url(ip, port, tls, path))):
                exposed.append({"indicator": indicator, "path": path})
        except Exception:  # noqa: BLE001, S112 — an unreachable path is simply not exposed
            continue
    result["exposed"] = exposed
    return result


async def probe_hosts(services_by_ip: dict[str, list[dict]], *, timeout: float = 5.0,
                      concurrency: int = 20) -> dict[str, dict[str, Any]]:
    """{ip: {"services": [per-port results]}} for every IP (empty list when it has no web service)."""
    import httpx

    limiter = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=False, follow_redirects=False, trust_env=False,
                                 timeout=httpx.Timeout(timeout), headers={"User-Agent": USER_AGENT},
                                 limits=httpx.Limits(max_connections=concurrency)) as client:
        async def one(ip: str, service: dict) -> tuple[str, dict]:
            async with limiter:
                return ip, await probe_service(client, ip, service)

        results = await asyncio.gather(*(one(ip, s) for ip, services in services_by_ip.items()
                                         for s in web_services(services)))
    hosts: dict[str, dict[str, Any]] = {ip: {"collector": COLLECTOR_ID, "version": COLLECTOR_VERSION, "services": []}
                                        for ip in services_by_ip}
    for ip, result in results:
        hosts[ip]["services"].append(result)
    for host in hosts.values():
        host["services"].sort(key=lambda r: r["port"])
    return hosts
