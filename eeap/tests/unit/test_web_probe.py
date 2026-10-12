import asyncio
import importlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
web_probe = importlib.import_module("assessment_app.collectors.web_probe")
net = importlib.import_module("assessment_app.controls.net")

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
HTML = {"content-type": "text/html"}


def test_web_services_skip_apis_and_non_http():
    services = [{"port": 80, "service": "http", "http_status": 200},
                {"port": 5985, "service": "winrm", "http_status": 404},
                {"port": 22, "service": "ssh"},
                {"port": 9200, "service": "elasticsearch", "http_status": 200}]
    assert [s["port"] for s in web_probe.web_services(services)] == [80]


def test_analyze_root_indicators():
    body = (b"<html><head><title>Index of /</title></head><body><h1>Index of /</h1>"
            b"<form><input type='password' name=p></form></body></html>")
    root = web_probe.analyze_root(200, {**HTML, "server": "nginx/1.27.3"}, body, tls=False)
    assert root["html"] and root["directory_listing"] and root["password_form"]
    assert root["title"] == "Index of /" and root["server"] == "nginx/1.27.3"
    assert root["hsts"] is None and not root["nosniff"] and not root["frame_protection"]

    headers = {**HTML, "strict-transport-security": "max-age=1", "x-content-type-options": "nosniff",
               "content-security-policy": "frame-ancestors 'none'"}
    secure = web_probe.analyze_root(200, headers, b"<h1>ok</h1>", tls=True)
    assert secure["hsts"] and secure["nosniff"] and secure["frame_protection"] and secure["csp"]
    assert not secure["directory_listing"] and not secure["password_form"]

    redirect = web_probe.analyze_root(301, {"location": "https://web1/"}, b"", tls=False)
    assert redirect["redirect_to_https"]
    assert web_probe.analyze_root(200, HTML, b"<h1>Welcome to nginx!</h1>", tls=False)["default_page"] == \
        "nginx default page"


@pytest.mark.parametrize(("path", "status", "headers", "body", "expected"), [
    ("/.git/HEAD", 200, {}, b"ref: refs/heads/main\n", True),
    ("/.git/HEAD", 200, HTML, b"<html>soft 404</html>", False),
    ("/server-status", 200, {}, b"Active connections: 1 \nserver accepts handled requests\n", True),
    ("/server-status", 403, {}, b"Forbidden", False),
    ("/phpinfo.php", 200, HTML, b"<title>PHP 8.3.1 - phpinfo()</title>", True),
    ("/manager/html", 401, {"www-authenticate": 'Basic realm="Tomcat Manager Application"'}, b"", True),
    ("/manager/html", 401, {"www-authenticate": 'Basic realm="intranet"'}, b"", False),
    ("/actuator", 200, {}, b'{"_links":{"self":{"href":"http://x/actuator"}}}', True),
])
def test_path_check_matchers(path, status, headers, body, expected):
    assert web_probe.PATH_CHECKS[path][1](status, headers, body) is expected


def test_probe_service_reads_root_and_paths_without_following_redirects():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/":
            return httpx.Response(200, headers={**HTML, "server": "nginx/1.27.3"},
                                  content=b"<title>Index of /</title>" + b"x" * 200_000)
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, content=b"ref: refs/heads/main\n")
        return httpx.Response(302, headers={"location": "/login"})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
            return await web_probe.probe_service(client, "10.0.0.5", {"port": 8080, "http_status": 200})

    result = asyncio.run(scenario())
    assert result["root"]["directory_listing"] and result["tls"] is False
    assert result["exposed"] == [{"indicator": "git_repository", "path": "/.git/HEAD"}]
    assert {r.method for r in requests} == {"GET"}
    assert [r.url.path for r in requests] == ["/", *web_probe.PATH_CHECKS]
    assert all(str(r.url).startswith("http://10.0.0.5:8080/") and not r.url.query for r in requests)


def test_probe_service_records_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await web_probe.probe_service(client, "10.0.0.5", {"port": 443, "tls_version": "TLSv1.3",
                                                                      "self_signed": True})

    result = asyncio.run(scenario())
    assert result == {"port": 443, "tls": True, "error": "ConnectError",
                      "certificate": {"self_signed": True, "not_after": None, "expired": None, "subject_cn": None}}


def _root(**overrides) -> dict:
    root = {"status": 200, "html": True, "server": None, "hsts": None, "nosniff": True, "frame_protection": True,
            "csp": False, "redirect_to_https": False, "directory_listing": False, "password_form": False,
            "default_page": None, "title": None}
    return {**root, **overrides}


def _snapshot(services: list[dict]) -> dict:
    return {"hosts": [{"ip": "10.0.0.5", "collected_at": NOW.isoformat(),
                       "probes": {"ports": {"open": []}, "web": {"services": services}}}]}


def _rows(evaluation) -> dict:
    return {(r.control_id, r.subject_key): (r.status, r.severity) for r in evaluation.observations}


def test_web_controls_classify_findings():
    soon = (NOW + timedelta(days=12)).isoformat()
    services = [
        {"port": 80, "tls": False, "root": _root(server="nginx/1.27.3", nosniff=False, directory_listing=True),
         "exposed": [{"indicator": "git_repository", "path": "/.git/HEAD"},
                     {"indicator": "server_status", "path": "/server-status"}]},
        {"port": 8080, "tls": False, "root": _root(password_form=True), "exposed": []},
        {"port": 443, "tls": True, "root": _root(hsts=True), "exposed": [],
         "certificate": {"self_signed": True, "not_after": soon, "expired": False}},
        {"port": 8443, "tls": True, "root": _root(hsts=False, html=False), "exposed": [],
         "certificate": {"self_signed": False, "not_after": "2026-01-01T00:00:00+00:00", "expired": True}},
        {"port": 8000, "tls": False, "root": _root(status=301, redirect_to_https=True, html=False),
         "exposed": [{"indicator": "tomcat_manager", "path": "/manager/html"}]},
    ]
    evaluation = net.evaluate(_snapshot(services), list(net.WEB_CONTROLS), NOW)
    assert _rows(evaluation) == {
        ("NET-010", "web:80"): ("WARNING", "Low"),
        ("NET-010", "web:8080"): ("PASS", None),
        ("NET-010", "web:443"): ("PASS", None),
        ("NET-011", "web:80"): ("FAIL", "High"),
        ("NET-011", "web:8080"): ("PASS", None),
        ("NET-011", "web:443"): ("PASS", None),
        ("NET-011", "web:8443"): ("PASS", None),
        ("NET-011", "web:8000"): ("WARNING", "Medium"),
        ("NET-012", "web:80"): ("WARNING", "Medium"),
        ("NET-012", "web:8080"): ("FAIL", "High"),
        ("NET-012", "web:443"): ("WARNING", "Medium"),
        ("NET-012", "web:8443"): ("FAIL", "High"),
        ("NET-012", "web:8000"): ("PASS", None),
    }
    assert evaluation.unassessed == {}


def test_web_controls_pass_without_web_services_and_skip_without_probe():
    evaluation = net.evaluate(_snapshot([]), list(net.WEB_CONTROLS), NOW)
    assert {(r.control_id, r.status, r.subject_key) for r in evaluation.observations} == {
        ("NET-010", "PASS", "web"), ("NET-011", "PASS", "web"), ("NET-012", "PASS", "web")}
    no_probe = {"hosts": [{"ip": "10.0.0.5", "collected_at": NOW.isoformat(), "probes": {"ports": {"open": []}}}]}
    assert net.evaluate(no_probe, list(net.WEB_CONTROLS), NOW).observations == []


def test_web_fetch_errors_keep_findings_open():
    evaluation = net.evaluate(_snapshot([{"port": 80, "tls": False, "error": "ReadTimeout"}]),
                              list(net.WEB_CONTROLS), NOW)
    assert evaluation.unassessed == {"10.0.0.5": list(net.WEB_CONTROLS)}


def test_web_probe_is_read_only():
    source = importlib.import_module("inspect").getsource(web_probe)
    assert '"GET"' in source
    for verb in ("POST", "PUT", "DELETE", "PATCH"):
        assert f'"{verb}"' not in source
