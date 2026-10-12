"""Report rendering: view model from a snapshot, then JSON, HTML (autoescaped Jinja2) and PDF."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

RATINGS = ("Critical", "High", "Medium", "Low")
PHASES = ("Immediate", "Short-term", "Medium-term", "Long-term")
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
CONTENT_TYPES = {"json": "application/json", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}

SECTIONS = {
    "executive_summary": ("overview", "priority_actions", "scenarios", "tactics", "top_assets"),
    "technical": ("overview", "findings", "scenarios", "roadmap"),
    "remediation_roadmap": ("overview", "roadmap"),
    "mitre_mapping": ("overview", "techniques", "tactics", "roadmap"),
}

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(["html", "j2"], default=True), trim_blocks=True,
                   lstrip_blocks=True)


def _merge_findings(data: dict) -> list[dict]:
    scored = {f["finding_id"]: f for f in (data.get("top_findings") or {}).get("items", [])}
    hostnames = {f["asset_id"]: f.get("hostname") for f in scored.values()}
    source = data.get("findings")
    if source is None:
        source = list(scored.values())
    merged = []
    for finding in source:
        score = scored.get(finding["finding_id"], {})
        merged.append({**finding, "score": score.get("score", 0), "rating": score.get("rating"),
                       "hostname": finding.get("hostname") or hostnames.get(finding["asset_id"])})
    merged.sort(key=lambda f: (-f["score"], SEVERITY_RANK.get(f.get("severity"), 9), f.get("control_id") or ""))
    return merged


def build_view(report_type: str, meta: dict, snapshot: dict) -> dict[str, Any]:
    data = snapshot["data"]
    summary = data.get("summary") or {}
    by_rating = (summary.get("open_by_rating") or {}).get("finding", {})
    remediation = (data.get("remediation") or {}).get("items", [])
    scenarios = data.get("scenarios") or []
    mitre = data.get("mitre") or {"techniques": [], "tactics": []}
    return {
        "meta": meta,
        "sections": SECTIONS[report_type],
        "omitted": snapshot.get("omitted", []),
        "has_summary": "summary" in data,
        "exposure": summary.get("exposure_score"),
        "finding_ratings": [(r, by_rating.get(r, 0)) for r in RATINGS],
        "open_findings": sum(by_rating.get(r, 0) for r in RATINGS),
        "active_scenarios": summary.get("active_scenarios", len(scenarios)),
        "scenarios": scenarios,
        "has_scenarios": "scenarios" in data,
        "remediation": remediation,
        "has_remediation": "remediation" in data,
        "phases": [(p, [i for i in remediation if i["roadmap_phase"] == p]) for p in PHASES],
        "immediate_actions": sum(1 for i in remediation if i["roadmap_phase"] == "Immediate"),
        "techniques": mitre.get("techniques", []),
        "tactics": mitre.get("tactics", []),
        "has_mitre": "mitre" in data,
        "top_assets": [a for a in (data.get("top_assets") or {}).get("items", []) if a.get("score", 0) > 0],
        "has_top_assets": "top_assets" in data,
        "findings": _merge_findings(data) if report_type == "technical" else [],
        "has_findings": "findings" in data or "top_findings" in data,
    }


def _fmt_dt(value: str | None) -> str:
    if not value:
        return "—"
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo:
        parsed = parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


_env.filters["dt"] = _fmt_dt


def render_json(meta: dict, snapshot: dict) -> bytes:
    return json.dumps({"report": meta, **snapshot}, indent=2, default=str, ensure_ascii=False).encode()


def render_html(report_type: str, meta: dict, snapshot: dict) -> str:
    return _env.get_template("report.html.j2").render(**build_view(report_type, meta, snapshot))


def _no_fetch(url: str, *args, **kwargs):
    raise ValueError(f"external resources are not allowed in reports: {url[:80]}")


def render_pdf(html: str) -> bytes:
    from weasyprint import HTML  # heavy native dependency, only needed by the worker

    return HTML(string=html, url_fetcher=_no_fetch).write_pdf()
