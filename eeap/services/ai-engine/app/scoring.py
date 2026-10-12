"""Deterministic, explainable risk scoring (docs/architecture/08-risk-scoring-model.md, ADR-0010).

Pure functions only: inputs in, score + factor breakdown out. Weights come from ai.scoring_models.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

FACTOR_KEYS = {"S": "severity", "C": "asset_criticality", "E": "exploitability",
               "B": "exposure_breadth", "P": "privilege_impact", "R": "propagation", "X": "network_exposure"}
DEFAULT_CRITICALITY = "Medium"
DEFAULT_EXPOSURE_UNKNOWN = 0.3
ASSET_TOP_N = 10
ASSET_CAP_ABOVE_MAX = 15

# Service classes that widen a host's attack surface, by well-known port (service names are a fallback
# for extra ports). Each class adds its weight once; see docs/architecture/08-risk-scoring-model.md.
EXPOSURE_CLASSES: dict[str, tuple[float, frozenset[int], frozenset[str]]] = {
    "remote_admin": (0.20, frozenset({22, 3389, 5900, 5985, 5986}),
                     frozenset({"ssh", "rdp", "vnc", "winrm", "winrm-https"})),
    "file_sharing": (0.15, frozenset({21, 111, 135, 139, 445, 873, 2049}),
                     frozenset({"ftp", "rpcbind", "msrpc", "netbios-ssn", "smb", "rsync", "nfs"})),
    "data_store": (0.25, frozenset({1433, 1521, 2379, 3306, 5432, 5984, 6379, 9200, 9300, 11211, 27017}),
                   frozenset({"mssql", "oracle", "etcd", "mysql", "postgresql", "couchdb", "redis",
                              "elasticsearch", "elasticsearch-transport", "memcached", "mongodb"})),
    "control_plane": (0.30, frozenset({2375, 2376, 6443, 10250, 15672}),
                      frozenset({"docker", "docker-tls", "kubernetes-api", "kubelet", "rabbitmq-management"})),
    "directory": (0.10, frozenset({88, 389, 464, 636, 3268, 3269}),
                  frozenset({"kerberos", "ldap", "kpasswd", "ldaps", "globalcatalog", "globalcatalog-tls"})),
    "cleartext_login": (0.15, frozenset({21, 23, 512, 513, 514}),
                        frozenset({"ftp", "telnet", "rexec", "rlogin", "rsh"})),
}
EXPOSURE_BASE = 0.20
EXPOSURE_PER_EXTRA_SERVICE = 0.05
EXPOSURE_EXTRA_SERVICES_CAP = 4
# Suggested asset criticality from exposed service classes (never lowers a classification).
SUGGESTED_CRITICALITY = (({"control_plane", "data_store", "directory"}, "High"),
                         ({"remote_admin", "file_sharing"}, "Medium"))


@dataclass(frozen=True)
class ScoringModel:
    version: str
    weights: dict[str, Any]

    @property
    def factor_weights(self) -> dict[str, float]:
        fw = self.weights["factor_weights"]
        return {symbol: float(fw[name]) for symbol, name in FACTOR_KEYS.items() if name in fw}

    def rating(self, score: int) -> str:
        bands = sorted(self.weights["bands"].items(), key=lambda kv: kv[1], reverse=True)
        return next(name for name, lower in bands if score >= lower)


@dataclass(frozen=True)
class FindingInputs:
    severity: str
    status: str
    lifecycle_state: str
    criticality: str | None
    exploitability: float
    privilege_impact: float
    affected_count: int
    propagation: float | None = None
    is_tier0: bool = False
    known_exploited: bool = False
    services: list[dict] | None = None  # open services of the asset; None when it was never port scanned


@dataclass(frozen=True)
class ScoreResult:
    score: int
    rating: str
    factors: dict[str, Any]


def round_half_up(value: float) -> int:
    return int(math.floor(value + 0.5))


def breadth(affected_count: int, reference: int) -> float:
    if affected_count <= 0:
        return 0.0
    return min(1.0, math.log10(1 + affected_count) / math.log10(1 + reference))


def service_classes(services: list[dict]) -> list[str]:
    found = []
    for name, (_, ports, names) in EXPOSURE_CLASSES.items():
        if any(s.get("port") in ports or s.get("service") in names for s in services):
            found.append(name)
    return found


def network_exposure(services: list[dict]) -> tuple[float, list[str]]:
    """0 for a scanned host without open services; grows with service count and sensitive service classes."""
    if not services:
        return 0.0, []
    classes = service_classes(services)
    extra = min(len(services) - 1, EXPOSURE_EXTRA_SERVICES_CAP) * EXPOSURE_PER_EXTRA_SERVICE
    value = EXPOSURE_BASE + extra + sum(EXPOSURE_CLASSES[c][0] for c in classes)
    return round(min(1.0, value), 3), classes


def suggested_criticality(services: list[dict]) -> str | None:
    classes = set(service_classes(services))
    return next((level for wanted, level in SUGGESTED_CRITICALITY if classes & wanted), None)


def score_finding(model: ScoringModel, inputs: FindingInputs) -> ScoreResult:
    w = model.weights
    criticality = inputs.criticality or DEFAULT_CRITICALITY
    privilege = max(inputs.privilege_impact, 1.0 if inputs.is_tier0 else 0.0)
    weights = model.factor_weights
    normalized = {
        "S": float(w["severity_values"][inputs.severity]),
        "C": float(w["criticality_values"][criticality]),
        "E": float(inputs.exploitability),
        "B": round(breadth(inputs.affected_count, int(w["breadth_reference_count"])), 3),
        "P": float(privilege),
        "R": float(inputs.propagation or 0.0),
    }
    exposure_inputs: dict[str, Any] = {}
    if "X" in weights:
        if inputs.services is None:
            normalized["X"] = float(w.get("exposure_unknown", DEFAULT_EXPOSURE_UNKNOWN))
            exposure_inputs = {"exposure_source": "not_scanned"}
        else:
            normalized["X"], classes = network_exposure(inputs.services)
            exposure_inputs = {"exposure_source": "port_scan", "open_services": len(inputs.services),
                               "exposed_classes": classes}
    base = sum(weights[k] * normalized[k] for k in weights)
    gate = float(w["status_multipliers"][inputs.status]) * float(w["lifecycle_multipliers"][inputs.lifecycle_state])
    raw = 100.0 * base * gate
    floors = {"severity": w.get("severity_floor", {}).get(inputs.severity),
              "known_exploited": w.get("known_exploited_floor") if inputs.known_exploited else None}
    floor_name, floor = max(((n, f) for n, f in floors.items() if f is not None), key=lambda nf: nf[1],
                            default=(None, None))
    floor_applied = gate > 0 and floor is not None and raw < floor
    score = max(0, min(100, round_half_up(float(floor) if floor_applied else raw)))
    return ScoreResult(score, model.rating(score), {
        "inputs": {"severity": inputs.severity, "criticality": criticality,
                   "asset_known": inputs.criticality is not None, "exploitability": inputs.exploitability,
                   "known_exploited": inputs.known_exploited,
                   "affected_count": inputs.affected_count, "privilege_impact": inputs.privilege_impact,
                   "is_tier0": inputs.is_tier0, "propagation": inputs.propagation,
                   "propagation_source": "graph" if inputs.propagation is not None else "not_available",
                   **exposure_inputs,
                   "status": inputs.status, "lifecycle_state": inputs.lifecycle_state},
        "normalized": normalized,
        "weights": weights,
        "gate": round(gate, 4),
        "floor_applied": floor_applied,
        **({"floor": floor_name} if floor_applied else {}),
        "raw": round(raw, 2),
    })


def score_asset(model: ScoringModel, finding_scores: list[int]) -> ScoreResult:
    """Noisy-OR over the top open finding scores, capped one band step above the worst finding."""
    top = sorted((s for s in finding_scores if s > 0), reverse=True)[:ASSET_TOP_N]
    if not top:
        return ScoreResult(0, model.rating(0), {"top_scores": [], "combined": 0.0, "cap": 0, "contributing": 0})
    combined = 100.0 * (1.0 - math.prod(1.0 - s / 100.0 for s in top))
    cap = min(100, top[0] + ASSET_CAP_ABOVE_MAX)
    score = min(round_half_up(combined), cap)
    return ScoreResult(score, model.rating(score), {
        "top_scores": top, "combined": round(combined, 2), "cap": cap, "contributing": len(top),
        "open_findings": sum(1 for s in finding_scores if s > 0)})


def weighted_percentile(values: list[tuple[float, float]], q: float) -> float:
    """values = [(value, weight)]; smallest value whose cumulative weight reaches q of the total."""
    items = sorted((v, w) for v, w in values if w > 0)
    total = sum(w for _, w in items)
    if total == 0:
        return 0.0
    cumulative = 0.0
    for value, weight in items:
        cumulative += weight
        if cumulative >= q * total - 1e-9:
            return value
    return items[-1][0]


@dataclass(frozen=True)
class AssetScore:
    asset_id: str
    score: int
    criticality: str | None
    tier: str | None


def score_organization(model: ScoringModel, assets: list[AssetScore], max_scenario_score: int) -> ScoreResult:
    crit_values = model.weights["criticality_values"]
    p90 = weighted_percentile(
        [(a.score, float(crit_values[a.criticality or DEFAULT_CRITICALITY])) for a in assets], 0.9)
    tier0 = [a for a in assets if a.tier == "Tier0"]
    high_band = int(model.weights["bands"]["High"])
    tier0_ratio = (sum(1 for a in tier0 if a.score >= high_band) / len(tier0)) if tier0 else 0.0
    raw = 0.5 * p90 + 0.3 * max_scenario_score + 0.2 * tier0_ratio * 100
    score = max(0, min(100, round_half_up(raw)))
    return ScoreResult(score, model.rating(score), {
        "asset_p90_weighted": round(p90, 2), "max_scenario_score": max_scenario_score,
        "tier0_assets": len(tier0), "tier0_exposed": sum(1 for a in tier0 if a.score >= high_band),
        "tier0_exposure_ratio": round(tier0_ratio, 4), "assets_scored": len(assets),
        "weights": {"asset_p90": 0.5, "scenario_max": 0.3, "tier0_exposure": 0.2}, "raw": round(raw, 2)})
