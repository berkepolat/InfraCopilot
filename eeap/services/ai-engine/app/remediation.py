"""Deterministic remediation roadmap: one work item per control with open risk (pure; doc 15).

expected_risk_reduction is the share (0-100) of current open risk the item removes: the scores of the
control's open findings plus the scores of active scenarios that would no longer match without them,
over the total of open finding and active scenario scores. Items are ordered by urgency phase, then
by removed risk per unit of effort.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

EFFORT_WEIGHT = {"Low": 1.0, "Medium": 2.0, "High": 3.0}
PHASES = ("Immediate", "Short-term", "Medium-term", "Long-term")
CRITICAL, HIGH, MEDIUM = 90, 70, 40


@dataclass(frozen=True)
class Template:
    title: str
    guidance: str
    effort: str


@dataclass(frozen=True)
class OpenFinding:
    finding_id: str
    control_id: str
    score: int


@dataclass(frozen=True)
class ActiveScenario:
    scenario_id: str
    key: tuple[str, str]
    score: int
    title: str


@dataclass
class RoadmapItem:
    control_id: str
    title: str
    guidance: str
    effort: str
    finding_ids: list[str]
    scenario_ids: list[str]
    expected_risk_reduction: int
    roadmap_phase: str
    priority: int = 0
    rationale: dict[str, Any] = field(default_factory=dict)


def phase_for(max_finding_score: int, broken_scores: list[int]) -> str:
    if max_finding_score >= CRITICAL or any(s >= CRITICAL for s in broken_scores):
        return "Immediate"
    if max_finding_score >= HIGH or broken_scores:
        return "Short-term"
    if max_finding_score >= MEDIUM:
        return "Medium-term"
    return "Long-term"


def build_roadmap(findings: list[OpenFinding], scenarios: list[ActiveScenario], templates: dict[str, Template],
                  still_matching: Callable[[str], set[tuple[str, str]]]) -> list[RoadmapItem]:
    """still_matching(control_id) returns the scenario keys that would still match without that control."""
    by_control: dict[str, list[OpenFinding]] = defaultdict(list)
    for f in findings:
        if f.score > 0:
            by_control[f.control_id].append(f)
    total = sum(f.score for fs in by_control.values() for f in fs) + sum(s.score for s in scenarios)

    items = []
    for control_id, control_findings in by_control.items():
        template = templates.get(control_id) or Template(f"Remediate {control_id}",
                                                         "Apply the control recommendation to the listed findings.",
                                                         "Medium")
        remaining = still_matching(control_id)
        broken = sorted((s for s in scenarios if s.key not in remaining), key=lambda s: -s.score)
        finding_risk = sum(f.score for f in control_findings)
        scenario_risk = sum(s.score for s in broken)
        removed = finding_risk + scenario_risk
        reduction = max(1, round(100 * removed / total)) if total and removed else 0
        max_score = max(f.score for f in control_findings)
        weight = EFFORT_WEIGHT.get(template.effort, 2.0)
        items.append(RoadmapItem(
            control_id=control_id, title=template.title, guidance=template.guidance, effort=template.effort,
            finding_ids=[f.finding_id for f in sorted(control_findings, key=lambda f: (-f.score, f.finding_id))],
            scenario_ids=[s.scenario_id for s in broken],
            expected_risk_reduction=min(100, reduction),
            roadmap_phase=phase_for(max_score, [s.score for s in broken]),
            rationale={"finding_risk": finding_risk, "scenario_risk": scenario_risk, "total_open_risk": total,
                       "max_finding_score": max_score, "open_findings": len(control_findings),
                       "scenarios_broken": [s.title for s in broken], "effort_weight": weight,
                       "value_per_effort": round(removed / weight, 2)},
        ))
    items.sort(key=lambda i: (PHASES.index(i.roadmap_phase), -i.rationale["value_per_effort"], i.control_id))
    for position, item in enumerate(items, start=1):
        item.priority = position
    return items
