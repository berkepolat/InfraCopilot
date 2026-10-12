"""Deterministic correlation of open findings and graph facts into risk scenarios (ADR-0010, doc 14).

Pure functions only. A rule definition (ai.correlation_rules.definition) looks like:

    {"scope": "subject" | "organization",
     "match": "all_stages" | {"min_stages": 3},
     "stages": [
        {"order": 1, "name": "...", "any_failed_controls": ["AD-002", "AD-003"]},
        {"order": 2, "name": "...", "graph": {"tier0_reachable": true, "max_hops": 1}},
        {"order": 3, "name": "...", "derived": true}],
     "scenario_title": "... {subject} ...",
     "summary": "... {subject} ..."}

A stage with controls matches open findings of those controls; a `graph` condition additionally
requires the finding's subject (or, for graph-only stages in subject scope, the scope subject) to
satisfy it. Derived stages carry no evidence and hold when the scenario matches.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

STAGE_BONUS = 5
_CN = re.compile(r"^CN=((?:\\,|[^,])+)", re.IGNORECASE)


@dataclass(frozen=True)
class FindingFact:
    finding_id: str
    control_id: str
    asset_id: str
    subject_key: str
    score: int


@dataclass(frozen=True)
class GraphFact:
    propagation_score: float
    tier0_reachable: bool
    min_hops: int | None
    is_tier0: bool
    is_privileged: bool


@dataclass
class StageResult:
    order: int
    name: str
    matched: bool
    finding_ids: list[str] = field(default_factory=list)
    derived: bool = False
    graph_evidence: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result = {"order": self.order, "name": self.name, "matched": self.matched, "finding_ids": self.finding_ids}
        if self.derived:
            result["derived"] = True
        if self.graph_evidence:
            result["graph"] = self.graph_evidence
        return result


@dataclass
class Scenario:
    rule_id: str
    scope_key: str
    title: str
    summary: str
    stages: list[StageResult]
    affected_asset_ids: list[str]
    score: int
    factors: dict[str, Any]

    @property
    def finding_stages(self) -> dict[str, int]:
        """finding_id -> first stage it supports (ai.scenario_findings)."""
        out: dict[str, int] = {}
        for stage in self.stages:
            for finding_id in stage.finding_ids:
                out.setdefault(finding_id, stage.order)
        return out


def subject_label(subject_key: str) -> str:
    match = _CN.match(subject_key or "")
    return match.group(1).replace("\\,", ",") if match else (subject_key or "organization")


def graph_condition_holds(condition: dict | None, fact: GraphFact | None) -> bool:
    if not condition:
        return True
    if fact is None:
        return False
    if condition.get("privileged") and not (fact.is_privileged or fact.is_tier0):
        return False
    if condition.get("tier0_reachable"):
        if not fact.tier0_reachable or fact.min_hops is None:
            return False
        if fact.is_tier0 and not condition.get("include_tier0", False):
            return False  # the condition is about a path *into* Tier 0
        if "max_hops" in condition and fact.min_hops > int(condition["max_hops"]):
            return False
    return True


def _graph_evidence(fact: GraphFact | None) -> dict[str, Any] | None:
    if fact is None:
        return None
    return {"tier0_reachable": fact.tier0_reachable, "min_hops": fact.min_hops,
            "propagation_score": fact.propagation_score, "is_tier0": fact.is_tier0,
            "is_privileged": fact.is_privileged}


def _rule_matches(definition: dict, evidence_defs: list[dict], results: dict[int, StageResult]) -> bool:
    if any(s.get("required") and not results[s["order"]].matched for s in evidence_defs):
        return False
    matched = sum(1 for s in evidence_defs if results[s["order"]].matched)
    match = definition.get("match", "all_stages")
    if match == "all_stages":
        return matched == len(evidence_defs)
    return matched >= int(match.get("min_stages", len(evidence_defs)))


def _render(template: str, **values: Any) -> str:
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template


def _evaluate_group(rule_id: str, definition: dict, scope_key: str, findings: list[FindingFact],
                    graph_of, subject_fact: GraphFact | None, subject: str | None) -> Scenario | None:
    stages = sorted(definition["stages"], key=lambda s: s["order"])
    evidence_defs = [s for s in stages if not s.get("derived")]
    by_control: dict[str, list[FindingFact]] = defaultdict(list)
    for f in findings:
        by_control[f.control_id].append(f)

    results: dict[int, StageResult] = {}
    used: dict[str, FindingFact] = {}
    for stage in evidence_defs:
        condition = stage.get("graph")
        controls = stage.get("any_failed_controls") or []
        if controls:
            hits = [f for c in controls for f in by_control.get(c, [])
                    if graph_condition_holds(condition, graph_of(f))]
            hits.sort(key=lambda f: (-f.score, f.finding_id))
            results[stage["order"]] = StageResult(stage["order"], stage["name"], bool(hits),
                                                  [f.finding_id for f in hits])
            used.update({f.finding_id: f for f in hits})
        else:
            holds = subject is not None and condition is not None and graph_condition_holds(condition, subject_fact)
            results[stage["order"]] = StageResult(stage["order"], stage["name"], holds,
                                                  graph_evidence=_graph_evidence(subject_fact) if holds else None)

    matched = sum(1 for s in evidence_defs if results[s["order"]].matched)
    if matched == 0 or not _rule_matches(definition, evidence_defs, results):
        return None
    for stage in stages:
        if stage.get("derived"):
            results[stage["order"]] = StageResult(stage["order"], stage["name"], True, derived=True)

    max_finding = max((f.score for f in used.values()), default=0)
    if max_finding <= 0:
        return None
    score = min(100, max_finding + STAGE_BONUS * (matched - 1))
    label = subject_label(subject) if subject else "organization"
    values = {"subject": label, "stages": matched, "findings": len(used)}
    return Scenario(
        rule_id=rule_id, scope_key=scope_key,
        title=_render(definition.get("scenario_title", rule_id), **values),
        summary=_render(definition.get("summary", ""), **values),
        stages=[results[s["order"]] for s in stages],
        affected_asset_ids=sorted({f.asset_id for f in used.values()}),
        score=score,
        factors={"max_stage_finding_score": max_finding, "stages_matched": matched,
                 "evidence_stages": len(evidence_defs), "stage_bonus": STAGE_BONUS * (matched - 1),
                 "findings": len(used), "formula": "max(stage finding scores) + 5 x (stages_matched - 1)"},
    )


def evaluate(rules: dict[str, dict], findings: list[FindingFact], graph_of, subject_graph) -> list[Scenario]:
    """rules: rule_id -> definition; graph_of(finding) and subject_graph(subject_key) return GraphFact | None."""
    scenarios: list[Scenario] = []
    for rule_id, definition in sorted(rules.items()):
        controls = {c for s in definition["stages"] for c in s.get("any_failed_controls") or []}
        relevant = [f for f in findings if f.control_id in controls]
        if definition.get("scope", "organization") == "subject":
            groups: dict[str, list[FindingFact]] = defaultdict(list)
            for f in relevant:
                if f.subject_key:
                    groups[f.subject_key].append(f)
            for subject, group in sorted(groups.items()):
                scenario = _evaluate_group(rule_id, definition, f"subject:{subject.lower()}", group, graph_of,
                                           subject_graph(subject), subject)
                if scenario:
                    scenarios.append(scenario)
        else:
            scenario = _evaluate_group(rule_id, definition, "organization", relevant, graph_of, None, None)
            if scenario:
                scenarios.append(scenario)
    return scenarios
