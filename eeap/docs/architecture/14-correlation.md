# 14 — Correlation and Risk Scenarios

Correlation turns individual open findings and exposure-graph facts into **risk scenarios**:
ordered chains of weaknesses that are worse together than alone. It is deterministic and
reproducible (ADR-0010); the rules are data in `ai.correlation_rules`, not code.

## When it runs

The AI Engine's recompute loop correlates after finding and asset scores are updated and before
the organization score, whenever findings, assets or graph facts changed (and on start-up). It:

1. loads enabled rules, the open gating findings (FAIL/WARNING; open, acknowledged or in
   remediation) of the controls the rules reference, their current scores, and `ai.graph_facts`;
2. evaluates every rule (`app/correlation.py`, pure);
3. upserts `ai.risk_scenarios` by `(rule_id, scope_key)` and replaces `ai.scenario_findings`;
4. marks active scenarios that no longer match as `mitigated` (score 0);
5. stores scenario scores (`subject_type = 'scenario'`) and publishes `correlation.completed`
   on `eeap.risk` when scenarios appear or are mitigated.

The organization exposure score uses the highest **active** scenario score (doc 08).

## Rule format

```json
{
  "scope": "subject",
  "match": "all_stages",
  "stages": [
    {"order": 1, "name": "Offline-Crackable Credential Exposure", "any_failed_controls": ["AD-002", "AD-003"]},
    {"order": 2, "name": "Tier-0 Reachability", "graph": {"tier0_reachable": true, "max_hops": 1}},
    {"order": 3, "name": "Domain Compromise Exposure", "derived": true}
  ],
  "scenario_title": "Crackable credentials of {subject} lead directly to Tier 0",
  "summary": "..."
}
```

| Key | Meaning |
|-----|---------|
| `scope` | `subject`: one scenario per finding subject (account, computer, …); `organization`: one scenario for all findings |
| `match` | `all_stages`, or `{"min_stages": n}` evidence stages; stages with `"required": true` must always match |
| `any_failed_controls` | the stage matches open findings of these controls |
| `graph` | condition on the graph fact of each matching finding, or — for a stage without controls in subject scope — of the scenario subject: `tier0_reachable` (+ `max_hops`), `privileged`; Tier-0 objects themselves only satisfy `tier0_reachable` with `include_tier0` |
| `derived` | consequence stage without evidence; holds when the scenario matches |
| templates | `{subject}` (CN of a DN, else the subject key), `{stages}`, `{findings}` |

Graph facts are looked up exactly as for scoring: a DN subject uses its directory object, any
other finding the fact of its asset (doc 13).

Scenario score: `max(stage finding scores) + 5 × (evidence stages matched − 1)`, capped at 100.

## Shipped rules

| Rule | Scope | Chain |
|------|-------|-------|
| `CORR-AD-001` | subject | AD-002/AD-003 crackable credentials → Tier 0 within 1 hop → domain compromise exposure |
| `CORR-AD-002` | subject | AD-004/005/006 delegation → Tier 0 within 2 hops → privilege escalation exposure |
| `CORR-AD-003` | organization | ≥ 3 of: AD-001 password policy, AD-002/003 credentials, **AD-007 privileged sprawl (required)**, AD-008 LAPS → increased organizational risk |
| `CORR-AUTH-001` | organization | WIN-001/003/004/005 → AD-002/003 → AD-007 on privileged objects (needs Windows evidence) |

## Lifecycle

| Status | Set by | Counted in organization score |
|--------|--------|-------------------------------|
| `active` | correlation (detected) or user (re-activate) | yes |
| `dismissed` | user (`PATCH /risk/scenarios/{id}`, `risk:manage`); kept while the rule still matches | no |
| `mitigated` | correlation (no longer matches) | no |

A mitigated scenario that matches again becomes active with a new `first_detected_at`.

## API (`risk:read`)

`GET /risk/scenarios?status=active`, `GET /risk/scenarios/{id}` (stages + supporting findings),
`PATCH /risk/scenarios/{id}` (`risk:manage`), and `top_scenarios` in `GET /risk/summary`.
The dashboard lists the top active scenarios with their matched chain.

## Next steps

- Remediation items per scenario (`ai.remediation_items`) and MITRE ATT&CK mapping.
- Optional LLM narratives, labelled advisory and never affecting scores (ADR-0010).
