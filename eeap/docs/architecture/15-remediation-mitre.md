# 15 — Remediation Roadmap and MITRE ATT&CK Mapping

The AI Engine turns open risk into an ordered list of work items ("what do we fix first") and
shows which ATT&CK techniques the open weaknesses may enable. Both are deterministic: templates
and the mapping are static reference data (migration `ai_0005`), and the roadmap is recomputed
with correlation ([doc 14](14-correlation.md)). Nothing here performs or automates an attack;
technique references are defensive context only (ADR-0011).

## Reference data

| Table | Content |
|-------|---------|
| `ai.mitre_techniques` | 19 ATT&CK Enterprise v16 techniques (id, name, tactics, URL) |
| `ai.control_technique_map` | control → technique with a one-line rationale (AD, NET and WIN controls) |
| `ai.remediation_templates` | control → title, guidance and effort (`Low` / `Medium` / `High`) |

## Roadmap items

One `template` item per control with open risk (gating finding with score > 0). For a control `c`:

```
finding_risk  = Σ scores of c's open findings
scenario_risk = Σ scores of active scenarios that no longer match when c's findings are removed
                (correlation is re-evaluated without them)
expected_risk_reduction = round(100 × (finding_risk + scenario_risk) / total_open_risk)
total_open_risk = Σ open finding scores + Σ active scenario scores
```

| Phase | Condition |
|-------|-----------|
| `Immediate` | a finding ≥ 90, or the fix breaks a scenario ≥ 90 |
| `Short-term` | a finding ≥ 70, or the fix breaks any active scenario |
| `Medium-term` | a finding ≥ 40 |
| `Long-term` | otherwise |

Priority orders items by phase, then by removed risk per effort weight (Low 1, Medium 2, High 3).
`rationale` stores the breakdown (finding and scenario risk, broken scenarios, effort weight).

Lifecycle: `proposed` → `accepted` / `rejected` / `done` (`PATCH /risk/remediation/{id}`,
`risk:manage`). Recalculation keeps the user's status, sets items whose control has no open risk
to `done` (except `rejected`) and reopens `done` items as `proposed` if the risk returns. Statuses
do not change scores; findings close only through a new assessment.

## MITRE view

`GET /risk/mitre` aggregates open, scored findings per mapped technique (open findings, top score,
controls) and per tactic. Techniques without open findings are omitted.

## API (`risk:read`)

`GET /risk/remediation?status=proposed&status=accepted` (default), `PATCH /risk/remediation/{id}`,
`GET /risk/mitre`. The dashboard shows the roadmap and the ATT&CK exposure table.

## Next steps

- Executive and technical reports with the roadmap and ATT&CK view: see [doc 16](16-reporting.md).
- Optional LLM narratives, labelled advisory and never affecting scores (ADR-0010).
