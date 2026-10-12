# 08 — Risk Scoring Model (v1)

The scoring model is **deterministic, versioned and explainable** (ADR-0010). The AI
Engine computes it; LLMs never influence scores. Weights live in `ai.scoring_models`
(`model_version = 'v1'`) so they can be tuned without code changes and every stored score
references the model that produced it.

## 1. Factors (each normalized to 0–1)

| Factor | Symbol | Source | Normalization |
|--------|--------|--------|---------------|
| Finding severity | S | `findings.severity` | Critical 1.0 · High 0.75 · Medium 0.5 · Low 0.25 · Informational 0 |
| Asset criticality | C | `asset.assets.criticality` | Critical 1.0 · High 0.75 · Medium 0.5 · Low 0.25 |
| Exploitability | E | `controls.exploitability` (catalog, 0–1) | As defined per control, reviewed by security engineering |
| Exposure breadth | B | Number of assets/objects affected by the same control failure | `min(1, log10(1+n) / log10(1+N_ref))`, `N_ref = 100` |
| Privilege impact | P | `controls.privilege_impact`, raised to 1.0 if the subject node `is_tier0` or `is_privileged` | max(control value, graph value) |
| Propagation contribution | R | `graph.node_metrics.propagation_score` | 0–1 from Relationship Engine (reachability to Tier 0, hop distance, path count) |

## 2. Finding score

```
base     = 0.30·S + 0.20·C + 0.15·E + 0.10·B + 0.15·P + 0.10·R
gate     = status_multiplier(status) × lifecycle_multiplier(lifecycle_state)
raw      = 100 × base × gate
score    = round( max(raw, severity_floor(severity)) if gate > 0 else raw )   ∈ [0, 100]
```

| Multiplier | Values |
|-----------|--------|
| status | FAIL 1.0 · WARNING 0.6 · INFO 0 · PASS 0 |
| lifecycle | open / acknowledged 1.0 · in_remediation 0.9 · risk_accepted / false_positive / resolved 0 |
| severity floor | Critical findings never score below 70 (High band) while open |

Rating bands (enforced by DB constraint): **Critical 90–100 · High 70–89 · Medium 40–69 · Low 0–39**.

### Worked example

AD-002 service-account exposure on `SQL01` (criticality High), FAIL, open; 12 service
accounts affected; account is member of a privileged group; graph shows it reaches
Tier 0 in 2 hops (`R = 0.8`).

| Factor | Value | Weighted |
|--------|-------|----------|
| S (High) | 0.75 | 0.225 |
| C (High) | 0.75 | 0.150 |
| E | 0.70 | 0.105 |
| B = log10(13)/log10(101) | 0.556 | 0.056 |
| P (privileged → 1.0) | 1.00 | 0.150 |
| R | 0.80 | 0.080 |
| **base** | | **0.766** |

Score = round(100 × 0.766) = **77 → High**.

Stored `factors`:

```json
{
  "inputs": {"severity": "High", "criticality": "High", "exploitability": 0.7,
             "affected_count": 12, "privilege_impact": 1.0, "propagation": 0.8,
             "status": "FAIL", "lifecycle_state": "open"},
  "normalized": {"S": 0.75, "C": 0.75, "E": 0.7, "B": 0.556, "P": 1.0, "R": 0.8},
  "weights": {"S": 0.30, "C": 0.20, "E": 0.15, "B": 0.10, "P": 0.15, "R": 0.10},
  "gate": 1.0, "floor_applied": false, "raw": 76.6
}
```

## 2a. Model v2 (active): exploitation evidence and network exposure

v2 (migration `ai_0010`, ADR-0020) keeps the v1 structure and adds one factor, a second floor and
finding-level exploitability. v1 stays in `ai.scoring_models`; its stored scores remain attributable.

```
base = 0.25·S + 0.20·C + 0.20·E + 0.05·B + 0.10·P + 0.10·R + 0.10·X
```

| Change | Detail |
|--------|--------|
| E per finding | A finding may carry its own exploitability in its evidence, overriding the control value. LIN-009 does: **1.0** if a CVE is in the uploaded CISA KEV catalog, otherwise `0.2 + 0.8 × max EPSS percentile` of its CVEs, **0.5** for CVEs EPSS has not scored, and the control value (0.8) when no EPSS file was uploaded. |
| X network exposure | From the asset's open services (`network.exposure_observed`, sent by every NET run with a port scan). `0` when scanned with nothing open; otherwise `0.20 + 0.05 per additional service (max 4)` plus each exposed class once: control plane 0.30 (Docker, Kubernetes, kubelet, RabbitMQ management), data store 0.25 (databases, Redis, etcd, Elasticsearch …), remote admin 0.20 (SSH, RDP, VNC, WinRM), file sharing 0.15 (SMB, NFS, FTP, RPC …), cleartext login 0.15 (Telnet, FTP, r-services), directory 0.10 (Kerberos, LDAP, GC); capped at 1. Assets never port scanned (e.g. AD objects) use `exposure_unknown` = 0.3. |
| KEV floor | An open, gated finding with a KEV-listed CVE never scores below **80** (`known_exploited_floor`). LIN-009 also raises such findings to at least High severity. |
| B, P | Weights lowered (0.05, 0.10) to make room for E and X. |

The exposed classes also yield a **suggested criticality** (control plane, data store or directory → High;
remote admin or file sharing → Medium), shown on the Assets page next to the editor. It is never applied
automatically; a manual criticality or tier is locked against discovery rules.

`factors.inputs` records `known_exploited`, `exposure_source` (`port_scan` / `not_scanned`),
`open_services` and `exposed_classes`, and `factors.floor` names the floor that was applied; the Risks
page turns these into "why" labels.

## 3. Aggregate scores

| Subject | Formula | Rationale |
|---------|---------|-----------|
| Asset | `100 × (1 − Π(1 − sᵢ/100))` over the top 10 open finding scores, capped at `max(sᵢ) + 15` | Many medium issues raise risk, but cannot exceed the worst issue by more than one band step |
| Risk scenario | `max(stage finding scores) + 5 × (stages_matched − 1)`, capped 100 | Chained weaknesses are worse than the worst link alone |
| Owner / team | Criticality-weighted mean of asset scores | Accountability views |
| Organization (exposure score) | `0.5 × P90(asset scores weighted by criticality) + 0.3 × max(scenario scores) + 0.2 × Tier-0 exposure ratio × 100` | Balances breadth, worst-case chains and Tier-0 exposure |

## 4. Recalculation triggers

| Event | Recomputed subjects |
|-------|---------------------|
| `assessment.run_completed` | Findings in run → their assets → scenarios → organization |
| `graph.analysis_completed` | All findings with changed R or P → assets → organization |
| `asset.criticality_changed` | That asset's findings → asset → organization |
| `finding.updated` (lifecycle change) | That finding → asset → organization |
| Scoring model activation | Full recompute (background job) |

## 5. Governance

- New model versions are added as new rows and activated explicitly (`is_active`); old
  scores remain attributable to their version.
- Score changes > 20 points for Tier-0 assets are surfaced in the dashboard's
  "significant changes" feed.
- Control `exploitability` and `privilege_impact` values are reviewed when a control's
  `version` changes.
