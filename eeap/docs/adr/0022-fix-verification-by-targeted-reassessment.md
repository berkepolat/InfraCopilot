# ADR-0022: Fix verification by targeted reassessment

**Status:** Accepted
**Date:** 2026-10-12

## Context

Remediation owners need to confirm that a fix worked without waiting for the next full scan, and
auditors need a record that it was confirmed. Options were:

1. Let owners mark findings as resolved manually.
2. Re-run the full assessment and let the normal lifecycle resolve findings.
3. Run a reassessment limited to the selected findings and record the outcome per finding.

## Decision

Option 3. `POST /assessments/verifications` takes up to 50 open, acknowledged or in-remediation
findings from server-side assessments (AD or NET, not both) and queues a normal run with
`trigger = verification`, limited to their controls and, for NET, to their hosts. Ports taken
from `tcp:<port>` / `web:<port>` subjects are added when they are outside the default profile.
The run uses the same scope checks (`SCAN_ALLOWED_CIDRS`), collectors and single-run lock as any
other run, so verification adds no new probing capability ([ADR-0011](0011-defensive-scope-guardrails.md)).

Each request writes one row per finding to `assessment.finding_verifications`. When the run
finishes, in the same transaction as its findings:

| Outcome | Condition |
|---|---|
| `verified` | the run observed the finding as PASS (the lifecycle resolves it as usual) |
| `still_failing` | the run observed it again as non-PASS |
| `inconclusive` | the run did not observe it (host unreachable, control not assessed) |
| `failed` | the run failed |

The outcome is also written to the finding history ("fix verified" / "fix verification: still
failing").

## Consequences

- Findings are never closed by assertion; only an observed PASS resolves them.
- A NET verification run only resolves findings for the selected controls on the selected hosts.
  Other findings on those hosts are left alone.
- Import and agent findings cannot be verified this way; a new import or agent submission is the
  verification.
- Because only one run is active at a time, a verification waits for (or blocks) a scheduled run.
