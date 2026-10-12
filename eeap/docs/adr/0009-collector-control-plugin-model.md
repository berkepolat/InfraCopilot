# ADR-0009: Collector / Control plugin model and Standard Finding Format

- Status: Accepted
- Date: 2026-10-12

## Context

EEAP must support AD, Windows, Network and future Cloud modules, plus third-party data.
Mixing data gathering with evaluation logic makes controls hard to test and forces
re-collection when evaluation rules change.

## Decision

Separate **collection** from **evaluation**:

```python
class Collector(Protocol):            # read-only, side-effect free on targets
    collector_id: str                 # e.g. "ad.domain_policy", "win.smb_config"
    execution_site: Literal["server", "agent:windows", "agent:linux"]
    def collect(self, target: Target, params: dict) -> RawEvidence: ...

class Control(Protocol):              # pure function, unit-testable with fixture evidence
    control_id: str                   # e.g. "AD-001"
    version: int
    requires: list[str]               # collector IDs
    def evaluate(self, evidence: Mapping[str, RawEvidence], ctx: AssetContext) -> list[FindingDraft]: ...
```

- Controls are registered in `assessment.controls` (metadata: severity, exploitability,
  privilege impact, MITRE techniques, recommendation template, version).
- One collector can feed many controls (e.g. `win.smb_config` → WIN-001, WIN-002).
- All results are normalized to the **Standard Finding Format**
  (`shared/schemas/finding.schema.json`), fingerprinted for deduplication.
- Collectors emitting relationship facts produce `relationship.observed` in
  `shared/schemas/relationship.schema.json` format.
- Re-evaluation from stored evidence is possible without re-collection when a control
  version changes.

## Consequences

- (+) Controls are deterministic and testable with recorded fixtures.
- (+) New modules (Cloud) plug in without touching the pipeline.
- (−) Evidence storage grows; managed by MinIO lifecycle rules.
