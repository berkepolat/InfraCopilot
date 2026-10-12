# ADR-0014: Integration adapters normalize third-party data

- Status: Accepted
- Date: 2026-10-12

## Context

Future integrations include Nessus, Qualys, Tenable, OpenVAS, BloodHound, SharpHound,
PingCastle, Purple Knight, Microsoft Defender, Wiz and Nmap XML. Each has a distinct data
model; some produce vulnerabilities, some produce AD posture findings, some produce
relationship graphs or host inventories.

## Decision

Implement an adapter interface in the Assessment Service:

```python
class IntegrationAdapter(Protocol):
    source_type: str                       # "nessus", "bloodhound", "nmap_xml", ...
    modes: set[Literal["file_import", "api_pull"]]
    def parse(self, stream: BinaryIO, ctx: ImportContext) -> Iterator[
        FindingDraft | RelationshipObservation | AssetObservation]: ...
```

| Source | Primary output |
|--------|----------------|
| Nessus, Qualys, Tenable, OpenVAS, Defender, Wiz | Findings (`control_id` mapped via `IMPORT-*` catalog entries), asset observations |
| BloodHound / SharpHound (exported JSON) | Relationship observations (mapped to EEAP edge types), nodes |
| PingCastle, Purple Knight | AD posture findings mapped to AD-* controls where equivalent |
| Nmap XML | Asset observations (hosts, open services) |

- Imports always create an `assessment_run` with `trigger=import` and `full_scope=false`
  (imports never auto-resolve native findings).
- Original files are stored in `eeap-imports` with SHA-256; parsing runs in an isolated
  worker with time/memory limits and `defusedxml`.
- EEAP ingests **results exported by those tools**; it does not run them.

## Consequences

- (+) Third-party results join the same scoring, graph and reporting pipeline.
- (−) Mapping tables (vendor IDs → EEAP controls / MITRE) need maintenance per vendor release.
