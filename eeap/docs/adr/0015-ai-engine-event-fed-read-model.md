# ADR-0015: AI Engine scores from an event-fed local read model

- Status: Accepted
- Date: 2026-10-12

## Context

Docs 05 and 06 originally had the AI Engine pull data at scoring time from internal
endpoints (`/internal/findings/snapshot`, `/internal/assets/criticality`,
`/internal/graph/metrics`). Internal service tokens are minted only by the gateway
(ADR-0007): services hold the public key and cannot mint tokens, by design. Background
workers therefore have no credential for service-to-service calls, and adding per-service
client credentials would create a new secret class and a wider blast radius.

Scoring also has to react to many small changes (one finding triaged, one asset
reclassified) without re-reading the full finding set from another service.

## Decision

- The AI Engine maintains a **local read model** in its own schema, populated from
  events it already consumes:
  - `ai.finding_facts` ← `finding.created|updated|resolved` (the events carry `severity`,
    `status`, `lifecycle_state`, `control_id`, and the control's `exploitability` and
    `privilege_impact`).
  - `ai.asset_facts` ← `asset.created|updated|criticality_changed` (the events carry
    `criticality`, `tier`, `environment`, `owner`).
- Updates are idempotent (`ai.event_inbox`) and ordered per subject by the envelope's
  `occurred_at`; older events never overwrite newer facts.
- Recalculation is **batched**: handlers mark controls/assets dirty in Redis
  (`ai:dirty:*`); a worker loop rescoring every 2 s handles the affected findings
  (whole control cohort, because exposure breadth `B` depends on it), their assets and the
  organization. On start-up the loop runs one full recompute to reconcile.
- Scores are written only when score, rating or factors change; previous rows keep
  `is_current = false` for history.
- Producers only emit events after commit, so the read model is eventually consistent;
  the dashboard shows `computed_at`.

## Consequences

- (+) No service-to-service credentials; services stay decoupled and the AI Engine keeps
  working when the other services are down.
- (+) Large imports cost one batched recompute instead of one per finding.
- (−) Event payloads become part of the contract: fields used by scoring must be kept
  (contract-tested) and new factors may need event changes.
- (−) Facts missed before the AI Engine existed need a replay: reset the
  `ai-engine.scoring` consumer group (`XGROUP SETID <stream> ai-engine.scoring 0`);
  the inbox makes replays safe.
- The internal snapshot endpoints remain the intended contract for the Reporting Service,
  which reads point-in-time data on behalf of a user request.
