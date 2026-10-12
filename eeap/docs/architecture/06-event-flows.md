# 06 — Event Flow Diagrams

All flows below use the reliable-publish pattern: a service writes its state change and
an `event_outbox` row in **one transaction**; the outbox relay publishes to Redis Streams;
consumers record `event_id` in `event_inbox` in the same transaction as their side
effects.

## 1. Reliable event publication (pattern)

```mermaid
sequenceDiagram
    autonumber
    participant S as Producer service
    participant DB as PostgreSQL (service schema)
    participant R as Outbox relay
    participant X as Redis Stream
    participant C as Consumer worker
    participant CDB as PostgreSQL (consumer schema)

    S->>DB: BEGIN; write domain rows; INSERT event_outbox; COMMIT
    loop every 500 ms / LISTEN-NOTIFY
        R->>DB: SELECT unpublished FOR UPDATE SKIP LOCKED
        R->>X: XADD eeap.<domain> envelope
        R->>DB: UPDATE published_at
    end
    C->>X: XREADGROUP (group, consumer)
    C->>CDB: BEGIN; INSERT event_inbox (dedupe); apply side effects; COMMIT
    C->>X: XACK
    Note over C,X: Pending messages idle > 60 s are reclaimed via XAUTOCLAIM.<br/>After 5 failed deliveries → eeap.dlq
```

## 2. User authentication and authorized request

```mermaid
sequenceDiagram
    autonumber
    actor U as User (browser)
    participant P as Edge proxy
    participant F as Frontend (BFF)
    participant G as API Gateway
    participant RL as Redis (rate limit)
    participant A as Asset Service
    participant AU as audit.audit_log

    U->>P: POST /login (HTTPS)
    P->>F: forward
    F->>G: POST /api/v1/auth/login
    G->>RL: token bucket check (IP, username)
    G->>G: verify Argon2id, lockout policy, MFA
    G->>AU: auth.login success/failure
    G-->>F: access JWT (15 min) + refresh token (8 h)
    F-->>U: Set-Cookie HttpOnly Secure SameSite=Strict

    U->>P: GET /assets
    P->>F: forward with cookie
    F->>G: GET /api/v1/assets (Bearer JWT, X-Request-ID)
    G->>RL: rate limit (principal)
    G->>G: verify JWT (RS256, exp, aud), RBAC: assets:read
    G->>A: GET /assets + internal service token (60 s, perms, scope)
    A->>A: verify internal token, apply owner scope
    A-->>G: 200 page
    G-->>F: 200 page
    F-->>U: render
```

## 3. Agent enrollment

```mermaid
sequenceDiagram
    autonumber
    actor Adm as Admin
    participant G as API Gateway
    participant DB as iam schema
    participant CA as Agent CA (gateway, key from secret)
    participant Ag as Agent (Windows/Linux)
    participant X as Redis eeap.agent
    participant AS as Asset Service

    Adm->>G: POST /agents/enrollment-tokens {platform, max_uses, ttl}
    G->>DB: store SHA-256(token), expiry
    G-->>Adm: token (shown once)
    Adm-->>Ag: deploy agent package + token (SCCM / Intune / Ansible)
    Ag->>Ag: generate key pair locally (TPM / DPAPI / 0600 file)
    Ag->>G: POST /agent/enroll {CSR, hostname, platform, capabilities} + token
    G->>DB: validate token (hash, expiry, uses, platform) — increment use_count
    G->>CA: sign CSR (CN=agent_id, 30-day validity, clientAuth EKU)
    G->>DB: INSERT agents (thumbprint, serial, expiry)
    G->>X: agent.enrolled
    G-->>Ag: certificate + CA chain + poll interval
    X-->>AS: agent.enrolled → resolve / create asset, add identifier agent_id
    Note over Ag,G: All later calls use mTLS (edge proxy verifies chain)<br/>+ agent JWT bound to cert thumbprint
```

## 4. Assessment run (end-to-end)

```mermaid
sequenceDiagram
    autonumber
    actor An as Analyst
    participant G as API Gateway
    participant AS as Assessment Service (API)
    participant O as Assessment Orchestrator (worker)
    participant AST as Asset Service
    participant Q as Redis (agent job queues)
    participant Ag as Agent
    participant SC as Server-side collectors
    participant M as MinIO eeap-evidence
    participant E as Evaluator / Normalizer
    participant X as Redis Streams

    An->>G: POST /assessments/runs {profile_id, scope}
    G->>AS: forward (assessments:run)
    AS->>AS: INSERT run(queued) + outbox assessment.run_requested
    AS-->>An: 202 {run_id}
    X-->>O: assessment.run_requested
    O->>AST: resolve scope → asset list
    O->>O: expand controls × assets → jobs (by execution_site)
    par agent jobs
        O->>Q: enqueue job per agent
        Ag->>G: GET /agent/jobs (mTLS)
        G->>AS: POST /internal/agent/jobs/pull {agent_id}
        AS->>Q: pop jobs for agent_id
        AS-->>G: jobs
        G-->>Ag: jobs (allow-listed collector IDs)
        Ag->>Ag: run built-in read-only collectors
        Ag->>G: POST /agent/jobs/{id}/result
        G->>AS: POST /internal/agent/results (agent identity asserted by gateway)
        AS->>M: store payload (sha256)
        AS->>X: agent.result_submitted
    and server-side jobs
        O->>SC: AD (LDAPS read-only), network checks
        SC->>M: store evidence
    end
    X-->>E: result / evidence available
    E->>E: evaluate controls → FindingDrafts → normalize, fingerprint
    E->>AS: upsert findings, finding_history
    E->>X: finding.created / finding.updated, relationship.observed, discovery.asset_observed
    O->>O: all jobs terminal → resolve unobserved findings (full scope only)
    O->>X: assessment.run_completed {stats}
```

## 5. Graph build, correlation and scoring

```mermaid
sequenceDiagram
    autonumber
    participant X as Redis Streams
    participant RE as Relationship Engine
    participant GDB as graph schema
    participant AI as AI Engine
    participant AST as Asset Service
    participant AS as Assessment Service
    participant ADB as ai schema
    participant LLM as LLM provider (optional)

    X-->>RE: relationship.observed (batch)
    RE->>GDB: upsert nodes (node_key), edges (src, tgt, rel)
    X-->>RE: asset.updated / finding.*
    RE->>GDB: sync Computer / Tier0 flags, AuthenticationRisk edges
    RE->>RE: debounce 60 s → analysis job
    RE->>GDB: load snapshot → NetworkX: Tier-0 reachability, centrality, concentration
    RE->>GDB: node_metrics, concentration_areas
    RE->>X: graph.analysis_completed

    X-->>AI: finding.* / asset.* / assessment.run_completed / graph.analysis_completed
    AI->>ADB: upsert finding_facts / asset_facts (read model, ADR-0015), mark dirty
    AI->>AI: every 2 s: rescore dirty control cohorts → assets → org (model v1)
    AI->>AI: evaluate correlation rules → risk scenarios
    AI->>AI: MITRE mapping, remediation prioritization
    opt AI_LLM_PROVIDER != none
        AI->>AI: redact identifiers → tokens
        AI->>LLM: summarize scenario / remediation (no raw evidence)
        LLM-->>AI: text
        AI->>AI: guardrail + schema check, de-tokenize
    end
    AI->>ADB: risk_scores (is_current), risk_scenarios, remediation_items, narratives
    AI->>X: risk.scores_updated, correlation.completed
```

## 6. Report generation

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant G as API Gateway
    participant RS as Reporting Service (API)
    participant W as Reporting worker
    participant Svc as Asset / Assessment / Graph / AI
    participant M as MinIO eeap-reports
    participant X as Redis Streams

    U->>G: POST /reports {report_type, formats}
    G->>RS: forward (reports:create)
    RS->>RS: INSERT report(queued, snapshot_at=now) + outbox report.requested
    RS-->>U: 202 {report_id}
    X-->>W: report.requested
    W->>Svc: fetch data as_of snapshot_at
    W->>W: build canonical JSON → Jinja2 HTML → WeasyPrint PDF
    W->>M: put artifacts (sha256)
    W->>RS: status=completed, artifacts
    W->>X: report.generated
    U->>G: GET /reports/{id}/download/pdf
    G->>G: RBAC + audit report.download
    G->>RS: request pre-signed URL (5 min)
    G-->>U: 302 → MinIO via edge proxy
```

## 7. Third-party import (Phase 3)

```mermaid
flowchart LR
    U[Analyst / API client] -->|POST /imports| G[Gateway]
    G --> AS[Assessment Service]
    AS -->|store original| M[(MinIO eeap-imports)]
    AS -->|imports row, run trigger=import| DB[(assessment)]
    AS --> W[Import worker]
    W --> AD{Adapter by source_type}
    AD -->|Nessus / Qualys / Tenable / OpenVAS / Defender / Wiz| F[Standard Findings<br/>control_id = IMPORT-xxxx map]
    AD -->|BloodHound / SharpHound JSON| R[relationship.observed]
    AD -->|PingCastle / Purple Knight| F
    AD -->|Nmap XML| D[discovery.asset_observed]
    F --> N[Normalizer + fingerprint] --> DB
    R --> X[(Redis Streams)]
    D --> X
```

## 8. Agent heartbeat and staleness

```mermaid
stateDiagram-v2
    [*] --> active: enrolled
    active --> active: heartbeat (≤ 15 min)
    active --> stale: no heartbeat 3 × interval
    stale --> active: heartbeat
    active --> suspended: admin
    suspended --> active: admin
    active --> revoked: admin / cert compromise
    stale --> revoked: admin
    suspended --> revoked: admin
    revoked --> [*]
```
