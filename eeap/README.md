# Enterprise Exposure Assessment Platform (EEAP)

EEAP is a Docker-native **Continuous Exposure Assessment Platform**. It discovers assets,
collects infrastructure security configuration, evaluates it against security baselines,
normalizes findings, builds privilege/relationship graphs, correlates risk, computes
exposure scores and produces AI-assisted remediation guidance and reports.

> **Scope guardrail.** EEAP is a *defensive* posture-assessment platform for authorized
> enterprise environments. It performs read-only configuration collection and evaluation.
> It does **not** contain exploit execution, credential extraction, attack automation,
> authentication bypass or lateral-movement capabilities. See
> [ADR-0011](docs/adr/0011-defensive-scope-guardrails.md).

## Status: Phase 2 — Platform skeleton

Phase 1 delivered the architecture foundation. The platform skeleton adds the shared
library, the six services, the frontend, Dockerfiles, health/metrics endpoints, user JWT
authentication, RBAC, audit logging, rate limiting, internal service tokens and the
transactional outbox / Redis Streams event pipeline. Findings can be imported and are risk
scored automatically. **AD-001 … AD-010** are implemented as a read-only LDAPS configuration
assessment ([doc 11](docs/architecture/11-ad-assessment.md)). **NET-001 … NET-009** probe an
explicit IP list authorized by `SCAN_ALLOWED_CIDRS`, including TCP port discovery with service
identification (open ports, product/version, TLS, RDP NLA) into a network service inventory ([doc 12](docs/architecture/12-net-assessment.md)).
AD runs also feed the exposure graph; the Relationship Engine computes Tier-0 reachability and
risk concentration areas, which drive the propagation factor R of the risk score
([doc 13](docs/architecture/13-graph-analytics.md)). Correlation rules combine open findings and
graph facts into risk scenarios ([doc 14](docs/architecture/14-correlation.md)), which feed a
prioritized remediation roadmap and an ATT&CK exposure view ([doc 15](docs/architecture/15-remediation-mitre.md)).
Executive, technical, roadmap and ATT&CK reports are rendered as PDF, HTML and JSON with the
requester's permissions ([doc 16](docs/architecture/16-reporting.md)).
WIN-0xx remain catalogued and accept imported findings only.

| Deliverable            | Location                                                                 |
|------------------------|--------------------------------------------------------------------------|
| System architecture    | [docs/architecture/01-system-architecture.md](docs/architecture/01-system-architecture.md) |
| Service design         | [docs/architecture/02-service-design.md](docs/architecture/02-service-design.md) |
| Docker architecture    | [docs/architecture/03-docker-architecture.md](docs/architecture/03-docker-architecture.md) |
| Database design        | [docs/architecture/04-database-design.md](docs/architecture/04-database-design.md), [infrastructure/postgres/init/](infrastructure/postgres/init/) |
| API contracts          | [docs/architecture/05-api-contracts.md](docs/architecture/05-api-contracts.md), [docs/api/openapi.yaml](docs/api/openapi.yaml), [shared/schemas/](shared/schemas/) |
| Event flow diagrams    | [docs/architecture/06-event-flows.md](docs/architecture/06-event-flows.md) |
| Security architecture  | [docs/architecture/07-security-architecture.md](docs/architecture/07-security-architecture.md) |
| Risk scoring model     | [docs/architecture/08-risk-scoring-model.md](docs/architecture/08-risk-scoring-model.md) |
| Deployment model       | [docs/architecture/09-deployment-model.md](docs/architecture/09-deployment-model.md) |
| Directory structure    | [docs/architecture/10-directory-structure.md](docs/architecture/10-directory-structure.md) |
| AD assessment          | [docs/architecture/11-ad-assessment.md](docs/architecture/11-ad-assessment.md) |
| NET IP assessment      | [docs/architecture/12-net-assessment.md](docs/architecture/12-net-assessment.md) |
| Graph analytics        | [docs/architecture/13-graph-analytics.md](docs/architecture/13-graph-analytics.md) |
| Correlation            | [docs/architecture/14-correlation.md](docs/architecture/14-correlation.md) |
| Remediation and MITRE  | [docs/architecture/15-remediation-mitre.md](docs/architecture/15-remediation-mitre.md) |
| Reporting              | [docs/architecture/16-reporting.md](docs/architecture/16-reporting.md) |
| ADRs                   | [docs/adr/](docs/adr/README.md) |
| Docker Compose         | [docker-compose.yml](docker-compose.yml), [.env.example](.env.example) |

## Quick start

```bash
cd eeap
./scripts/generate-secrets.sh        # creates ./secrets/* (git-ignored)
cp .env.example .env
docker compose up -d                 # data tier only: postgres, redis, minio, minio-init
docker compose --profile app up -d --build   # full platform
docker compose --profile app ps      # every long-running service should report "healthy"
```

There is no default account. Create the first administrator with the gateway CLI
(the password is read from the environment or prompted for; minimum 14 characters):

```bash
docker compose --profile app run --rm --no-deps -it api-gateway \
  python -m app.cli create-user --username admin --display-name "Platform Admin" --role admin
```

Then open `https://localhost/` (self-signed certificate in dev). Roles: `admin`,
`security_analyst`, `auditor`, `executive`, `asset_owner`, `integration_client`.

### Importing findings

Findings in the Standard Finding Format (JSON) or CSV are imported through the API; the
original file is kept in MinIO (`eeap-imports`), rows are validated, deduplicated by
fingerprint (`asset_id | control_id | subject_key`) and scored automatically by the AI
Engine (model v1, [doc 08](docs/architecture/08-risk-scoring-model.md)). Samples:
[`docs/examples/`](docs/examples/).

```bash
TOKEN=$(curl -sk -X POST https://localhost/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -sk -X POST "https://localhost/api/v1/imports?source_type=eeap_json" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @docs/examples/findings-sample.json
curl -sk -X POST "https://localhost/api/v1/imports?source_type=eeap_csv" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: text/csv' --data-binary @docs/examples/findings-sample.csv

curl -sk "https://localhost/api/v1/imports" -H "Authorization: Bearer $TOKEN"          # status + row errors
curl -sk "https://localhost/api/v1/risk/top-findings" -H "Authorization: Bearer $TOKEN" # scored findings
```

A later observation of `PASS` resolves a finding; `FAIL` on a resolved finding reopens it.
Triage via `POST /api/v1/findings/{id}/lifecycle` and `POST /api/v1/findings/{id}/risk-acceptance`
(expiring; expired acceptances reopen automatically).

### Active Directory assessment

Point the worker at a domain controller over LDAPS with a read-only account (`.env`:
`AD_LDAP_URL`, `AD_BIND_USER`, optional `AD_BASE_DN` and `AD_TLS_CA_FILE`; password in
`secrets/ad_bind_password`), then start a run from the dashboard (**Run AD assessment**) or:

```bash
curl -sk -X POST https://localhost/api/v1/assessments/runs -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{}'            # or {"control_ids": ["AD-001", "AD-007"]}
curl -sk "https://localhost/api/v1/assessments/runs?limit=5" -H "Authorization: Bearer $TOKEN"
```

### Network IP assessment

Set `SCAN_ALLOWED_CIDRS` in `.env` to the ranges you authorize (e.g. `10.0.0.0/8,172.16.0.0/12`),
recreate the assessment containers, then scan from the dashboard (**Scan IPs**) or:

```bash
curl -sk -X POST https://localhost/api/v1/assessments/runs -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"targets":["10.0.0.10","10.0.0.20"]}'
```

For development there is a Samba AD **test lab** seeded with configuration weaknesses
(never use it outside development):

```bash
./scripts/lab-setup.sh
docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile app up -d --build
```

Observability stack (Prometheus, Loki, Promtail, Grafana on `127.0.0.1:3001`):

```bash
docker compose --profile app --profile observability up -d
```

### Tests

Unit and contract tests run in a throwaway container:

```bash
docker run --rm -v "$PWD:/src:ro" -w /tmp python:3.12-slim sh -c \
  "cp -r /src/shared /tmp/shared && pip install -q '/tmp/shared[test]' 'argon2-cffi>=23.1,<26' 'ldap3>=2.9,<3' 'dnspython>=2.6,<3' 'networkx>=3.3,<4' \
   && cd /src && python -m pytest -q -p no:cacheprovider tests"
```
