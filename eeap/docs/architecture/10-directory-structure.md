# 10 — Directory Structure

```
eeap/
├── README.md
├── docker-compose.yml               # full topology; data tier default, app/observability profiles
├── .env.example                     # non-secret configuration contract
├── .gitignore
│
├── services/                        # Python 3.12 / FastAPI microservices (Phase 2 implementation)
│   ├── api-gateway/                 # AuthN/AuthZ, routing, rate limiting, audit, agent enrollment + CA
│   ├── asset-service/               # inventory, classification, ownership, criticality
│   ├── assessment-service/          # runs, jobs, collectors, control evaluators, findings, imports
│   ├── relationship-engine/         # exposure graph ingest + analytics
│   ├── ai-engine/                   # scoring, correlation, MITRE mapping, remediation, LLM gateway
│   └── reporting-service/           # report assembly and rendering (JSON/HTML/PDF)
│       └── (each service)
│           ├── Dockerfile           # CMD python -m app.entrypoint (EEAP_ROLE=api|worker|migrate)
│           ├── requirements.txt     # service-only deps; common deps come from eeap-shared
│           ├── migrations/versions/ # Alembic revisions for this service's schema only
│           ├── app/
│           │   ├── main.py · worker.py · entrypoint.py · config.py · api.py
│           │   ├── domain/          # pure domain logic (as it grows)
│           │   ├── repositories/    # data access (as it grows)
│           │   └── clients/         # typed internal HTTP clients
│           └── tests/
│
├── agents/
│   ├── windows-agent/               # .NET 8 Windows Service; built-in read-only collectors
│   └── linux-agent/                 # Go static binary + systemd unit; built-in read-only collectors
│
├── frontend/                        # Next.js 14 / React / TypeScript
│   ├── Dockerfile
│   ├── app/                         # routes: dashboard, assets, findings, exposure, risk, reports, admin
│   ├── components/
│   ├── lib/api/                     # generated API client (from docs/api/openapi.yaml)
│   └── tests/
│
├── shared/                          # installed into every Python image as `eeap-shared`
│   ├── schemas/                     # JSON Schema contracts (source of truth)
│   ├── models/                      # Pydantic models mirroring the schemas (drift-tested)
│   ├── logging/                     # JSON logger, redaction filter, request-id context
│   ├── migrations/                  # shared Alembic env.py / script template
│   └── utils/                       # settings (*_FILE secrets), app factory, outbox + Redis Streams, runtime, internal auth
│
├── infrastructure/
│   ├── postgres/init/               # bootstrap DDL (roles, schemas, tables, seed reference data, grants)
│   ├── redis/                       # redis.conf
│   ├── minio/                       # bucket bootstrap script, lifecycle policies
│   ├── docker/                      # edge-proxy (nginx) config, observability configs
│   └── lab/samba-dc/                # development-only Samba AD test lab (docker-compose.lab.yml)
│
├── docs/
│   ├── architecture/                # 01–11 architecture documents
│   ├── adr/                         # architecture decision records
│   └── api/openapi.yaml             # public API contract
│
├── tests/
│   ├── unit/                        # cross-cutting unit tests (shared lib)
│   ├── integration/                 # Compose-based end-to-end tests
│   └── contract/                    # JSON Schema ↔ Pydantic ↔ OpenAPI drift tests
│
├── scripts/                         # generate-secrets.sh, lab-setup.sh, backup, restore, dev helpers
└── secrets/                         # generated locally, git-ignored
```

## Rules

1. A service imports only `shared/` and its own package; never another service's code.
2. A service writes only to its own PostgreSQL schema and its own MinIO prefixes.
3. Contracts change in `shared/schemas` or `docs/api/openapi.yaml` first, in the same PR as code.
4. Every service directory is buildable in isolation with the repository root as the Docker build context.
5. Control evaluators live in `services/assessment-service/app/controls/<module>.py` (pure functions over a
   snapshot) and their read-only collectors in `app/collectors/` (ADR-0009, ADR-0011; AD: [doc 11](11-ad-assessment.md)).
6. New integration adapters live in `services/assessment-service/app/integrations/<tool>/` (Phase 3, ADR-0014).
