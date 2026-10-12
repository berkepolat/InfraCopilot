# ADR-0013: Secrets via Docker secrets and `*_FILE`, external store in production

- Status: Accepted
- Date: 2026-10-12

## Context

The platform needs database passwords, Redis password, MinIO keys, JWT signing keys, the
internal token key, the Agent CA key, TLS keys and optional LLM/integration credentials.
Environment variables leak through `docker inspect`, crash dumps and child processes.

## Decision

- All secrets are mounted as files (`/run/secrets/<name>`) and referenced with the
  `<VAR>_FILE` convention, which the shared settings loader resolves.
- Development: `scripts/generate-secrets.sh` creates random secrets and keys in `./secrets`
  (git-ignored, `0600`).
- Production: secrets are provisioned from an enterprise store (HashiCorp Vault, Azure Key
  Vault, AWS Secrets Manager) via Swarm secrets, Vault Agent templates, or External
  Secrets Operator on Kubernetes.
- Integration credentials are never stored in PostgreSQL; rows hold `secret_ref` only.
- The Agent CA private key is the most sensitive secret; production deployments should use
  an HSM/KMS-backed CA or an offline root with an online intermediate.

## Consequences

- (+) No secrets in images, env vars, logs or database.
- (−) Rotation requires coordinated restarts in T1; T2/T3 use rolling restarts.
