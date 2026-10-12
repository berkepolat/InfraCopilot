# ADR-0006: MinIO for evidence, imports and reports

- Status: Accepted
- Date: 2026-10-12

## Context

Raw collector output, third-party import files (Nessus exports, BloodHound archives can be
hundreds of MB) and rendered reports are large, immutable blobs that must be retained for
audit and reproducibility, but should not bloat PostgreSQL.

## Decision

Use MinIO (S3 API) with buckets:

| Bucket | Content | Writer | Lifecycle |
|--------|---------|--------|-----------|
| `eeap-evidence` | Raw collection payloads `<run_id>/<job_id>/<sha256>.json` | assessment | 365 d |
| `eeap-imports` | Original third-party files | assessment | 180 d |
| `eeap-reports` | Rendered reports `<report_id>.<fmt>` | reporting | 180 d |
| `eeap-backups` | Database dumps | backup job | 30 d |

Objects are content-addressed (SHA-256 recorded in PostgreSQL), bucket versioning is on,
and each service has its own access key restricted by bucket policy. Clients download via
gateway-authorized pre-signed URLs (5-minute TTL).

### Image source

MinIO Inc. withdrew the `minio/minio` and `minio/mc` images from Docker Hub in 2025.
EEAP uses the community builds of the same AGPLv3 source published as `pgsty/minio`
and `pgsty/mc`, pinned to `RELEASE.*` tags. Enterprises with a MinIO subscription, or
policies requiring a different supplier, can swap the image in `docker-compose.yml`; the
platform depends only on the S3 API and `mc` admin commands.

## Alternatives considered

- Filesystem volumes: no access policies, hard to scale beyond one node.
- PostgreSQL large objects / bytea: backup bloat and memory pressure.

## Consequences

- (+) S3-compatible → customers may substitute AWS S3, Azure Blob (via gateway) or Ceph.
- (+) Immutable, hash-verified evidence supports audit defensibility.
- (−) Another stateful component to back up; covered by deployment model.
