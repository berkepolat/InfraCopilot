# ADR-0019: Known vulnerable packages from uploaded OSV data

- Status: Accepted
- Date: 2026-10-12

## Context

Missing security updates are the most common host weakness, and LIN-002 only counts pending updates from
the host's own (possibly stale) package metadata. Matching installed packages against a vulnerability
database names the affected packages and CVEs. Deployments are often on networks without internet access,
and the host inventory must not be sent to an external service. Matching service banners against CVE
version ranges produces many false positives, because distributions backport fixes without changing the
upstream version number.

## Decision

- The Linux posture script (ADR-0018) also lists installed packages with their source package and version
  (dpkg, rpm, apk). Matching uses distribution package versions, never service banners.
- The vulnerability data is the OSV export of the distribution (Alpine, Debian, Ubuntu, Rocky Linux,
  AlmaLinux). An administrator downloads the family archive (`<Family>/all.zip`) on a machine with
  internet access and uploads it unchanged (`POST /vulnerability-feeds`, `assessments:manage`).
  The platform never fetches data from the internet.
- Uploads are streamed through the edge proxy, gateway and service into MinIO (up to 1 GiB, bounded
  memory). The worker reads the archive through ranged object reads in two passes: first it determines
  the releases the archive covers, then it inserts fixed-version ranges in batches. One transaction
  replaces the data of exactly those releases, and the uploaded object is deleted afterwards.
- Only ranges with a fixed version are stored, so every LIN-009 finding has an available update. Bug-fix
  and enhancement advisories, withdrawn records and Ubuntu Pro / FIPS channels are skipped.
- Versions are compared with each distribution's own ordering (dpkg, rpm, apk). An advisory applies when
  the installed version lies in every applicable range of the advisory for that package. For RPM module
  streams, module builds are compared only with module builds.
- Severity is the distribution's rating where present (Debian urgency, Ubuntu priority, Red Hat-family
  rating), otherwise the CVSS v3 base score, otherwise Medium.
- LIN-009 reports one finding per vulnerable source package (`pkg:<name>`) plus `vuln-data`, which warns
  when the release's data is more than 30 days old. Hosts without an inventory or without data for their
  release keep their open LIN-009 findings.

## Consequences

- (+) Works offline; no host inventory leaves the platform.
- (+) Uses the distribution's own fixed versions, so backported fixes are recognised.
- (−) Results are only as current as the last upload; LIN-009 warns when the data ages.
- (−) Unfixed vulnerabilities are not reported (by design), and distributions without OSV data
  (e.g. RHEL itself, SUSE, Arch) are not covered.
- (−) The Ubuntu archive is large (≈750 MB); imports take minutes and the upload limit is 1 GiB.
