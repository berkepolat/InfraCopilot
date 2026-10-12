# ADR-0008: Pull-based agents with mTLS enrollment and no command channel

- Status: Accepted
- Date: 2026-10-12

## Context

Windows and Linux agents collect local configuration (registry, local administrators,
security products, SMB/WinRM/RDP, SSH, sudoers, services). Endpoints sit behind firewalls
and NAT; inbound connections to endpoints are unacceptable to most security teams. A
compromised central platform must not become a tool to control the fleet.

## Decision

- Agents initiate all communication (outbound HTTPS 443) and **pull** jobs.
- Enrollment: one-time, hashed, expiring token + locally generated key pair + CSR → client
  certificate from an internal Agent CA (30-day validity, auto-renewal). Revocation is
  immediate via the agent status check at the gateway.
- Jobs contain only an allow-listed **collector ID** compiled into the signed agent binary
  and declarative parameters. There is no command, script or binary-download capability.
- Results are uploaded with SHA-256 integrity, accepted only for jobs assigned to that agent.
- Agents run with least privilege (dedicated service account / `eeap-agent` user with
  narrowly scoped read-only rights).

## Alternatives considered

- Push model (WinRM/SSH from the platform): requires inbound ports and stored privileged
  credentials on the platform — rejected.
- Generic script execution agent (e.g., run PowerShell sent by server): flexible but turns
  the platform into a remote execution system — rejected by ADR-0011.

## Consequences

- (+) Firewall-friendly, minimal attack surface, no credentials stored centrally.
- (+) A compromised platform can at most request data collection from the built-in set.
- (−) New collectors require an agent release; mitigated by a capability flag so the
  platform only schedules collectors the agent advertises.
