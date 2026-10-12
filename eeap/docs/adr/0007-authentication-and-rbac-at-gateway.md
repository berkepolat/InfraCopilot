# ADR-0007: JWT authentication and RBAC enforced at the gateway, re-checked in services

- Status: Accepted
- Date: 2026-10-12

## Context

The platform must provide JWT authentication, RBAC, rate limiting and audit logging for
users, agents and integration clients, while internal services must not be callable
without authorization even if the internal network is reached.

## Decision

- The API Gateway is the only ingress for authentication: user JWTs (RS256, 15 min) with
  rotating refresh tokens; scoped, expiring API keys; agent mTLS + certificate-bound JWT.
- RBAC is permission-based (`resource:action`), roles map to permission sets in `iam`.
  The gateway authorizes each route (`x-permission` in OpenAPI).
- For each upstream call the gateway mints a 60-second **internal service token**
  (audience = target service) carrying subject, permissions and scope. Services verify it
  and re-check permissions and owner scope (defense in depth).
- TLS terminates at an nginx edge proxy, which also verifies agent client certificates and
  forwards the verified certificate to the gateway in a header that is only accepted from the proxy.

## Alternatives considered

- Off-the-shelf API gateway (Kong, Traefik plugins) + Keycloak: powerful, but adds two
  stateful products; can be adopted later (OIDC federation is planned).
- Forwarding the user's JWT unchanged to services: works, but services could not distinguish
  gateway-originated calls from replayed user tokens on the internal network.

## Consequences

- (+) Single, auditable policy enforcement point plus service-level checks.
- (+) Internal tokens are short-lived and audience-bound, limiting replay.
- (−) Gateway is on the critical path; must be horizontally scaled and stateless.
