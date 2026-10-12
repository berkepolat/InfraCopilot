# ADR-0011: Defensive-only scope guardrails

- Status: Accepted
- Date: 2026-10-12

## Context

EEAP is a security posture, exposure and compliance platform for authorized enterprise
environments. Several assessed areas (service accounts with SPNs, accounts without
Kerberos pre-authentication, delegation, privileged groups, LAPS) are also topics of
offensive tooling. The platform must be clearly and verifiably defensive.

## Decision

The following are **out of scope and must not be implemented**: exploit execution,
credential extraction or cracking, ticket requests for offline cracking, authentication
bypass, attack automation, lateral movement, persistence, and any remote code/command
execution channel.

Architectural guardrails:

1. **Configuration reads only**: collectors read configuration attributes and policies
   (e.g. `userAccountControl` flags, `servicePrincipalName` presence,
   `msDS-AllowedToDelegateTo`, LAPS attribute *presence/schema*, registry policy values).
   They never request Kerberos service tickets/AS-REPs for cracking, never read password
   attributes or LAPS password values, and never authenticate as discovered accounts.
2. **No command channel** to agents (ADR-0008).
3. **Graph = exposure analysis**: path queries describe privilege relationships for
   remediation prioritization; the platform does not generate attack playbooks.
4. **LLM guardrails**: system prompts and output filters restrict content to
   explanation and remediation (ADR-0010).
5. **Evidence hygiene**: payload validator rejects secret-like material (hashes, keys,
   cleartext passwords).
6. **Authorization of scope**: assessment profiles require an explicit scope; network
   checks run only against assets/subnets registered in the inventory, and every run is audited.
7. **Code review rule**: PRs adding collectors must document the exact attributes/APIs read;
   CODEOWNERS for `app/controls/` and `agents/` include security engineering.

## Consequences

- (+) Safe to deploy in production and acceptable to enterprise change boards.
- (+) Clear boundary for contributors and auditors.
- (−) Some validations (e.g. "is this weak password actually crackable") are deliberately
  not possible; findings are based on configuration, which is the remediation lever anyway.
