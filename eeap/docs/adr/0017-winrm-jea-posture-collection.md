# ADR-0017: Credentialed Windows posture over WinRM through a JEA endpoint

- Status: Accepted
- Date: 2026-10-12

## Context

WIN-003 (NTLM), WIN-004 / WIN-005 (LDAP signing and channel binding on DCs), WIN-007 (local
Administrators) and WIN-009 (endpoint protection) are host settings that cannot be observed on the
network. EEAP is deployed on one server that assesses other servers by IP. ADR-0008 plans pull-based
agents, but installing and operating an agent on every Windows host is a large rollout. WinRM is
built into Windows, yet a normal WinRM session with an administrative account gives the scanner a
full remote shell on every target, which conflicts with ADR-0011.

## Decision

- The assessment worker connects over WinRM (HTTPS 5986 by default) to a **Just Enough
  Administration** endpoint `EEAP.Posture` that each target registers with
  `infrastructure/windows/jea/Install-EeapJea.ps1`.
- The endpoint runs in `NoLanguage` mode, exposes exactly one function,
  `Get-EeapSecurityPosture` (read-only registry, CIM, local group and Defender queries), and
  returns one JSON document (`eeap.windows.posture/1`). The function lives in a module under
  Program Files, so the scanner account cannot change it.
- The scanner account is an ordinary domain user that is only granted access to that endpoint.
  Commands run as a virtual account (member servers) or a gMSA (domain controllers, where virtual
  accounts are not available). Transcripts are written on the target.
- Authentication: Kerberos by default (needs PTR records for the target IPs), `negotiate` and
  `ntlm` opt-in; Basic and CredSSP are not supported. Message encryption is forced on HTTP.
- The password is a Docker secret (`secrets/winrm_password`, ADR-0013) mounted on workers only.
  Without `WINRM_USERNAME` the WinRM controls are dropped from NET runs.
- Hosts where collection fails keep their open WinRM findings unchanged (no false resolution);
  the failure stage is stored in the run evidence.

## Consequences

- (+) No agent rollout; the controls work with built-in Windows features.
- (+) A stolen scanner credential can only read the posture document, not run commands.
- (−) Each target needs the JEA endpoint registered (GPO startup script or configuration
  management), and WinRM HTTPS listeners need certificates.
- (−) Kerberos requires reverse DNS and Kerberos libraries in the worker image.
- (−) Results reflect the moment of the scan; continuous monitoring still needs agents (ADR-0008).
