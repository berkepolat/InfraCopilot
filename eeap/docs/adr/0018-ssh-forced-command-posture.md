# ADR-0018: Linux posture over SSH with a forced, read-only command

- Status: Accepted
- Date: 2026-10-12

## Context

Linux host settings (sshd configuration, pending updates, sudo rules, firewall, accounts, kernel
settings, file permissions, release lifecycle) cannot be observed on the network. EEAP runs on one
server and assesses hosts by IP; agents (ADR-0008) are not deployed. A normal SSH account for the
scanner would give it an interactive shell, often with sudo, on every Linux host, which conflicts with
ADR-0011. ADR-0017 solved the same problem for Windows with a JEA endpoint.

## Decision

- Each target installs `infrastructure/linux/install-eeap-posture.sh`, which creates the account
  `eeap-scan` (no usable password) and a root-owned `authorized_keys` entry for the scanner's public key
  with `restrict,command="sudo -n /usr/local/libexec/eeap/eeap-posture"` (optionally `from=`).
  Whatever the client requests, sshd runs only that command; PTYs and all forwarding are disabled.
- sudo allows exactly that root-owned script without arguments. The script only reads configuration
  (package managers in simulation / cache-only mode) and prints `section<TAB>key<TAB>value` records
  (`eeap.linux.posture/1`). It never prints password hashes, keys or file contents beyond the listed
  settings.
- The worker authenticates with an Ed25519 key only (Docker secret `linux_ssh_key`, ADR-0013); password
  authentication is not implemented.
- The host key is verified **before** authenticating: against `LINUX_SSH_KNOWN_HOSTS_FILE` when set,
  otherwise against the key pinned on first use in `assessment.ssh_host_keys`. A changed key fails the
  host (`hostkey`) until an operator with `assessments:manage` removes the pin.
- Hosts where collection fails or is skipped keep their open LIN findings unchanged.

## Consequences

- (+) No agent rollout; works with standard OpenSSH (7.2+) and sudo.
- (+) A stolen scanner key can only produce the posture output of hosts that trust it.
- (+) Host keys are checked, so the scanner does not report a spoofed host's posture.
- (−) Each target needs the installer (configuration management) and the posture script runs as root.
- (−) Trust on first use accepts whatever key is presented at the first scan; use a known_hosts file
  where host keys are managed centrally.
- (−) Results are a point-in-time snapshot; package results depend on the host's cached metadata.
