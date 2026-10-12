# ADR-0021: Windows patch status from the Windows Update Agent cache

**Status:** Accepted
**Date:** 2026-10-12

## Context

Missing security updates and unsupported Windows releases are among the most common causes of
exposure. EEAP already reads Windows hosts through the `EEAP.Posture` JEA endpoint
([ADR-0017](0017-winrm-jea-posture-collection.md)). Options for patch status were:

1. Match the installed build/UBR or KB list against an uploaded Microsoft security update catalogue
   (MSRC CVRF), like OSV for Linux ([ADR-0019](0019-offline-osv-package-vulnerabilities.md)).
2. Ask the Windows Update Agent (WUA) on the host which applicable updates are not installed.
3. Query WSUS / Intune / Configuration Manager.

Option 1 needs a large catalogue, supersedence logic and per-product applicability rules that WUA
already implements. Option 3 depends on a product that not every customer runs. A live WUA search
(`Online = true`) contacts Windows Update or WSUS and can take minutes.

## Decision

* `Get-EeapSecurityPosture` (module 1.1.0) adds an `updates` section, still read-only:
  * `Win32_QuickFixEngineering` (installed KBs and dates),
  * `Microsoft.Update.AutoUpdate.Results` (last successful search and installation),
  * an **offline** WUA search (`IUpdateSearcher.Online = false`) over the host's own cached scan
    results: `IsInstalled=0 and IsHidden=0 and Type='Software'` (at most 200 entries) with title,
    KB, MSRC severity, CVEs and categories,
  * the reboot-pending registry markers, and `UBR`, `EditionID`, `InstallationType` for the build.
  Nothing is downloaded, installed or sent to an update server; the search runs in the existing
  trusted module (FullLanguage) behind the `NoLanguage` JEA session.
* Three controls evaluate it (`controls/win_host.py`):
  * **WIN-010** one FAIL per missing security update (subject `kb:<KB>`), severity from MSRC
    (Critical, Important → High, Moderate → Medium, Low), at least High when a fixed CVE is in the
    uploaded CISA KEV list; KEV/EPSS give the finding-level exploitability used by scoring model v2
    ([ADR-0020](0020-exploitation-and-exposure-in-risk-scoring.md)). A Low WARNING (`wu-scan`) flags
    a last WUA search older than 30 days, because the cached list is then stale.
  * **WIN-011** days since the newest installed update (> 35 WARNING, > 60 FAIL) and pending reboot.
  * **WIN-012** end of security updates per build and servicing class (Server, Home/Pro,
    Enterprise/Education, LTSC, IoT LTSC) from Microsoft's lifecycle pages; FAIL after the date,
    WARNING within 180 days. Extended Security Updates are not considered.
* Hosts with an older posture module (no `updates`) leave WIN-010/011 unassessed, so existing
  findings stay open instead of being resolved.

## Consequences

* Results are only as current as the host's last WUA scan; WIN-010 makes that visible instead of
  hiding it. Hosts managed by WSUS report what WSUS approved for them.
* The lifecycle table needs maintenance when Microsoft ships a new release; unknown builds produce
  no WIN-012 result.
* No new credentials, ports or privileges are required beyond ADR-0017.
