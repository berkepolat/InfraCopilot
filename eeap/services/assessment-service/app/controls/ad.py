"""AD-001..AD-010 evaluators. Pure functions over a configuration snapshot (collectors/ad_ldap.py).

Evaluators report configuration states only. Per-object controls emit FAIL/WARNING/INFO for the
objects that need attention; objects that no longer appear are resolved by the orchestrator.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..domain import ImportRow

SOURCE_TOOL = "eeap-ad-ldap/1.0"
AD_CONTROL_IDS = tuple(f"AD-{n:03d}" for n in range(1, 11))

UAC_ACCOUNTDISABLE = 0x2
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
ENC_DES = 0x3
ENC_AES = 0x18

SERVICE_ACCOUNT_MAX_PASSWORD_AGE_DAYS = 365
DOMAIN_ADMINS_MAX_MEMBERS = 5
EOL_WARNING_DAYS = 180

# (pattern, end of extended support). Order matters: more specific patterns first.
OS_END_OF_SUPPORT: tuple[tuple[str, str], ...] = (
    (r"windows server 2003", "2015-07-14"),
    (r"windows server 2008", "2020-01-14"),
    (r"windows server 2012", "2023-10-10"),
    (r"windows server 2016", "2027-01-12"),
    (r"windows server 2019", "2029-01-09"),
    (r"windows xp", "2014-04-08"),
    (r"windows vista", "2017-04-11"),
    (r"windows 7\b", "2020-01-14"),
    (r"windows 8\.1", "2023-01-10"),
    (r"windows 8\b", "2016-01-12"),
    (r"windows 10(?!.*\blts[bc]\b)", "2025-10-14"),
)

_ASSET_ID_INVALID = re.compile(r"[^A-Za-z0-9._-]")


def asset_id_for(name: str) -> str:
    value = _ASSET_ID_INVALID.sub("-", name.strip().upper())[:64]
    return value if value[:1].isalnum() else f"H{value}"[:64]


@dataclass
class Evaluation:
    domain_asset_id: str
    observations: list[ImportRow] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    evaluated_controls: list[str] = field(default_factory=list)


class _Context:
    def __init__(self, snapshot: dict, now: datetime):
        self.snapshot = snapshot
        self.now = now
        self.domain = snapshot["domain"]
        self.domain_asset_id = asset_id_for(self.domain["dns_name"])
        self.privileged: dict[str, list[str]] = {}
        for group in snapshot["privileged_groups"]:
            for member in group["members"]:
                if member["kind"] != "group" and member["dn"]:
                    self.privileged.setdefault(member["dn"], []).append(group["name"])
        self.dc_hosts = set()
        for computer in snapshot["computers"]:
            if computer["is_dc"]:
                self.dc_hosts.add(computer["name"].lower())
                if computer["dns_host_name"]:
                    self.dc_hosts.add(computer["dns_host_name"].lower())
        self.accounts_by_dn = {a["dn"]: a for a in snapshot["users"] + snapshot["computers"]}
        self.rows: list[ImportRow] = []

    def computer_asset(self, computer: dict) -> str:
        return asset_id_for(computer["name"])

    def emit(self, control_id: str, status: str, *, subject: str, summary: str, asset_id: str | None = None,
             severity: str | None = None, **details) -> None:
        self.rows.append(ImportRow(
            asset_id=asset_id or self.domain_asset_id, control_id=control_id, status=status, severity=severity,
            subject_key=subject, evidence={"summary": summary, **details},
            raw_data={"domain": self.domain["dns_name"]}, source_tool=SOURCE_TOOL))

    def account_target(self, account: dict) -> str:
        return self.computer_asset(account) if "is_dc" in account else self.domain_asset_id

    def password_age_days(self, account: dict) -> float | None:
        if not account["pwd_last_set"]:
            return None
        return (self.now - datetime.fromisoformat(account["pwd_last_set"])).total_seconds() / 86400


def _ad001_password_policy(ctx: _Context) -> None:
    p = ctx.domain["policy"]
    fail, warn = [], []
    min_length = p["min_password_length"] or 0
    if min_length < 8:
        fail.append(f"minimum password length is {min_length} (below 8)")
    elif min_length < 14:
        warn.append(f"minimum password length is {min_length} (CIS benchmark: 14)")
    if not p["complexity_enabled"]:
        (fail if min_length < 14 else warn).append("password complexity is disabled")
    if p["reversible_encryption"]:
        fail.append("passwords are stored with reversible encryption")
    if (p["password_history_length"] or 0) < 24:
        warn.append(f"password history is {p['password_history_length'] or 0} (CIS benchmark: 24)")
    threshold = p["lockout_threshold"] or 0
    if threshold == 0:
        fail.append("account lockout is disabled (threshold 0)")
    elif threshold > 10:
        warn.append(f"account lockout threshold is {threshold} (CIS benchmark: 5 or fewer)")
    status = "FAIL" if fail else "WARNING" if warn else "PASS"
    severity = "High" if min_length < 8 or p["reversible_encryption"] else None
    ctx.emit("AD-001", status, subject="default-domain-password-policy", severity=severity,
             summary="; ".join(fail + warn) or "domain password policy meets the baseline",
             issues=fail + warn, policy=p)


def _ad002_service_accounts(ctx: _Context) -> None:
    for user in ctx.snapshot["users"]:
        if not user["spns"] or not user["enabled"] or (user["sam"] or "").lower() == "krbtgt":
            continue
        fail, warn = [], []
        groups = ctx.privileged.get(user["dn"], [])
        if groups:
            fail.append(f"member of privileged groups: {', '.join(sorted(set(groups)))}")
        elif user["admin_count"]:
            warn.append("adminCount=1 (currently or formerly protected account)")
        age = ctx.password_age_days(user)
        if age is None:
            warn.append("password last-set time is not available")
        elif age > SERVICE_ACCOUNT_MAX_PASSWORD_AGE_DAYS:
            fail.append(f"password not changed for {int(age)} days")
        if user["uac"] & UAC_DONT_EXPIRE_PASSWORD:
            warn.append("password is set to never expire")
        if user["uac"] & UAC_USE_DES_KEY_ONLY:
            fail.append("account is restricted to DES encryption")
        enc = user["encryption_types"]
        if not enc or not enc & ENC_AES:
            warn.append("AES is not enabled for Kerberos (RC4 is used)")
        elif enc & ENC_DES:
            warn.append("DES encryption types are enabled")
        if not fail and not warn:
            continue
        ctx.emit("AD-002", "FAIL" if fail else "WARNING", subject=user["dn"],
                 severity="Critical" if groups else "High" if fail else "Medium",
                 summary=f"{user['sam']}: " + "; ".join(fail + warn), account=user["sam"],
                 spns=user["spns"][:20], issues=fail + warn, password_age_days=None if age is None else int(age))


def _ad003_preauth(ctx: _Context) -> None:
    for account in ctx.snapshot["users"] + ctx.snapshot["computers"]:
        if not account["uac"] & UAC_DONT_REQ_PREAUTH:
            continue
        groups = ctx.privileged.get(account["dn"], [])
        if account["enabled"]:
            ctx.emit("AD-003", "FAIL", subject=account["dn"], asset_id=ctx.account_target(account),
                     severity="Critical" if groups else None, account=account["sam"],
                     summary=f"{account['sam']}: Kerberos pre-authentication is not required")
        else:
            ctx.emit("AD-003", "WARNING", subject=account["dn"], asset_id=ctx.account_target(account),
                     severity="Low", account=account["sam"],
                     summary=f"{account['sam']} (disabled) does not require Kerberos pre-authentication")


def _ad004_unconstrained(ctx: _Context) -> None:
    for account in ctx.snapshot["users"] + ctx.snapshot["computers"]:
        if not account["uac"] & UAC_TRUSTED_FOR_DELEGATION or account.get("is_dc"):
            continue
        kind = "computer" if "is_dc" in account else "user account"
        if account["enabled"]:
            ctx.emit("AD-004", "FAIL", subject=account["dn"], asset_id=ctx.account_target(account),
                     account=account["sam"], summary=f"{kind} {account['sam']} is trusted for unconstrained delegation")
        else:
            ctx.emit("AD-004", "WARNING", subject=account["dn"], asset_id=ctx.account_target(account),
                     severity="Low", account=account["sam"],
                     summary=f"disabled {kind} {account['sam']} is trusted for unconstrained delegation")


def _spn_host(spn: str) -> str:
    host = spn.split("/", 2)[1] if "/" in spn else spn
    return host.split(":", 1)[0].lower()


def _ad005_constrained(ctx: _Context) -> None:
    for account in ctx.snapshot["users"] + ctx.snapshot["computers"]:
        if not account["delegate_to"] or not account["enabled"]:
            continue
        dc_targets = [t for t in account["delegate_to"] if _spn_host(t) in ctx.dc_hosts]
        transition = bool(account["uac"] & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        issues = []
        if transition:
            issues.append("protocol transition is enabled (any authentication)")
        if dc_targets:
            issues.append(f"delegates to domain controller services: {', '.join(dc_targets[:10])}")
        severity = "Critical" if transition and dc_targets else "High" if issues else "Low"
        ctx.emit("AD-005", "FAIL" if issues else "WARNING", subject=account["dn"],
                 asset_id=ctx.account_target(account), severity=severity, account=account["sam"],
                 summary=f"{account['sam']}: constrained delegation to {len(account['delegate_to'])} service(s)"
                         + (f"; {'; '.join(issues)}" if issues else ""),
                 delegate_to=account["delegate_to"][:50], protocol_transition=transition)


def _ad006_rbcd(ctx: _Context) -> None:
    for account in ctx.snapshot["users"] + ctx.snapshot["computers"]:
        if not account["rbcd_configured"] or not account["enabled"]:
            continue
        sensitive = account.get("is_dc") or account["dn"] in ctx.privileged
        ctx.emit("AD-006", "FAIL" if sensitive else "WARNING", subject=account["dn"],
                 asset_id=ctx.account_target(account), severity="High" if sensitive else None,
                 account=account["sam"],
                 summary=f"{account['sam']} has resource-based constrained delegation configured"
                         + (" on a Tier-0 object" if sensitive else ""))


def _ad007_privileged_groups(ctx: _Context) -> None:
    for group in ctx.snapshot["privileged_groups"]:
        accounts = [m for m in group["members"] if m["kind"] != "group"]
        enabled = [m for m in accounts if m["enabled"]]
        disabled = [m for m in accounts if not m["enabled"]]
        fail, warn = [], []
        rid = group["sid"].rsplit("-", 1)[-1]
        builtin = group["sid"].startswith("S-1-5-32-")
        if not builtin and rid == "512" and len(enabled) > DOMAIN_ADMINS_MAX_MEMBERS:
            fail.append(f"{len(enabled)} enabled members (recommended: {DOMAIN_ADMINS_MAX_MEMBERS} or fewer)")
        if not builtin and rid in ("518", "519") and enabled:
            warn.append(f"{len(enabled)} members; keep empty except during planned changes")
        if builtin and rid in ("548", "549", "550", "551") and enabled:
            warn.append(f"operator group has {len(enabled)} members; delegate narrower rights instead")
        service = [m["sam"] for m in enabled if ctx.accounts_by_dn.get(m["dn"], {}).get("spns")
                   and m["kind"] == "user"]
        if service:
            fail.append(f"service accounts with SPNs are members: {', '.join(service[:20])}")
        if disabled:
            warn.append(f"{len(disabled)} disabled accounts retain membership")
        if not fail and not warn:
            continue
        ctx.emit("AD-007", "FAIL" if fail else "WARNING", subject=group["sid"],
                 severity=None if fail else "Medium",
                 summary=f"{group['name']}: " + "; ".join(fail + warn), group=group["name"],
                 issues=fail + warn, enabled_members=[m["sam"] for m in enabled][:100],
                 disabled_members=[m["sam"] for m in disabled][:100],
                 nested_groups=[m["sam"] for m in group["members"] if m["kind"] == "group"][:50])


def _ad008_laps(ctx: _Context) -> None:
    schema = ctx.snapshot["laps_schema"]
    if not any(schema.values()):
        ctx.emit("AD-008", "FAIL", subject="laps-schema",
                 summary="no LAPS schema is present; local administrator passwords are not centrally rotated",
                 laps_schema=schema)
        return
    for computer in ctx.snapshot["computers"]:
        if computer["is_dc"] or not computer["enabled"]:
            continue
        if computer["laps_legacy_managed"] or computer["laps_windows_managed"]:
            continue
        ctx.emit("AD-008", "FAIL", subject=computer["dn"], asset_id=ctx.computer_asset(computer),
                 summary=f"{computer['name']} has no LAPS-managed local administrator password",
                 laps_schema=schema)


def _ad009_legacy_os(ctx: _Context) -> None:
    for computer in ctx.snapshot["computers"]:
        if not computer["enabled"] or not computer["os"]:
            continue
        os_name = computer["os"].lower()
        for pattern, end in OS_END_OF_SUPPORT:
            if re.search(pattern, os_name):
                break
        else:
            continue
        end_date = datetime.fromisoformat(end).replace(tzinfo=ctx.now.tzinfo)
        days_left = (end_date - ctx.now).days
        if days_left > EOL_WARNING_DAYS:
            continue
        expired = days_left < 0
        ctx.emit("AD-009", "FAIL" if expired else "WARNING", subject="operating-system",
                 asset_id=ctx.computer_asset(computer), severity=None if expired else "Medium",
                 summary=f"{computer['name']} runs {computer['os']}, "
                         + (f"out of support since {end}" if expired else f"support ends {end}"),
                 operating_system=computer["os"], os_version=computer["os_version"], end_of_support=end)


def _ad010_tier0(ctx: _Context) -> None:
    ctx.emit("AD-010", "INFO", subject="domain", summary=f"AD domain {ctx.domain['dns_name']} (Tier 0 identity system)")
    for computer in ctx.snapshot["computers"]:
        if computer["is_dc"] and computer["enabled"]:
            ctx.emit("AD-010", "INFO", subject="domain-controller", asset_id=ctx.computer_asset(computer),
                     summary=f"{computer['name']} is a domain controller (Tier 0)")
    for dn, groups in sorted(ctx.privileged.items()):
        account = ctx.accounts_by_dn.get(dn)
        if account is None or not account["enabled"] or account.get("is_dc"):
            continue
        ctx.emit("AD-010", "INFO", subject=dn, asset_id=ctx.account_target(account), account=account["sam"],
                 groups=sorted(set(groups)),
                 summary=f"{account['sam']} is a Tier-0 account (member of {', '.join(sorted(set(groups)))})")


EVALUATORS: dict[str, Callable[[_Context], None]] = {
    "AD-001": _ad001_password_policy,
    "AD-002": _ad002_service_accounts,
    "AD-003": _ad003_preauth,
    "AD-004": _ad004_unconstrained,
    "AD-005": _ad005_constrained,
    "AD-006": _ad006_rbcd,
    "AD-007": _ad007_privileged_groups,
    "AD-008": _ad008_laps,
    "AD-009": _ad009_legacy_os,
    "AD-010": _ad010_tier0,
}


def discovered_assets(ctx: _Context) -> list[dict]:
    domain = ctx.domain
    assets = [{
        "asset_id": ctx.domain_asset_id, "hostname": domain["dns_name"], "fqdn": domain["dns_name"],
        "asset_type": "Identity", "os_family": None, "os_version": None, "domain": domain["dns_name"],
        "tags": ["ad:domain"],
        "identifiers": [i for i in ({"id_type": "ad_object_sid", "value": domain["sid"]},
                                    {"id_type": "ad_dn", "value": domain["dn"]},
                                    {"id_type": "fqdn", "value": domain["dns_name"]}) if i["value"]],
    }]
    for computer in ctx.snapshot["computers"]:
        if not computer["enabled"]:
            continue
        os_name = computer["os"] or ""
        if computer["is_dc"]:
            asset_type = "DomainController"
        elif "server" in os_name.lower():
            asset_type = "Server"
        elif os_name.lower().startswith("windows"):
            asset_type = "Workstation"
        else:
            asset_type = "Other"
        tags = ["ad:computer"] + (["ad:tier0"] if computer["dn"] in ctx.privileged else [])
        assets.append({
            "asset_id": ctx.computer_asset(computer), "hostname": computer["name"],
            "fqdn": computer["dns_host_name"], "asset_type": asset_type,
            "os_family": "Windows" if os_name.lower().startswith("windows") else None,
            "os_version": " ".join(v for v in (computer["os"], computer["os_version"]) if v) or None,
            "domain": domain["dns_name"], "tags": tags,
            "identifiers": [i for i in ({"id_type": "ad_object_sid", "value": computer["sid"]},
                                        {"id_type": "ad_dn", "value": computer["dn"]},
                                        {"id_type": "fqdn", "value": computer["dns_host_name"]},
                                        {"id_type": "hostname", "value": computer["name"]}) if i["value"]],
        })
    return assets


def evaluate(snapshot: dict, control_ids: list[str] | None, now: datetime) -> Evaluation:
    selected = [c for c in AD_CONTROL_IDS if control_ids is None or c in control_ids]
    ctx = _Context(snapshot, now)
    for control_id in selected:
        EVALUATORS[control_id](ctx)
    return Evaluation(domain_asset_id=ctx.domain_asset_id, observations=ctx.rows,
                      assets=discovered_assets(ctx), evaluated_controls=selected)
