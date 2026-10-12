"""Read-only Active Directory configuration collector (LDAPS).

Guardrails (ADR-0011): the collector binds as the configured reader account, issues LDAP searches
only, and requests an explicit attribute allowlist. Password, password-history and LAPS password
attributes are never requested; no Kerberos operations are performed. The attribute list is
documented in docs/architecture/11-ad-assessment.md and must be updated with any change here.
"""
from __future__ import annotations

import ssl
import struct
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import ldap3
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from ..config import AdTarget

ROOT_DSE_ATTRIBUTES = ("defaultNamingContext", "schemaNamingContext", "dnsHostName")
DOMAIN_ATTRIBUTES = ("distinguishedName", "objectSid", "minPwdLength", "pwdHistoryLength", "pwdProperties",
                     "maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration", "msDS-Behavior-Version")
ACCOUNT_ATTRIBUTES = ("distinguishedName", "sAMAccountName", "objectSid", "userAccountControl",
                      "servicePrincipalName", "pwdLastSet", "adminCount", "msDS-SupportedEncryptionTypes",
                      "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                      "lastLogonTimestamp", "primaryGroupID")
COMPUTER_ATTRIBUTES = ACCOUNT_ATTRIBUTES + ("dNSHostName", "operatingSystem", "operatingSystemVersion",
                                            "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime")
MEMBER_ATTRIBUTES = ("distinguishedName", "sAMAccountName", "objectSid", "objectClass", "userAccountControl")
GROUP_ATTRIBUTES = ("distinguishedName", "sAMAccountName", "objectSid")
SCHEMA_ATTRIBUTES = ("lDAPDisplayName",)

ALLOWED_ATTRIBUTES = frozenset(a.lower() for a in (
    ROOT_DSE_ATTRIBUTES + DOMAIN_ATTRIBUTES + COMPUTER_ATTRIBUTES + MEMBER_ATTRIBUTES + GROUP_ATTRIBUTES
    + SCHEMA_ATTRIBUTES))
# Never requested, regardless of the allowlist: secrets and wildcard selectors.
DENIED_ATTRIBUTES = frozenset(a.lower() for a in (
    "*", "+", "unicodePwd", "userPassword", "ntPwdHistory", "lmPwdHistory", "dBCSPwd", "supplementalCredentials",
    "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory", "msDS-ManagedPassword",
    "msFVE-RecoveryPassword", "msDS-KeyCredentialLink", "unixUserPassword", "msSFU30Password",
    "currentValue", "priorValue", "trustAuthIncoming", "trustAuthOutgoing", "initialAuthIncoming",
    "initialAuthOutgoing"))
assert not ALLOWED_ATTRIBUTES & DENIED_ATTRIBUTES

# Privileged groups by well-known RID (domain-relative) or SID (builtin).
PRIVILEGED_DOMAIN_RIDS = {512: "Domain Admins", 518: "Schema Admins", 519: "Enterprise Admins"}
PRIVILEGED_BUILTIN_SIDS = {"S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators",
                           "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
                           "S-1-5-32-551": "Backup Operators"}
LAPS_SCHEMA_ATTRIBUTES = {"legacy": "ms-Mcs-AdmPwdExpirationTime", "windows": "msLAPS-PasswordExpirationTime"}

UAC_SERVER_TRUST_ACCOUNT = 0x2000
DC_PRIMARY_GROUP_IDS = (516, 521)
_NEVER = (0, 0x7FFFFFFFFFFFFFFF)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
PAGE_SIZE = 500


class AdCollectionError(RuntimeError):
    """Collection failed; the message is safe to store and show (contains no secrets)."""


def check_attributes(attributes: Iterable[str]) -> list[str]:
    requested = list(attributes)
    for attribute in requested:
        name = attribute.lower()
        if name in DENIED_ATTRIBUTES or name not in ALLOWED_ATTRIBUTES:
            raise AdCollectionError(f"attribute {attribute!r} is not on the collector allowlist")
    return requested


class ReadOnlyDirectory:
    """Exposes LDAP search only, restricted to the attribute allowlist."""

    def __init__(self, connection: ldap3.Connection, max_objects: int):
        self._conn = connection
        self._max_objects = max_objects
        self._returned = 0

    def read(self, dn: str, attributes: Iterable[str]) -> dict[str, list[bytes]] | None:
        self._conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=check_attributes(attributes))
        entries = [e for e in self._conn.response or [] if e.get("type") == "searchResEntry"]
        return _normalize(entries[0]) if entries else None

    def search(self, base: str, ldap_filter: str, attributes: Iterable[str],
               scope: str = ldap3.SUBTREE) -> list[dict[str, list[bytes]]]:
        results = []
        for entry in self._conn.extend.standard.paged_search(
                base, ldap_filter, search_scope=scope, attributes=check_attributes(attributes),
                paged_size=PAGE_SIZE, generator=True):
            if entry.get("type") != "searchResEntry":
                continue
            self._returned += 1
            if self._returned > self._max_objects:
                raise AdCollectionError(f"directory returned more than {self._max_objects} objects")
            results.append(_normalize(entry))
        return results


def _normalize(entry: dict) -> dict[str, list[bytes]]:
    raw = {k.lower(): v for k, v in entry.get("raw_attributes", {}).items()}
    if not raw.get("distinguishedname"):
        raw["distinguishedname"] = [entry["dn"].encode()]
    return raw


# ------------------------------------------------------------------------------------- value parsing

def _str(raw: dict, attribute: str) -> str | None:
    values = raw.get(attribute.lower()) or []
    return values[0].decode("utf-8", "replace") if values else None


def _strs(raw: dict, attribute: str) -> list[str]:
    return [v.decode("utf-8", "replace") for v in raw.get(attribute.lower()) or []]


def _int(raw: dict, attribute: str) -> int | None:
    value = _str(raw, attribute)
    return int(value) if value not in (None, "") else None


def _present(raw: dict, attribute: str) -> bool:
    return bool(raw.get(attribute.lower()))


def sid_to_str(value: bytes) -> str:
    count = value[1]
    authority = int.from_bytes(value[2:8], "big")
    subs = struct.unpack(f"<{count}I", value[8:8 + 4 * count])
    return f"S-{value[0]}-{authority}" + "".join(f"-{s}" for s in subs)


def _sid(raw: dict) -> str | None:
    values = raw.get("objectsid") or []
    return sid_to_str(values[0]) if values else None


def filetime_to_iso(value: int | None) -> str | None:
    if value is None or value in _NEVER or value < 0:
        return None
    return (_FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat()


def interval_days(value: int | None) -> float | None:
    """AD stores policy durations as negative 100 ns intervals; 0 and the minimum value mean 'none'."""
    if value is None:
        return None
    if value == -0x8000000000000000:
        return 0.0
    return round(abs(value) / 864_000_000_000, 2)


def dn_to_dns(dn: str) -> str:
    return ".".join(part.split("=", 1)[1] for part in dn.split(",") if part.strip().upper().startswith("DC="))


def _account(raw: dict) -> dict:
    uac = _int(raw, "userAccountControl") or 0
    return {
        "dn": _str(raw, "distinguishedName"),
        "sam": _str(raw, "sAMAccountName"),
        "sid": _sid(raw),
        "uac": uac,
        "enabled": not uac & 0x2,
        "spns": _strs(raw, "servicePrincipalName"),
        "pwd_last_set": filetime_to_iso(_int(raw, "pwdLastSet")),
        "admin_count": _int(raw, "adminCount") or 0,
        "encryption_types": _int(raw, "msDS-SupportedEncryptionTypes"),
        "delegate_to": _strs(raw, "msDS-AllowedToDelegateTo"),
        "rbcd_configured": _present(raw, "msDS-AllowedToActOnBehalfOfOtherIdentity"),
        "last_logon": filetime_to_iso(_int(raw, "lastLogonTimestamp")),
        "primary_group_id": _int(raw, "primaryGroupID"),
    }


def _computer(raw: dict) -> dict:
    account = _account(raw)
    sam = account["sam"] or ""
    return {
        **account,
        "name": sam.rstrip("$"),
        "dns_host_name": _str(raw, "dNSHostName"),
        "os": _str(raw, "operatingSystem"),
        "os_version": _str(raw, "operatingSystemVersion"),
        "is_dc": bool(account["uac"] & UAC_SERVER_TRUST_ACCOUNT)
                 or account["primary_group_id"] in DC_PRIMARY_GROUP_IDS,
        "laps_legacy_managed": _present(raw, "ms-Mcs-AdmPwdExpirationTime"),
        "laps_windows_managed": _present(raw, "msLAPS-PasswordExpirationTime"),
    }


# ------------------------------------------------------------------------------------------ collection

def connect(target: AdTarget) -> ldap3.Connection:
    url = urlparse(target.ldap_url)
    if url.scheme != "ldaps" or not url.hostname:
        raise AdCollectionError("AD_LDAP_URL must be an ldaps:// URL; plaintext LDAP is not supported")
    tls = ldap3.Tls(ca_certs_file=target.ca_file, validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
    server = ldap3.Server(url.hostname, port=url.port or 636, use_ssl=True, tls=tls, get_info=ldap3.NONE,
                          connect_timeout=target.timeout_seconds)
    try:
        return ldap3.Connection(server, user=target.bind_user, password=target.bind_password,
                                authentication=ldap3.SIMPLE, read_only=True, auto_bind=True,
                                receive_timeout=target.timeout_seconds, raise_exceptions=True)
    except LDAPException as exc:
        raise AdCollectionError(f"LDAP bind to {url.hostname} failed: {type(exc).__name__}") from exc


def collect(target: AdTarget, now: datetime | None = None) -> dict:
    """Returns a JSON-serializable configuration snapshot of the domain."""
    connection = connect(target)
    try:
        return _collect(ReadOnlyDirectory(connection, target.max_objects), target, now or datetime.now(UTC))
    except LDAPException as exc:
        raise AdCollectionError(f"LDAP search failed: {type(exc).__name__}: {str(exc)[:200]}") from exc
    finally:
        connection.unbind()


def _collect(directory: ReadOnlyDirectory, target: AdTarget, now: datetime) -> dict:
    root = directory.read("", ROOT_DSE_ATTRIBUTES) or {}
    base_dn = target.base_dn or _str(root, "defaultNamingContext")
    schema_dn = _str(root, "schemaNamingContext")
    if not base_dn:
        raise AdCollectionError("could not determine the domain naming context")

    domain_raw = directory.read(base_dn, DOMAIN_ATTRIBUTES)
    if domain_raw is None:
        raise AdCollectionError(f"domain object {base_dn} not readable")
    domain_sid = _sid(domain_raw)
    domain = {
        "dn": base_dn,
        "dns_name": dn_to_dns(base_dn).lower(),
        "sid": domain_sid,
        "functional_level": _int(domain_raw, "msDS-Behavior-Version"),
        "policy": {
            "min_password_length": _int(domain_raw, "minPwdLength"),
            "password_history_length": _int(domain_raw, "pwdHistoryLength"),
            "complexity_enabled": bool((_int(domain_raw, "pwdProperties") or 0) & 0x1),
            "reversible_encryption": bool((_int(domain_raw, "pwdProperties") or 0) & 0x10),
            "max_password_age_days": interval_days(_int(domain_raw, "maxPwdAge")),
            "min_password_age_days": interval_days(_int(domain_raw, "minPwdAge")),
            "lockout_threshold": _int(domain_raw, "lockoutThreshold"),
            "lockout_duration_minutes": (lambda d: None if d is None else round(d * 1440))(
                interval_days(_int(domain_raw, "lockoutDuration"))),
        },
    }

    users = [_account(r) for r in directory.search(
        base_dn, "(&(objectClass=user)(!(objectClass=computer)))", ACCOUNT_ATTRIBUTES)]
    computers = [_computer(r) for r in directory.search(base_dn, "(objectClass=computer)", COMPUTER_ATTRIBUTES)]

    groups = []
    wanted = {f"{domain_sid}-{rid}": name for rid, name in PRIVILEGED_DOMAIN_RIDS.items()} if domain_sid else {}
    wanted.update(PRIVILEGED_BUILTIN_SIDS)
    for sid, default_name in wanted.items():
        found = directory.search(base_dn, f"(objectSid={escape_filter_chars(sid)})", GROUP_ATTRIBUTES)
        if not found:
            continue
        group_dn = _str(found[0], "distinguishedName")
        members = []
        for raw in directory.search(
                base_dn, f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)})", MEMBER_ATTRIBUTES):
            classes = {c.lower() for c in _strs(raw, "objectClass")}
            kind = "computer" if "computer" in classes else "user" if "user" in classes else "group"
            uac = _int(raw, "userAccountControl") or 0
            members.append({"dn": _str(raw, "distinguishedName"), "sam": _str(raw, "sAMAccountName"),
                            "sid": _sid(raw), "kind": kind, "enabled": kind == "group" or not uac & 0x2})
        groups.append({"sid": sid, "name": _str(found[0], "sAMAccountName") or default_name, "dn": group_dn,
                       "members": sorted(members, key=lambda m: (m["kind"], (m["sam"] or "").lower()))})

    laps_schema = {key: False for key in LAPS_SCHEMA_ATTRIBUTES}
    if schema_dn:
        names = {(_str(r, "lDAPDisplayName") or "").lower() for r in directory.search(
            schema_dn, "(|" + "".join(f"(lDAPDisplayName={a})" for a in LAPS_SCHEMA_ATTRIBUTES.values()) + ")",
            SCHEMA_ATTRIBUTES, scope=ldap3.LEVEL)}
        laps_schema = {key: attr.lower() in names for key, attr in LAPS_SCHEMA_ATTRIBUTES.items()}

    return {
        "collector": "eeap-ad-ldap/1.0",
        "collected_at": now.isoformat(),
        "server": _str(root, "dnsHostName"),
        "domain": domain,
        "users": sorted(users, key=lambda u: u["dn"] or ""),
        "computers": sorted(computers, key=lambda c: c["dn"] or ""),
        "privileged_groups": groups,
        "laps_schema": laps_schema,
    }
