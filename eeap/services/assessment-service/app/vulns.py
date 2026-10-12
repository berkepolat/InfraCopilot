"""Known-vulnerable package matching against uploaded OSV data (LIN-009).

Pure functions: distribution version ordering (dpkg, rpm, apk), OSV record parsing, severity rating and
matching of a host's installed packages against fixed-version ranges. Only ranges with a fixed version are
used, so every finding has an available update.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Iterable
from typing import Any

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
# OSV ecosystem family -> version scheme
FAMILIES = {"Alpine": "apk", "Debian": "dpkg", "Ubuntu": "dpkg", "Rocky Linux": "rpm", "AlmaLinux": "rpm"}
# Bug-fix and enhancement advisories carry no security fix.
NON_SECURITY_PREFIXES = ("RLBA-", "RLEA-", "ALBA-", "ALEA-")


def family(ecosystem: str) -> str:
    return ecosystem.split(":", 1)[0]


# --------------------------------------------------------------------------------------- dpkg

def _dpkg_order(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < len(a) else "")
            bc = _dpkg_order(b[j] if j < len(b) else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff and a[i] != b[j]:
                first_diff = -1 if a[i] < b[j] else 1
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_evr(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    try:
        return int(epoch or 0), upstream, revision
    except ValueError:
        return 0, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _split_evr(a)
    eb, ub, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


# ---------------------------------------------------------------------------------------- rpm

def _rpm_segment(s: str, i: int) -> tuple[str, int, bool]:
    numeric = s[i].isdigit()
    j = i
    while j < len(s) and (s[j].isdigit() if numeric else (s[j].isascii() and s[j].isalpha())):
        j += 1
    return s[i:j], j, numeric


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0

    def skip(s: str, k: int) -> int:
        while k < len(s) and not (s[k].isascii() and s[k].isalnum()) and s[k] not in "~^":
            k += 1
        return k

    while i < len(a) or j < len(b):
        i, j = skip(a, i), skip(b, j)
        ca, cb = (a[i] if i < len(a) else ""), (b[j] if j < len(b) else "")
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not ca or not cb:
            break
        seg_a, i, numeric = _rpm_segment(a, i)
        seg_b, j_end, _ = (_rpm_segment(b, j) if b[j].isdigit() == numeric else ("", j, numeric))
        if not seg_b:
            return 1 if numeric else -1
        j = j_end
        if numeric:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return -1 if len(seg_a) < len(seg_b) else 1
        if seg_a != seg_b:
            return -1 if seg_a < seg_b else 1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return rpmvercmp(va, vb) or rpmvercmp(ra, rb)


# ---------------------------------------------------------------------------------------- apk

_APK = re.compile(r"(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?")
_APK_SUFFIX = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4, "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}


def _apk_key(version: str):
    m = _APK.fullmatch(version)
    if m is None:
        return None
    digits = m.group(1).split(".")
    suffixes = [(_APK_SUFFIX[name], int(num or 0))
                for name, num in re.findall(r"_([a-z]+)(\d*)", m.group(3))]
    return digits, m.group(2), suffixes, int(m.group(4) or 0)


def _apk_digits(a: list[str], b: list[str]) -> int:
    for index, (x, y) in enumerate(zip(a, b, strict=False)):
        if index and (x.startswith("0") or y.startswith("0")):
            fx, fy = float("0." + x), float("0." + y)
        else:
            fx, fy = int(x), int(y)
        if fx != fy:
            return -1 if fx < fy else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def apk_compare(a: str, b: str) -> int:
    ka, kb = _apk_key(a), _apk_key(b)
    if ka is None or kb is None:
        return dpkg_compare(a, b)
    if result := _apk_digits(ka[0], kb[0]):
        return result
    if ka[1] != kb[1]:
        return -1 if ka[1] < kb[1] else 1
    none = (_APK_SUFFIX[""], 0)
    for index in range(max(len(ka[2]), len(kb[2]))):
        sa = ka[2][index] if index < len(ka[2]) else none
        sb = kb[2][index] if index < len(kb[2]) else none
        if sa != sb:
            return -1 if sa < sb else 1
    return (ka[3] > kb[3]) - (ka[3] < kb[3])


COMPARATORS: dict[str, Callable[[str, str], int]] = {"dpkg": dpkg_compare, "rpm": rpm_compare, "apk": apk_compare}


def comparator(ecosystem: str) -> Callable[[str, str], int] | None:
    scheme = FAMILIES.get(family(ecosystem))
    return COMPARATORS[scheme] if scheme else None


# ----------------------------------------------------------------------------------- host side

def host_ecosystems(os_id: str | None, version_id: str | None) -> list[str]:
    """OSV ecosystems that describe this release (most specific first); empty when unsupported."""
    os_id, version = (os_id or "").lower(), version_id or ""
    major = version.split(".", 1)[0]
    if not major.isdigit():
        return []
    if os_id == "alpine" and (m := re.match(r"(\d+)\.(\d+)", version)):
        return [f"Alpine:v{m.group(1)}.{m.group(2)}"]
    if os_id == "debian":
        return [f"Debian:{major}"]
    if os_id == "ubuntu":
        return [f"Ubuntu:{version}:LTS", f"Ubuntu:{version}"]
    if os_id == "rocky":
        return [f"Rocky Linux:{major}"]
    if os_id == "almalinux":
        return [f"AlmaLinux:{major}"]
    return []


def parse_packages(values: Iterable[str], fmt: str | None) -> list[dict[str, str]]:
    """Posture "packages pkg" records: "<name> <version> <source> [<source version>]"."""
    packages = []
    for value in values:
        parts = value.split()
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        source = parts[2] if len(parts) > 2 else name
        source_version = parts[3] if len(parts) > 3 else version
        if fmt == "rpm":
            if name == "gpg-pubkey":
                continue
            version = version.replace("(none):", "0:")
            # SOURCERPM is "<name>-<version>-<release>.src.rpm"
            source = re.sub(r"-[^-]+-[^-]+\.(?:no)?src\.rpm$", "", source) if source.endswith("src.rpm") else name
            source_version = version
        packages.append({"name": name, "version": version, "source": source, "source_version": source_version})
    return packages


# ------------------------------------------------------------------------------------ severity

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(value: float) -> float:
    scaled = round(value * 100000)
    return scaled / 100000.0 if scaled % 10000 == 0 else (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope = metrics["S"]
        iss = 1 - math.prod(1 - _CVSS3["CIA"][metrics[k]] for k in ("C", "I", "A"))
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploitability = (8.22 * _CVSS3["AV"][metrics["AV"]] * _CVSS3["AC"][metrics["AC"]]
                          * _PR[scope][metrics["PR"]] * _CVSS3["UI"][metrics["UI"]])
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(total, 10.0))


def rating_from_score(score: float | None) -> str | None:
    if score is None or score <= 0:
        return None
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


_VENDOR = {"critical": "Critical", "important": "High", "high": "High", "moderate": "Medium", "medium": "Medium",
           "low": "Low", "negligible": "Low", "unimportant": "Low"}


def _vendor_rating(doc: dict, affected: dict) -> str | None:
    urgency = re.sub(r"[^a-z ]", "", str((affected.get("ecosystem_specific") or {}).get("urgency", "")).lower())
    if urgency in _VENDOR:
        return _VENDOR[urgency]
    for entry in (affected.get("severity") or []) + (doc.get("severity") or []):
        if entry.get("type") == "Ubuntu" and str(entry.get("score", "")).lower() in _VENDOR:
            return _VENDOR[str(entry["score"]).lower()]
    if m := re.match(r"(Critical|Important|Moderate|Low):", doc.get("summary") or ""):
        return _VENDOR[m.group(1).lower()]
    return None


def advisory_severity(doc: dict, affected: dict) -> str:
    """Distribution rating when present, else the CVSS v3 base score, else Medium."""
    if vendor := _vendor_rating(doc, affected):
        return vendor
    for entry in (affected.get("severity") or []) + (doc.get("severity") or []):
        if entry.get("type") == "CVSS_V3" and (rating := rating_from_score(cvss3_base_score(entry.get("score", "")))):
            return rating
    return "Medium"


# ----------------------------------------------------------------------------------- OSV records

def parse_advisory(doc: dict) -> tuple[set[str], list[tuple]]:
    """(ecosystems the record mentions, rows) where a row is
    (ecosystem, package, advisory_id, cves, severity, introduced, fixed)."""
    advisory_id = str(doc.get("id") or "")
    if not advisory_id or doc.get("withdrawn") or advisory_id.startswith(NON_SECURITY_PREFIXES):
        return set(), []
    cves = sorted({i for i in [advisory_id, *(doc.get("aliases") or []), *(doc.get("upstream") or [])]
                   if isinstance(i, str) and i.startswith("CVE-")})
    ecosystems: set[str] = set()
    rows: list[tuple] = []
    for affected in doc.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if not ecosystem or not name or family(ecosystem) not in FAMILIES:
            continue
        ecosystems.add(ecosystem)
        severity = None
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            introduced = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    introduced = str(event["introduced"])
                elif "fixed" in event and introduced is not None:
                    severity = severity or advisory_severity(doc, affected)
                    rows.append((ecosystem, name, advisory_id, cves, severity, introduced, str(event["fixed"])))
                    introduced = None
    return ecosystems, rows


def covered_ecosystems(record_ecosystems: list[set[str]]) -> set[str]:
    """Ecosystems a feed file is authoritative for.

    A per-release file (e.g. Debian:12/all.zip) mentions its release in every record and neighbouring
    releases only where a record spans several, so those are incomplete; a whole-family file
    (Debian/all.zip) covers every release of its dominant family.
    """
    records = [s for s in record_ecosystems if s]
    if not records:
        return set()
    families = Counter(f for s in records for f in {family(e) for e in s})
    dominant = families.most_common(1)[0][0]
    per_ecosystem = Counter(e for s in records for e in s if family(e) == dominant)
    specific = {e for e, n in per_ecosystem.items() if n == len(records)}
    return specific or set(per_ecosystem)


# ------------------------------------------------------------------------------------- matching

def _applicable(installed: str, fixed: str, scheme: str) -> bool:
    # RHEL-family module streams carry their own builds; compare module builds only with module builds.
    return scheme != "rpm" or ((".module" in installed) == (".module" in fixed))


def match_packages(packages: list[dict], ranges: list[dict], ecosystem: str, *, max_advisories: int = 50) -> list[dict]:
    """Vulnerable packages grouped by source package, worst first.

    ``ranges`` rows: package, advisory_id, cves, severity, introduced, fixed. An advisory applies when the
    installed version is inside every applicable range of that advisory for the package.
    """
    compare = comparator(ecosystem)
    scheme = FAMILIES.get(family(ecosystem))
    if compare is None:
        return []
    by_package: dict[str, dict[str, list[dict]]] = {}
    for r in ranges:
        by_package.setdefault(r["package"], {}).setdefault(r["advisory_id"], []).append(r)

    groups: dict[str, dict[str, Any]] = {}
    for pkg in packages:
        candidates = [(pkg["name"], pkg["version"])]
        if scheme != "rpm" and pkg["source"] != pkg["name"]:
            candidates.append((pkg["source"], pkg["source_version"]))
        for key, installed in candidates:
            for advisory_id, advisory_ranges in (by_package.get(key) or {}).items():
                usable = [r for r in advisory_ranges if _applicable(installed, r["fixed"], scheme)]
                if not usable or not all(
                        (r["introduced"] == "0" or compare(installed, r["introduced"]) >= 0)
                        and compare(installed, r["fixed"]) < 0 for r in usable):
                    continue
                group = groups.setdefault(pkg["source"], {"package": pkg["source"], "installed": installed,
                                                          "binaries": set(), "advisories": {}})
                group["binaries"].add(pkg["name"])
                fixed = max((r["fixed"] for r in usable), key=_sort_key(compare))
                group["advisories"].setdefault(advisory_id, {
                    "id": advisory_id, "cves": list(usable[0]["cves"] or []), "severity": usable[0]["severity"],
                    "fixed": fixed})

    results = []
    for group in groups.values():
        advisories = sorted(group["advisories"].values(),
                            key=lambda a: (-SEVERITY_ORDER.get(a["severity"], 1), a["id"]))
        fixed_version = max((a["fixed"] for a in advisories), key=_sort_key(compare))
        results.append({
            "package": group["package"], "installed": group["installed"], "fixed_version": fixed_version,
            "binaries": sorted(group["binaries"])[:20], "severity": advisories[0]["severity"],
            "advisory_count": len(advisories),
            "cves": sorted({c for a in advisories for c in a["cves"]})[:max_advisories],
            "advisories": advisories[:max_advisories],
        })
    return sorted(results, key=lambda g: (-SEVERITY_ORDER.get(g["severity"], 1), -g["advisory_count"], g["package"]))


def _sort_key(compare: Callable[[str, str], int]):
    import functools

    return functools.cmp_to_key(compare)
