import importlib

import pytest
from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
vulns = importlib.import_module("assessment_app.vulns")


@pytest.mark.parametrize(("a", "b"), [
    ("1.0~rc1", "1.0"), ("1.0", "1.0.1"), ("1.0", "1.0a"), ("2.0", "1:0.9"), ("1.0", "1.0.0"),
    ("1.2-1", "1.2-1+deb12u1"), ("2.36.1-8+deb12u1", "2.36.1-8+deb12u2"), ("3.0.11-1~deb12u1", "3.0.11-1"),
    ("1.9", "1.10"), ("0", "0.1"),
])
def test_dpkg_order(a, b):
    assert vulns.dpkg_compare(a, b) == -1
    assert vulns.dpkg_compare(b, a) == 1
    assert vulns.dpkg_compare(a, a) == 0


@pytest.mark.parametrize(("a", "b"), [
    ("1.0~rc1", "1.0"), ("1.0", "1.0^post1"), ("0:2.0-1.el9", "1:0.1-1.el9"), ("3.0.7-25.el9_3", "3.0.7-27.el9"),
    ("1.0a", "1.0.1"), ("2.0", "2.0.0"), ("5.14.0-427.13.1.el9_4", "5.14.0-427.20.1.el9_4"), ("1.9", "1.10"),
    ("0", "1:0.9.59-3.el8"),
])
def test_rpm_order(a, b):
    assert vulns.rpm_compare(a, b) == -1
    assert vulns.rpm_compare(b, a) == 1
    assert vulns.rpm_compare(a, a) == 0


@pytest.mark.parametrize(("a", "b"), [
    ("1.2.3-r0", "1.2.3-r1"), ("1.2.3_rc1-r0", "1.2.3-r0"), ("1.2.3-r5", "1.2.3_p1-r0"), ("1.2.9", "1.2.10"),
    ("3.3.1-r0", "3.3.2-r0"), ("2024a-r0", "2024b-r0"), ("1.36.1-r29", "1.36.1-r30"), ("1.2", "1.2.1"),
    ("0", "1.0-r0"),
])
def test_apk_order(a, b):
    assert vulns.apk_compare(a, b) == -1
    assert vulns.apk_compare(b, a) == 1
    assert vulns.apk_compare(a, a) == 0


@pytest.mark.parametrize(("vector", "score", "rating"), [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, None),
])
def test_cvss3_base_score(vector, score, rating):
    assert vulns.cvss3_base_score(vector) == score
    assert vulns.rating_from_score(score) == rating
    assert vulns.cvss3_base_score("garbage") is None


def test_advisory_severity_prefers_distribution_rating():
    cvss = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert vulns.advisory_severity({"summary": "Moderate: openssl security update", "severity": cvss}, {}) == "Medium"
    assert vulns.advisory_severity({"severity": cvss}, {"ecosystem_specific": {"urgency": "low**"}}) == "Low"
    assert vulns.advisory_severity({"severity": cvss}, {"ecosystem_specific": {"urgency": "not yet assigned"}}) \
        == "Critical"
    assert vulns.advisory_severity({}, {"severity": [{"type": "Ubuntu", "score": "high"}]}) == "High"
    assert vulns.advisory_severity({}, {}) == "Medium"


def _doc(advisory_id="CVE-2024-0001", ecosystems=("Debian:12",), events=({"introduced": "0"}, {"fixed": "1.2-3"}),
         **extra):
    return {"id": advisory_id, "aliases": ["GHSA-x"], "upstream": ["CVE-2024-0002"], **extra,
            "affected": [{"package": {"ecosystem": e, "name": "openssl"},
                          "ranges": [{"type": "ECOSYSTEM", "events": list(events)}]} for e in ecosystems]}


def test_parse_advisory_rows():
    ecosystems, rows = vulns.parse_advisory(_doc(ecosystems=("Debian:12", "Debian:11", "PyPI")))
    assert ecosystems == {"Debian:12", "Debian:11"}
    assert rows[0] == ("Debian:12", "openssl", "CVE-2024-0001", ["CVE-2024-0001", "CVE-2024-0002"], "Medium",
                       "0", "1.2-3")
    unfixed = vulns.parse_advisory(_doc(events=({"introduced": "0"},)))
    assert unfixed == ({"Debian:12"}, [])
    two = vulns.parse_advisory(_doc(events=({"introduced": "0"}, {"fixed": "1.0"}, {"introduced": "2.0"},
                                            {"fixed": "2.1"})))[1]
    assert [(r[5], r[6]) for r in two] == [("0", "1.0"), ("2.0", "2.1")]
    assert vulns.parse_advisory(_doc(withdrawn="2024-01-01T00:00:00Z")) == (set(), [])
    assert vulns.parse_advisory(_doc(advisory_id="ALEA-2021:1919")) == (set(), [])


def test_covered_ecosystems():
    per_release = [{"Debian:12", "Debian:11"}, {"Debian:12"}, {"Debian:12", "Debian:13", "Alpine:v3.20"}]
    assert vulns.covered_ecosystems(per_release) == {"Debian:12"}
    family = [{"Alpine:v3.19"}, {"Alpine:v3.20", "Debian:12"}, {"Alpine:v3.20"}]
    assert vulns.covered_ecosystems(family) == {"Alpine:v3.19", "Alpine:v3.20"}
    assert vulns.covered_ecosystems([set(), set()]) == set()


def test_host_ecosystems():
    assert vulns.host_ecosystems("alpine", "3.20.3") == ["Alpine:v3.20"]
    assert vulns.host_ecosystems("debian", "12") == ["Debian:12"]
    assert vulns.host_ecosystems("ubuntu", "22.04") == ["Ubuntu:22.04:LTS", "Ubuntu:22.04"]
    assert vulns.host_ecosystems("rocky", "9.4") == ["Rocky Linux:9"]
    assert vulns.host_ecosystems("almalinux", "8.10") == ["AlmaLinux:8"]
    assert vulns.host_ecosystems("arch", "") == []
    assert vulns.host_ecosystems("fedora", "40") == []


def test_parse_packages_formats():
    dpkg = vulns.parse_packages(["libssl3 3.0.11-1~deb12u2 openssl 3.0.11-1~deb12u2", "bash 5.2.15-2+b2 bash 5.2.15-2",
                                 "broken"], "dpkg")
    assert dpkg == [
        {"name": "libssl3", "version": "3.0.11-1~deb12u2", "source": "openssl", "source_version": "3.0.11-1~deb12u2"},
        {"name": "bash", "version": "5.2.15-2+b2", "source": "bash", "source_version": "5.2.15-2"}]
    rpm = vulns.parse_packages(["openssl-libs 1:3.0.7-25.el9_3 openssl-3.0.7-25.el9_3.src.rpm",
                                "gpg-pubkey (none):abc-def (none)", "bash (none):5.1.8-6.el9 bash-5.1.8-6.el9.src.rpm"],
                               "rpm")
    assert rpm == [
        {"name": "openssl-libs", "version": "1:3.0.7-25.el9_3", "source": "openssl", "source_version": "1:3.0.7-25.el9_3"},
        {"name": "bash", "version": "0:5.1.8-6.el9", "source": "bash", "source_version": "0:5.1.8-6.el9"}]
    apk = vulns.parse_packages(["libcrypto3 3.3.1-r0 openssl 3.3.1-r0"], "apk")
    assert apk[0]["source"] == "openssl"


def _range(package, advisory_id, fixed, severity="High", introduced="0", cves=("CVE-1",)):
    return {"package": package, "advisory_id": advisory_id, "cves": list(cves), "severity": severity,
            "introduced": introduced, "fixed": fixed}


def test_match_packages_groups_by_source_and_respects_ranges():
    packages = [{"name": "libssl3", "version": "3.0.11-1~deb12u1", "source": "openssl", "source_version": "3.0.11-1~deb12u1"},
                {"name": "openssl", "version": "3.0.11-1~deb12u1", "source": "openssl", "source_version": "3.0.11-1~deb12u1"},
                {"name": "bash", "version": "5.2.15-2+b2", "source": "bash", "source_version": "5.2.15-2"},
                {"name": "zlib1g", "version": "1:1.2.13.dfsg-1", "source": "zlib", "source_version": "1:1.2.13.dfsg-1"}]
    ranges = [_range("openssl", "DSA-1", "3.0.11-1~deb12u2", "Critical", cves=("CVE-2024-1",)),
              _range("openssl", "CVE-2024-2", "3.0.13-1~deb12u1", "Medium", cves=("CVE-2024-2",)),
              _range("openssl", "CVE-2023-9", "3.0.11-1~deb12u1"),            # already fixed
              _range("bash", "CVE-2022-1", "5.2.15-3", introduced="5.2"),       # source version 5.2.15-2 is inside
              _range("zlib", "CVE-2018-1", "1:1.2.11", introduced="1:1.2.8"),   # installed is newer
              _range("curl", "CVE-2024-3", "8.0")]                              # not installed
    result = vulns.match_packages(packages, ranges, "Debian:12")
    assert [(g["package"], g["severity"], g["advisory_count"], g["fixed_version"]) for g in result] == [
        ("openssl", "Critical", 2, "3.0.13-1~deb12u1"), ("bash", "High", 1, "5.2.15-3")]
    assert result[0]["binaries"] == ["libssl3", "openssl"]
    assert result[0]["cves"] == ["CVE-2024-1", "CVE-2024-2"]
    assert vulns.match_packages(packages, ranges, "Fedora:40") == []


def test_match_packages_rpm_uses_binary_names_and_module_streams():
    packages = vulns.parse_packages([
        "openssl-libs 1:3.0.7-24.el9 openssl-3.0.7-24.el9.src.rpm",
        "python39-Cython 0:0.29.21-5.module_el8.6.0+2780+a40f65e1 python39-Cython-0.29.21-5.src.rpm"], "rpm")
    ranges = [_range("openssl-libs", "RLSA-2024:1", "1:3.0.7-25.el9_3"),
              _range("python39-Cython", "ALSA-2021:1", "0.29.21-5.module_el8.6.0+2780+a40f65e1"),
              _range("python39-Cython", "ALSA-2021:2", "0.29.22-1.el8")]   # non-module build: not comparable
    result = vulns.match_packages(packages, ranges, "Rocky Linux:9")
    assert [(g["package"], g["binaries"], g["advisory_count"]) for g in result] == [("openssl", ["openssl-libs"], 1)]
