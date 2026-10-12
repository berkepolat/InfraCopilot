import importlib

import pytest

from conftest import load_service_package

load_service_package("assessment-service", "assessment_app")
targets = importlib.import_module("assessment_app.targets")


def test_parse_targets_normalizes_and_dedupes():
    assert targets.parse_targets(["10.0.0.1", "10.0.0.1", " 10.0.0.2 "]) == ["10.0.0.1", "10.0.0.2"]


def test_parse_targets_rejects_cidr_hostname_and_loopback():
    with pytest.raises(targets.TargetError, match="CIDR"):
        targets.parse_targets(["10.0.0.0/24"])
    with pytest.raises(targets.TargetError, match="not an IP"):
        targets.parse_targets(["dc1.lab.eeap.local"])
    with pytest.raises(targets.TargetError, match="not scannable"):
        targets.parse_targets(["127.0.0.1"])
    with pytest.raises(targets.TargetError, match="not scannable"):
        targets.parse_targets(["169.254.169.254"])


def test_authorize_requires_allow_list_and_membership():
    with pytest.raises(targets.TargetError, match="SCAN_ALLOWED_CIDRS"):
        targets.authorize_targets(["10.0.0.1"], "")
    with pytest.raises(targets.TargetError, match="outside"):
        targets.authorize_targets(["8.8.8.8"], "10.0.0.0/8")
    assert targets.authorize_targets(["10.1.2.3"], "10.0.0.0/8,192.168.0.0/16") == ["10.1.2.3"]


def test_asset_id_for_ip():
    assert targets.asset_id_for_ip("10.0.0.10") == "IP-10-0-0-10"
    assert targets.asset_id_for_ip("2001:db8::1").startswith("IP6-")
