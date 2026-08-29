"""Regression tests for active-scan authorization boundaries."""

import pytest

from app.api.scans import ScanNetworkCreate
from app.core.scan_authorization import (
    ScanAuthorizationError,
    authorize_scan_host,
    authorize_scan_network,
)


def test_authorized_subnet_is_canonicalized():
    assert (
        authorize_scan_network("10.20.30.7/28", allowed_cidrs=["10.20.0.0/16"], max_hosts=256)
        == "10.20.30.0/28"
    )


def test_scan_fails_closed_without_allowlist():
    with pytest.raises(ScanAuthorizationError, match="disabled"):
        authorize_scan_network("10.20.30.0/24", allowed_cidrs=[])


def test_scan_rejects_target_outside_allowlist():
    with pytest.raises(ScanAuthorizationError, match="outside"):
        authorize_scan_network("10.21.0.0/24", allowed_cidrs=["10.20.0.0/16"])


def test_scan_rejects_target_above_host_limit():
    with pytest.raises(ScanAuthorizationError, match="limit"):
        authorize_scan_network("10.20.0.0/16", allowed_cidrs=["10.20.0.0/16"], max_hosts=4096)


def test_service_scan_rejects_host_outside_allowlist():
    with pytest.raises(ScanAuthorizationError, match="outside"):
        authorize_scan_host("192.0.2.10", allowed_cidrs=["10.20.0.0/16"])


def test_scan_request_rejects_exclusion_outside_target():
    with pytest.raises(ValueError, match="excluded IP"):
        ScanNetworkCreate(
            cidr="10.20.30.0/24",
            name="approved-segment",
            excluded_ips=["10.20.31.1"],
        )
