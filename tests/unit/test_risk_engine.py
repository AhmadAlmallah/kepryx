"""Unit tests for the risk scoring engine."""

import pytest

from app.services.risk_engine import compute_risk


def test_clean_asset_is_informational():
    asset = {
        "control_coverage": "full",
        "network_exposure": "isolated",
        "auth_method": "mfa+pam",
        "criticality": "low",
        "data_classification": "Public",
        "eol_status": False,
        "cves": [],
    }
    result = compute_risk(asset)
    assert result.tier == "Informational"
    assert result.score < 1.5


def test_critical_kev_internet_facing_is_critical():
    asset = {
        "control_coverage": "none",
        "network_exposure": "internet-facing",
        "auth_method": "password-only",
        "criticality": "tier-1",
        "data_classification": "Restricted",
        "eol_status": False,
        "cves": [{"cvss_v3": 9.8, "epss": 0.97, "kev": True}],
    }
    result = compute_risk(asset)
    assert result.tier == "Critical"
    assert result.score >= 4
    assert result.sla_days <= 7


def test_kev_ransomware_boost():
    base = {
        "control_coverage": "partial",
        "network_exposure": "dmz",
        "auth_method": "password",
        "criticality": "medium",
        "data_classification": "Internal",
        "eol_status": False,
        "cves": [{"cvss_v3": 7.5, "epss": 0.6, "kev": True, "kev_ransomware": False}],
    }
    boosted = {**base, "cves": [{**base["cves"][0], "kev_ransomware": True}]}
    assert compute_risk(boosted).score >= compute_risk(base).score


def test_no_cves_with_high_criticality_still_medium():
    asset = {
        "control_coverage": "full",
        "network_exposure": "internal",
        "auth_method": "mfa",
        "criticality": "tier-1",
        "data_classification": "Restricted",
        "eol_status": False,
        "cves": [],
    }
    result = compute_risk(asset)
    assert result.tier in ("Low", "Medium")


def test_breakdown_keys_present():
    asset = {
        "control_coverage": "full",
        "network_exposure": "internal",
        "auth_method": "mfa",
        "criticality": "medium",
        "data_classification": "Internal",
        "eol_status": False,
        "cves": [],
    }
    result = compute_risk(asset)
    for key in (
        "cve",
        "kev",
        "controls",
        "exposure",
        "access",
        "criticality",
        "data_classification",
    ):
        assert key in result.breakdown
        assert 1 <= result.breakdown[key] <= 5


def test_eol_asset_gets_replacement_action():
    asset = {
        "control_coverage": "partial",
        "network_exposure": "internal",
        "auth_method": "password",
        "criticality": "low",
        "data_classification": "Internal",
        "eol_status": True,
        "cves": [],
    }
    result = compute_risk(asset)
    if result.tier == "Low":
        assert (
            "EOL" in result.recommended_action or "replacement" in result.recommended_action.lower()
        )


@pytest.mark.parametrize(
    "exposure,expected_min_score",
    [
        ("isolated", 1),
        ("internal", 1),
        ("internet-facing", 5),
    ],
)
def test_exposure_drives_score_higher(exposure, expected_min_score):
    asset = {
        "control_coverage": "full",
        "network_exposure": exposure,
        "auth_method": "mfa+pam",
        "criticality": "low",
        "data_classification": "Public",
        "eol_status": False,
        "cves": [],
    }
    result = compute_risk(asset)
    assert result.breakdown["exposure"] >= expected_min_score


def test_data_classification_increases_score():
    base = {
        "control_coverage": "full",
        "network_exposure": "internal",
        "auth_method": "mfa",
        "criticality": "high",
        "eol_status": False,
        "cves": [],
    }
    assert (
        compute_risk({**base, "data_classification": "Restricted"}).score
        > compute_risk({**base, "data_classification": "Public"}).score
    )
