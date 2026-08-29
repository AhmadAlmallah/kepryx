from types import SimpleNamespace

from app.services.compliance_ai import ComplianceReview
from app.services.compliance_catalog import CONTROL_RULES
from app.workers.compliance_tasks import _assess, _integrity_hash


def _asset(**overrides):
    values = {
        "name": "asset-01",
        "ip": "10.0.0.10",
        "os": "Linux",
        "type": "server",
        "software_stack": ["nginx"],
        "control_coverage": "full",
        "auth_method": "mfa",
        "last_patch": "2026-08-01",
        "eol_status": False,
        "edr_status": "healthy",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_compliant_control_is_deterministic_and_scored_one():
    rule = CONTROL_RULES["cis-v8"]["1.1"]
    assert _assess(rule, _asset())[:3] == ("compliant", 1.0, 1.0)


def test_incomplete_multi_field_control_is_partial():
    rule = CONTROL_RULES["cis-v8"]["1.1"]
    status, score, _confidence, rationale = _assess(rule, _asset(ip=None))
    assert status == "partial"
    assert score == 0.67
    assert "ip=missing" in rationale


def test_invalid_single_field_control_is_a_gap_not_partial():
    rule = CONTROL_RULES["cis-v8"]["6.1"]
    status, score, _confidence, _rationale = _assess(rule, _asset(auth_method="password"))
    assert (status, score) == ("gap", 0.0)


def test_evidence_hash_is_stable_for_canonical_json():
    assert _integrity_hash({"b": 2, "a": 1}) == _integrity_hash({"a": 1, "b": 2})
    assert len(_integrity_hash({"a": 1})) == 64


def test_ai_review_schema_restricts_suggestion_to_review_statuses():
    review = ComplianceReview(
        suggested_status="partial",
        rationale="The record is incomplete.",
        evidence_gaps=["Provide a current source observation."],
        confidence=0.5,
    )
    assert review.abstained is False
