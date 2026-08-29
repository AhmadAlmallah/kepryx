"""OSV interpretation and review-only AI validation contract tests."""

import httpx
import pytest

from app.services import ai_update_validator
from app.services.self_security_scanner import DepRecord, SelfSecurityScanner


@pytest.mark.asyncio
async def test_python_dependency_parser_normalizes_names_and_skips_non_pins():
    async with SelfSecurityScanner() as scanner:
        deps = await scanner.scan_python_deps(
            "# comment\n-e .\ncryptography==44.0.0; python_version >= '3.12'\n"
            "package-name[extra]==1.2.3\nnot-a-pin>=2.0"
        )
    assert [(dep.name, dep.version, dep.purl) for dep in deps] == [
        ("cryptography", "44.0.0", "pkg:pypi/cryptography@44.0.0"),
        ("package-name", "1.2.3", "pkg:pypi/package-name@1.2.3"),
    ]


@pytest.mark.asyncio
async def test_osv_scores_and_fixed_versions_are_interpreted_safely(monkeypatch):
    payload = {
        "vulns": [
            {
                "id": "GHSA-critical",
                "aliases": ["CVE-2026-0100"],
                "summary": "critical issue",
                "severity": [{"type": "CVSS_V31", "score": "9.1"}],
                "affected": [
                    {
                        "package": {"name": "demo"},
                        "ranges": [{"events": [{"fixed": "1.0.1"}, {"fixed": "2.0.0"}]}],
                    }
                ],
            },
            {
                "id": "OSV-low",
                "aliases": [],
                "details": "low issue",
                "database_specific": {"severity": "moderate"},
                "affected": [{"package": {"name": "other"}}],
            },
        ]
    }
    async with SelfSecurityScanner() as scanner:
        monkeypatch.setattr(scanner, "_osv_query", lambda _dep: _async_value(payload))
        findings = await scanner.find_vulns(
            DepRecord(component="api", package_type="pip", name="demo", version="1.0.0")
        )
    assert findings[0].severity == "critical"
    assert findings[0].cvss == 9.1
    assert findings[0].fixed_version == "1.0.1"
    assert findings[1].severity == "medium"
    assert findings[1].cvss is None


async def _async_value(value):
    return value


@pytest.mark.asyncio
async def test_osv_and_pypi_http_failures_return_safe_results(monkeypatch):
    async with SelfSecurityScanner() as scanner:

        async def fail_post(*_args, **_kwargs):
            raise httpx.TimeoutException("offline")

        async def fail_get(*_args, **_kwargs):
            raise httpx.ConnectError("offline")

        monkeypatch.setattr(scanner.client, "post", fail_post)
        monkeypatch.setattr(scanner.client, "get", fail_get)
        with pytest.raises(httpx.TimeoutException):
            await scanner._osv_query(DepRecord("api", "pip", "demo", "1.0.0"))
        assert await scanner.get_latest_pypi_version("demo") is None


@pytest.mark.asyncio
async def test_ai_validator_returns_provider_result_and_safe_fallbacks(monkeypatch):
    valid = (
        '{"recommendation":"approve","risk_score":2,"version_jump_type":"patch",'
        '"breaking_changes_detected":false,"breaking_changes":[],'
        '"compatibility_concerns":[],"security_improvement":"fixes CVE",'
        '"test_recommendations":["run tests"],"summary":"safe"}'
    )

    async def complete(*_args, **_kwargs):
        return valid

    monkeypatch.setattr(ai_update_validator, "complete_json", complete)
    result = await ai_update_validator.assess_update("demo", "1.0.0", "1.0.1", "cve_fix", ["CVE-1"])
    assert result["recommendation"] == "approve"
    assert result["risk_score"] == 2.0

    async def malformed(*_args, **_kwargs):
        return "not-json"

    monkeypatch.setattr(ai_update_validator, "complete_json", malformed)
    malformed_result = await ai_update_validator.assess_update("demo", "1", "2", "manual", [])
    assert malformed_result["recommendation"] == "manual_review"
    assert "_raw" in malformed_result

    async def unavailable(*_args, **_kwargs):
        raise RuntimeError("provider down")

    monkeypatch.setattr(ai_update_validator, "complete_json", unavailable)
    failed = await ai_update_validator.assess_update("demo", "1", "2", "cve_fix", [])
    assert failed["recommendation"] == "manual_review"
    assert failed["risk_score"] == 10
