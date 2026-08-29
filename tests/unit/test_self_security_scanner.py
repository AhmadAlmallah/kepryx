"""Regression tests for dependency evidence and OSV interpretation."""

from app.services.self_security_scanner import DepRecord, SelfSecurityScanner


async def test_requirement_ranges_are_not_reported_as_installed_versions():
    async with SelfSecurityScanner() as scanner:
        deps = await scanner.scan_python_deps(
            "requests>=2.0\nfastapi==0.141.1\nuvicorn[standard]==0.37.0"
        )
    assert [(dep.name, dep.version) for dep in deps] == [
        ("fastapi", "0.141.1"),
        ("uvicorn", "0.37.0"),
    ]


async def test_osv_vector_is_not_misread_as_cvss_and_invalid_fix_is_skipped(monkeypatch):
    payload = {
        "vulns": [
            {
                "id": "GHSA-test",
                "aliases": ["CVE-2099-0001"],
                "summary": "test finding",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "demo"},
                        "ranges": [{"events": [{"fixed": "not-a-version"}, {"fixed": "2.1.0"}]}],
                    }
                ],
            }
        ]
    }

    async with SelfSecurityScanner() as scanner:

        async def fake_query(_dep):
            return payload

        monkeypatch.setattr(scanner, "_osv_query", fake_query)
        findings = await scanner.find_vulns(
            DepRecord(component="api", package_type="pip", name="demo", version="2.0.0")
        )

    assert findings[0].cvss is None
    assert findings[0].severity == "high"
    assert findings[0].fixed_version == "2.1.0"
