"""Tests for bounded software inventory ingest and advisory interpretation."""

import io
import zipfile

import httpx
import pytest

from app.services.software_inventory import (
    SoftwareRecord,
    SoftwareVulnerabilityService,
    build_purl,
    merge_advisories,
    parse_osv_vulnerabilities,
    parse_software_inventory,
)


def test_csv_import_normalizes_headers_ecosystems_and_builds_purls():
    payload = (
        b"Application,Package Manager,Library,Installed Version,Asset,Direct\n"
        b"Future,nodejs,express,v4.18.2,WEB-01,yes\n"
        b"Future,pip,Requests,2.31.0,WEB-01,no\n"
    )
    result = parse_software_inventory(payload, "future.csv")

    assert not result.errors
    assert [
        (item.solution, item.ecosystem, item.normalized_package, item.version, item.direct)
        for item in result.records
    ] == [
        ("Future", "npm", "express", "4.18.2", True),
        ("Future", "pypi", "requests", "2.31.0", False),
    ]
    assert result.records[0].purl == "pkg:npm/express@4.18.2"
    assert result.records[1].purl == "pkg:pypi/requests@2.31.0"


def test_import_rejects_formula_like_identity_values_and_unknown_extension():
    formula = b"solution,ecosystem,package,version\n=Future,npm,express,4.18.2\n"
    result = parse_software_inventory(formula, "future.csv")
    assert result.records == []
    assert "unsafe spreadsheet value" in result.errors[0]["error"]

    result = parse_software_inventory(b"anything", "future.xls")
    assert "only .csv and .xlsx" in result.errors[0]["error"]


def test_xlsx_import_reads_first_sheet_without_executing_formulas():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
      <row r="1"><c r="A1" t="inlineStr"><is><t>solution</t></is></c><c r="B1" t="inlineStr"><is><t>ecosystem</t></is></c><c r="C1" t="inlineStr"><is><t>package</t></is></c><c r="D1" t="inlineStr"><is><t>version</t></is></c></row>
      <row r="2"><c r="A2" t="inlineStr"><is><t>Future</t></is></c><c r="B2" t="inlineStr"><is><t>npm</t></is></c><c r="C2" t="inlineStr"><is><t>express</t></is></c><c r="D2" t="inlineStr"><is><t>4.18.2</t></is></c></row>
    </sheetData></worksheet>"""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("xl/worksheets/sheet1.xml", xml)
    result = parse_software_inventory(output.getvalue(), "future.xlsx")
    assert not result.errors
    assert result.records[0].package == "express"


def test_osv_parser_keeps_vectors_as_unknown_cvss_and_extracts_fixed_version():
    record_payload = b"solution,ecosystem,package,version\nFuture,pypi,demo,2.0.0\n"
    record = parse_software_inventory(record_payload, "future.csv").records[0]
    advisories = parse_osv_vulnerabilities(
        {
            "vulns": [
                {
                    "id": "GHSA-demo",
                    "aliases": ["CVE-2099-0001"],
                    "summary": "Demo advisory",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {"package": {"name": "demo"}, "ranges": [{"events": [{"fixed": "2.1.0"}]}]}
                    ],
                }
            ]
        },
        record,
    )
    assert advisories[0].cve_id == "CVE-2099-0001"
    assert advisories[0].cvss is None
    assert advisories[0].severity == "high"
    assert advisories[0].fixed_version == "2.1.0"


def test_purl_builder_returns_none_for_unmapped_product_ecosystem():
    assert build_purl("postgresql", "postgres", "15.4") is None


def test_merge_advisories_preserves_cross_provider_provenance_and_nvd_score():
    record = SoftwareRecord("Future", "npm", "demo", "1.0.0")
    osv = parse_osv_vulnerabilities(
        {
            "vulns": [
                {
                    "id": "GHSA-demo",
                    "aliases": ["CVE-2099-0002"],
                    "summary": "OSV summary",
                    "database_specific": {"cvss_score": 7.5},
                    "affected": [],
                }
            ]
        },
        record,
    )
    from app.services.software_inventory import Advisory

    merged = merge_advisories(
        osv
        + [
            Advisory(
                advisory_id="CVE-2099-0002",
                cve_id="CVE-2099-0002",
                source="NVD",
                cvss=8.0,
                severity="high",
                summary="NVD summary",
                fixed_version=None,
            )
        ]
    )
    assert len(merged) == 1
    assert merged[0].source == "NVD+OSV"
    assert merged[0].cvss == 8.0
    assert merged[0].aliases == ["CVE-2099-0002"]


@pytest.mark.asyncio
async def test_assess_queries_both_advisory_sources_and_surfaces_provider_errors():
    async def handler(request: httpx.Request):
        if request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-demo",
                            "aliases": ["CVE-2099-0002"],
                            "summary": "OSV summary",
                            "database_specific": {"cvss_score": 7.5},
                            "affected": [],
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"version": "1.0.1"})

    class FakeNVD:
        async def get_cves_for_cpe(self, _cpe, *, raise_errors=False):
            return [
                {
                    "id": "CVE-2099-0002",
                    "cvss_v3": 8.0,
                    "description": "NVD summary",
                },
                {
                    "id": "CVE-2099-0003",
                    "cvss_v3": 9.0,
                    "description": "NVD-only summary",
                },
            ]

        async def close(self):
            return None

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = SoftwareVulnerabilityService(client=client)
    service.nvd = FakeNVD()
    try:
        assessment = await service.assess(
            SoftwareRecord(
                "Future",
                "npm",
                "demo",
                "1.0.0",
                cpe="cpe:2.3:a:demo:demo:1.0.0:*:*:*:*:*:*:*",
            )
        )
    finally:
        await service.close()
    assert {item.advisory_id for item in assessment.advisories} == {
        "CVE-2099-0002",
        "CVE-2099-0003",
    }
    assert assessment.update_available is True
    assert assessment.provider_errors == {}


@pytest.mark.asyncio
async def test_assess_marks_osv_provider_failure_without_discarding_scan_result():
    async def handler(_request: httpx.Request):
        raise httpx.ConnectError("offline")

    class FakeNVD:
        async def close(self):
            return None

    service = SoftwareVulnerabilityService(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    service.nvd = FakeNVD()
    try:
        assessment = await service.assess(SoftwareRecord("Future", "pypi", "demo", "1.0.0"))
    finally:
        await service.close()
    assert assessment.advisories == []
    assert assessment.status == "unknown"
    assert assessment.provider_errors == {
        "OSV": "ConnectError",
        "registry": "ConnectError",
    }


@pytest.mark.asyncio
async def test_assess_marks_registry_failure_as_partial_data():
    async def handler(request: httpx.Request):
        if request.method == "POST":
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(503, json={"error": "temporarily unavailable"})

    service = SoftwareVulnerabilityService(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    try:
        assessment = await service.assess(SoftwareRecord("Future", "npm", "demo", "1.0.0"))
    finally:
        await service.close()
    assert assessment.status == "unknown"
    assert assessment.provider_errors == {"registry": "HTTPStatusError"}
