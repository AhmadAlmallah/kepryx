"""Deterministic NVD, EPSS, KEV, cache, and merge tests."""

import httpx
import pytest

from app.services.cve_enrichment import CVEEnricher


@pytest.mark.asyncio
async def test_enrichment_merges_authoritative_sources_and_caches_kev(monkeypatch):
    enricher = CVEEnricher()
    calls = {"kev": 0, "nvd": 0, "epss": 0}

    async def nvd(_params, _headers):
        calls["nvd"] += 1
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "v"}}]
                        },
                        "descriptions": [{"lang": "en", "value": "test vuln"}],
                        "configurations": [
                            {
                                "nodes": [
                                    {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:test"}]}
                                ]
                            }
                        ],
                    }
                },
                {"cve": {"id": "CVE-2026-no-metrics", "descriptions": []}},
                {"cve": {"descriptions": [{"lang": "en", "value": "ignored"}]}},
            ]
        }

    async def epss(_params):
        calls["epss"] += 1
        return {"data": [{"cve": "CVE-2026-0001", "epss": "0.91", "percentile": "99.2"}]}

    async def sleep(_seconds):
        return None

    async def get(_url, **_kwargs):
        calls["kev"] += 1
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0001",
                        "dateAdded": "2026-08-01",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ]
            },
            request=httpx.Request("GET", "https://example.test"),
        )

    monkeypatch.setattr(enricher, "_nvd_get", nvd)
    monkeypatch.setattr(enricher, "_epss_get", epss)
    monkeypatch.setattr("app.services.cve_enrichment.asyncio.sleep", sleep)
    monkeypatch.setattr(enricher.client, "get", get)
    try:
        result = await enricher.enrich_asset(["cpe:one", "cpe:two"])
        assert result[0]["id"] == "CVE-2026-0001"
        assert result[0]["epss_score"] == 0.91
        assert result[0]["kev"] is True
        assert result[0]["kev_ransomware"] is True
        assert len(result) == 2
        assert calls == {"kev": 1, "nvd": 2, "epss": 1}

        await enricher.load_kev_catalog()
        assert calls["kev"] == 1
    finally:
        await enricher.close()


@pytest.mark.asyncio
async def test_feed_failures_are_fail_safe_and_empty_epss_is_cheap(monkeypatch):
    enricher = CVEEnricher()

    async def fail(_params, _headers):
        raise httpx.ConnectError("offline")

    async def epss_fail(_params):
        raise httpx.TimeoutException("slow")

    async def get_fail(_url, **_kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(enricher, "_nvd_get", fail)
    monkeypatch.setattr(enricher, "_epss_get", epss_fail)
    monkeypatch.setattr(enricher.client, "get", get_fail)
    try:
        assert await enricher.get_cves_for_cpe("cpe:test") == []
        assert await enricher.get_epss_scores([]) == {}
        assert await enricher.get_epss_scores(["CVE-2026-0001"]) == {}
        assert await enricher.load_kev_catalog(force=True) == {}
    finally:
        await enricher.close()
