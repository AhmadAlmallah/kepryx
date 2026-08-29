"""CVE enrichment — direct NVD/EPSS/KEV API integration."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings

logger = logging.getLogger(__name__)

NVD_RATE_LIMIT_DELAY = 6.0
NVD_RATE_LIMIT_DELAY_KEY = 0.6


class CVEEnricher:
    def __init__(self):
        self.nvd_delay = NVD_RATE_LIMIT_DELAY_KEY if settings.NVD_API_KEY else NVD_RATE_LIMIT_DELAY
        self.kev_cache: dict[str, dict] = {}
        self.kev_cached_at: datetime | None = None
        # Persistent HTTP client - reused across calls within one enricher instance
        self.client = httpx.AsyncClient(
            timeout=30.0,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=15),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        reraise=False,
    )
    async def _nvd_get(self, params: dict, headers: dict) -> dict:
        r = await self.client.get(settings.NVD_BASE_URL, params=params, headers=headers)
        r.raise_for_status()
        return r.json()

    async def get_cves_for_cpe(self, cpe: str) -> list[dict]:
        headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
        params = {"cpeName": cpe, "resultsPerPage": 100}
        try:
            data = await self._nvd_get(params, headers)
            if not data:
                return []
        except Exception as e:
            logger.error(f"NVD query failed for {cpe}: {e}")
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            metrics = cve.get("metrics", {})
            cvss_metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
            cvss = cvss_metric.get("cvssData", {}) if cvss_metric else {}
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            # Fix the broken nested comprehension from before
            affected = []
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable") and match.get("criteria"):
                            affected.append(match["criteria"])

            cves.append(
                {
                    "id": cve_id,
                    "cvss_v3": cvss.get("baseScore"),
                    "cvss_vector": cvss.get("vectorString"),
                    "description": desc[:1000],
                    "published": cve.get("published"),
                    "modified": cve.get("lastModified"),
                    "affected_cpes": affected,
                }
            )
        await asyncio.sleep(self.nvd_delay)
        return cves

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
        reraise=False,
    )
    async def _epss_get(self, params: dict) -> dict:
        r = await self.client.get(settings.EPSS_BASE_URL, params=params)
        r.raise_for_status()
        return r.json()

    async def get_epss_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        if not cve_ids:
            return {}
        results = {}
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i : i + 100]
            try:
                data = await self._epss_get({"cve": ",".join(batch)})
                if not data:
                    continue
                for item in data.get("data", []):
                    results[item["cve"]] = {
                        "score": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                    }
            except Exception as e:
                logger.error(f"EPSS batch failed: {e}")
        return results

    async def load_kev_catalog(self, force: bool = False) -> dict[str, dict]:
        if (
            not force
            and self.kev_cached_at
            and datetime.now(UTC) - self.kev_cached_at < timedelta(hours=6)
        ):
            return self.kev_cache
        try:
            r = await self.client.get(settings.KEV_FEED_URL)
            r.raise_for_status()
            data = r.json()
            self.kev_cache = {
                v["cveID"]: {
                    "date_added": v.get("dateAdded"),
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "vulnerability_name": v.get("vulnerabilityName"),
                    "due_date": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                }
                for v in data.get("vulnerabilities", [])
            }
            self.kev_cached_at = datetime.now(UTC)
            logger.info(f"Loaded {len(self.kev_cache)} KEV entries")
        except httpx.HTTPError as e:
            logger.error(f"KEV catalog fetch failed: {e}")
        return self.kev_cache

    async def enrich_asset(self, cpes: list[str]) -> list[dict]:
        await self.load_kev_catalog()
        all_cves: dict[str, dict] = {}
        for cpe in cpes:
            cves = await self.get_cves_for_cpe(cpe)
            for cve in cves:
                cve_id = cve["id"]
                if cve_id not in all_cves:
                    cve["matched_cpe"] = cpe
                    all_cves[cve_id] = cve

        epss = await self.get_epss_scores(list(all_cves.keys()))
        for cve_id, cve in all_cves.items():
            cve["epss_score"] = epss.get(cve_id, {}).get("score", 0.0)
            cve["epss_percentile"] = epss.get(cve_id, {}).get("percentile", 0.0)
            kev_data = self.kev_cache.get(cve_id)
            cve["kev"] = bool(kev_data)
            if kev_data:
                cve["kev_date_added"] = kev_data["date_added"]
                cve["kev_ransomware"] = kev_data.get("ransomware", False)
        return list(all_cves.values())
