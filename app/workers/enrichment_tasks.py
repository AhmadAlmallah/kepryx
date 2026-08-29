"""Enrichment tasks — NVD/EPSS/KEV sync, per-asset CVE matching."""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select

from app.core.database import SessionLocal
from app.models import CVE, Asset, AssetCVE
from app.services.cve_enrichment import CVEEnricher
from app.services.risk_engine import compute_risk
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.enrichment_tasks.sync_cve_feeds")
def sync_cve_feeds():
    return run_async(_sync_cve_feeds())


async def _sync_cve_feeds():
    """Daily: refresh KEV catalog. NVD is queried on-demand per asset."""
    enricher = CVEEnricher()
    try:
        kev = await enricher.load_kev_catalog(force=True)
        async with SessionLocal() as db:
            for cve_id, kev_data in kev.items():
                result = await db.execute(select(CVE).where(CVE.id == cve_id))
                cve = result.scalar_one_or_none()
                if cve:
                    cve.kev = True
                    if kev_data.get("date_added"):
                        try:
                            cve.kev_date_added = datetime.fromisoformat(kev_data["date_added"])
                        except (ValueError, TypeError):
                            pass
                else:
                    db.add(
                        CVE(id=cve_id, kev=True, description=kev_data.get("vulnerability_name", ""))
                    )
            await db.commit()
        return {"kev_synced": len(kev)}
    finally:
        await enricher.close()


@celery_app.task(name="app.workers.enrichment_tasks.enrich_pending_assets")
def enrich_pending_assets():
    return run_async(_enrich_pending_assets())


async def _enrich_pending_assets():
    """Enrich assets that have CPEs but haven't been enriched recently."""
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    async with SessionLocal() as db:
        result = await db.execute(
            select(Asset)
            .where(
                Asset.cpe != [],
                or_(
                    Asset.last_seen > cutoff,  # recently changed
                    ~Asset.cves.any(),
                ),  # never enriched
            )
            .limit(50)
        )
        assets = result.scalars().all()

        enricher = CVEEnricher()
        try:
            for asset in assets:
                await _enrich_one_asset(db, asset, enricher)
                await db.commit()
        finally:
            await enricher.close()
        return {"enriched": len(assets)}


@celery_app.task(name="app.workers.enrichment_tasks.enrich_asset")
def enrich_asset(asset_id: str):
    return run_async(_enrich_single(asset_id))


async def _enrich_single(asset_id: str):
    async with SessionLocal() as db:
        result = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            return {"error": "not found"}
        enricher = CVEEnricher()
        try:
            cve_count = await _enrich_one_asset(db, asset, enricher)
            await db.commit()
        finally:
            await enricher.close()
        return {"asset_id": asset_id, "cves": cve_count}


async def _enrich_one_asset(db, asset: Asset, enricher: CVEEnricher):
    if not asset.cpe:
        return 0
    cves = await enricher.enrich_asset(asset.cpe)
    for cve_data in cves:
        # Upsert CVE
        result = await db.execute(select(CVE).where(CVE.id == cve_data["id"]))
        cve = result.scalar_one_or_none()
        if not cve:
            cve = CVE(
                id=cve_data["id"],
                cvss_v3=cve_data.get("cvss_v3"),
                cvss_vector=cve_data.get("cvss_vector"),
                epss_score=cve_data.get("epss_score", 0),
                epss_percentile=cve_data.get("epss_percentile", 0),
                kev=cve_data.get("kev", False),
                description=cve_data.get("description", ""),
                affected_cpes=cve_data.get("affected_cpes", []),
            )
            db.add(cve)
        else:
            cve.cvss_v3 = cve_data.get("cvss_v3") or cve.cvss_v3
            cve.epss_score = cve_data.get("epss_score", cve.epss_score)
            cve.epss_percentile = cve_data.get("epss_percentile", cve.epss_percentile)
            cve.kev = cve_data.get("kev", cve.kev)
            cve.last_synced = datetime.now(UTC)

        # Junction
        result = await db.execute(
            select(AssetCVE).where(AssetCVE.asset_id == asset.id, AssetCVE.cve_id == cve.id)
        )
        if not result.scalar_one_or_none():
            db.add(
                AssetCVE(asset_id=asset.id, cve_id=cve.id, matched_cpe=cve_data.get("matched_cpe"))
            )

    # Recompute risk
    asset_dict = {
        "control_coverage": asset.control_coverage,
        "network_exposure": asset.network_exposure,
        "auth_method": asset.auth_method,
        "criticality": asset.criticality,
        "data_classification": asset.data_classification,
        "eol_status": asset.eol_status,
        "cves": [
            {"cvss_v3": c["cvss_v3"], "epss": c.get("epss_score", 0), "kev": c.get("kev", False)}
            for c in cves
        ],
    }
    risk = compute_risk(asset_dict)
    asset.risk_score = risk.score
    asset.risk_tier = risk.tier
    asset.risk_breakdown = risk.breakdown
    return len(cves)
