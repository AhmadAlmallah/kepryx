"""Reconciliation tasks — sync integrations, detect gaps, rescore, cleanup."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import selectinload

from app.connectors import get_connector
from app.core.connector_secrets import resolve_connector_config
from app.core.database import SessionLocal
from app.models import Alert, Asset, AssetCVE, Integration
from app.services.reconciler import Reconciler
from app.services.risk_engine import compute_risk
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

ALERT_RETENTION_DAYS = 180


@celery_app.task(name="app.workers.reconcile_tasks.sync_all_integrations")
def sync_all_integrations(integration_id: str | None = None):
    return run_async(_sync_all(integration_id))


async def _sync_all(integration_id: str | None = None):
    async with SessionLocal() as db:
        query = select(Integration).where(Integration.enabled.is_(True))
        if integration_id:
            query = query.where(Integration.id == integration_id)
        result = await db.execute(query)
        integrations = result.scalars().all()
        results = {}
        for integ in integrations:
            try:
                connector_class = get_connector(integ.connector_type)
                if not connector_class:
                    logger.warning(f"No connector for {integ.connector_type}")
                    continue
                connector = connector_class(
                    resolve_connector_config(integ.connector_type, integ.config)
                )
                hosts = await connector.fetch_inventory()
                reconciler = Reconciler(db)
                for host in hosts:
                    await reconciler.reconcile_host(integ.connector_type, host)
                integ.last_run = datetime.now(UTC)
                integ.last_status = "success"
                integ.assets_reported = len(hosts)
                integ.failure_count = 0
                await db.commit()
                results[integ.name] = len(hosts)
                logger.info(f"Integration {integ.name}: {len(hosts)} assets")
            except Exception:
                integ.failure_count = (integ.failure_count or 0) + 1
                integ.last_status = "failed"
                # Auto-disable after 5 consecutive failures
                if integ.failure_count >= 5:
                    integ.enabled = False
                    logger.error(f"Auto-disabled {integ.name} after {integ.failure_count} failures")
                await db.commit()
                logger.exception("Integration %s failed", integ.name)
        return results


@celery_app.task(name="app.workers.reconcile_tasks.detect_stale_and_gaps")
def detect_stale_and_gaps():
    return run_async(_detect_stale_and_gaps())


async def _detect_stale_and_gaps():
    async with SessionLocal() as db:
        reconciler = Reconciler(db)
        stale = await reconciler.detect_stale_assets(threshold_days=30)
        gaps = await reconciler.detect_edr_gaps()
        await db.commit()
        return {"stale": stale, "edr_gaps": gaps}


@celery_app.task(name="app.workers.reconcile_tasks.rescore_assets")
def rescore_assets():
    return run_async(_rescore_assets())


async def _rescore_assets():
    """Recompute risk scores for all assets — keeps scores fresh as CVEs/controls change."""
    async with SessionLocal() as db:
        result = await db.execute(
            select(Asset).options(selectinload(Asset.cves).selectinload(AssetCVE.cve))
        )
        assets = result.scalars().all()
        for asset in assets:
            cve_data = [
                {
                    "cvss_v3": ac.cve.cvss_v3,
                    "epss": ac.cve.epss_score or 0,
                    "kev": ac.cve.kev,
                }
                for ac in asset.cves
                if not ac.suppressed and not ac.remediated
            ]

            risk = compute_risk(
                {
                    "control_coverage": asset.control_coverage,
                    "network_exposure": asset.network_exposure,
                    "auth_method": asset.auth_method,
                    "criticality": asset.criticality,
                    "data_classification": asset.data_classification,
                    "eol_status": asset.eol_status,
                    "cves": cve_data,
                }
            )
            asset.risk_score = risk.score
            asset.risk_tier = risk.tier
            asset.risk_breakdown = risk.breakdown
        await db.commit()
        return {"rescored": len(assets)}


@celery_app.task(name="app.workers.reconcile_tasks.cleanup_old_data")
def cleanup_old_data():
    return run_async(_cleanup_old_data())


async def _cleanup_old_data():
    """Trim resolved alerts; audit retention is owned by retention_tasks."""
    async with SessionLocal() as db:
        alert_cutoff = datetime.now(UTC) - timedelta(days=ALERT_RETENTION_DAYS)
        alert_deleted = cast(
            CursorResult[Any],
            await db.execute(
                delete(Alert).where(Alert.status == "resolved", Alert.resolved_at < alert_cutoff)
            ),
        )
        await db.commit()
        return {"alerts_pruned": alert_deleted.rowcount}
