"""Scanner tasks — run nmap discovery and service scans."""

import logging
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.scan_authorization import ScanAuthorizationError, authorize_scan_network
from app.models import Scan, ScanNetwork
from app.services.reconciler import Reconciler
from app.services.scanner import NetworkScanner
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.scan_tasks.run_all_network_scans", bind=True, max_retries=2)
def run_all_network_scans(self):
    return run_async(_run_all_network_scans())


async def _run_all_network_scans():
    """Iterate all enabled scan networks and run discovery."""
    async with SessionLocal() as db:
        # A worker restart must not leave historical jobs permanently running.
        stale_cutoff = datetime.now(UTC).timestamp() - (settings.SCAN_TIMEOUT_SEC * 2)
        stale_result = await db.execute(
            select(Scan).where(Scan.status == "running", Scan.started_at.is_not(None))
        )
        recovered = 0
        for stale_scan in stale_result.scalars().all():
            if stale_scan.started_at.timestamp() < stale_cutoff:
                stale_scan.status = "failed"
                stale_scan.error = "recovered stale scan after worker interruption"
                stale_scan.completed_at = datetime.now(UTC)
                recovered += 1
        if recovered:
            await db.commit()

        result = await db.execute(select(ScanNetwork).where(ScanNetwork.enabled.is_(True)))
        networks = result.scalars().all()

        total_hosts = 0
        scanned = 0
        failed = 0
        for network in networks:
            try:
                authorize_scan_network(network.cidr)
            except ScanAuthorizationError as exc:
                # Database rows are not an authorization boundary. Keep them visible
                # to admins, but never execute a scan outside SCAN_NETWORKS.
                logger.warning("Skipping unauthorized scan network %s: %s", network.cidr, exc)
                continue

            scanned += 1
            scan = Scan(
                scan_type="discovery",
                target=network.cidr,
                status="running",
                started_at=datetime.now(UTC),
                triggered_by="scheduler",
            )
            db.add(scan)
            await db.commit()

            try:
                scanner = NetworkScanner()
                hosts = await scanner.discover(network.cidr, network.excluded_ips)
                reconciler = Reconciler(db)

                for host in hosts:
                    await reconciler.reconcile_host(
                        "nmap_scan",
                        {
                            "ip": host.ip,
                            "mac": host.mac,
                            "hostname": host.hostname,
                            "name": host.hostname or host.ip,
                            "os_guess": host.os_guess,
                            "type": "Unknown",
                            "segment": network.name,
                            "software_stack": [
                                s.get("product") for s in host.services if s.get("product")
                            ],
                            "cpe": [cpe for s in host.services for cpe in s.get("cpe", [])],
                            "services": host.services,
                            "mac_vendor": host.mac_vendor,
                        },
                    )

                scan.status = "completed"
                scan.hosts_found = len(hosts)
                scan.completed_at = datetime.now(UTC)
                total_hosts += len(hosts)
                await db.commit()
                logger.info(f"Scan complete: {network.cidr} → {len(hosts)} hosts")
            except Exception as e:
                failed += 1
                # Reconciliation may have failed after PostgreSQL aborted the
                # transaction (for example, an invalid host payload). Reset the
                # transaction before recording the scan failure itself.
                await db.rollback()
                scan.status = "failed"
                scan.error = str(e)[:1000]
                scan.completed_at = datetime.now(UTC)
                await db.commit()
                logger.exception(f"Scan failed for {network.cidr}: {e}")

        if not scanned:
            return {
                "status": "blocked",
                "networks_scanned": 0,
                "total_hosts": 0,
                "recovered_stale": recovered,
                "error": "no enabled scan network is authorized by SCAN_NETWORKS",
            }
        return {
            "status": "completed"
            if failed == 0
            else ("failed" if failed == scanned else "partial"),
            "networks_scanned": scanned,
            "failed_networks": failed,
            "total_hosts": total_hosts,
            "recovered_stale": recovered,
        }


@celery_app.task(name="app.workers.scan_tasks.service_scan_host")
def service_scan_host(ip: str):
    return run_async(_service_scan_host(ip))


async def _service_scan_host(ip: str):
    scanner = NetworkScanner()
    hosts = await scanner.service_scan(ip)
    if not hosts:
        return {"ip": ip, "result": "no_data"}
    async with SessionLocal() as db:
        reconciler = Reconciler(db)
        for host in hosts:
            await reconciler.reconcile_host(
                "nmap_scan",
                {
                    "ip": host.ip,
                    "mac": host.mac,
                    "hostname": host.hostname,
                    "name": host.hostname or host.ip,
                    "os_guess": host.os_guess,
                    "software_stack": [s.get("product") for s in host.services if s.get("product")],
                    "cpe": [cpe for s in host.services for cpe in s.get("cpe", [])],
                    "services": host.services,
                },
            )
        await db.commit()
    return {"ip": ip, "services": len(hosts[0].services) if hosts else 0}
