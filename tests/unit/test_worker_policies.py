"""Worker retry, auto-disable, stale-scan, and enrichment policy tests."""

from datetime import UTC, datetime, timedelta

import pytest

from app.models import Asset, Integration, Scan, ScanNetwork
from app.workers import enrichment_tasks, reconcile_tasks, scan_tasks
from tests.support import FakeDB, FakeResult


class SessionFactory:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, *_args):
        return None


@pytest.mark.asyncio
async def test_integration_success_resets_failure_count_and_reconciles(monkeypatch):
    integration = Integration(
        name="lab", connector_type="asset_api", config={}, enabled=True, failure_count=3
    )
    db = FakeDB(execute_results=[FakeResult([integration])])

    class Connector:
        def __init__(self, _config):
            pass

        async def fetch_inventory(self):
            return []

    monkeypatch.setattr(reconcile_tasks, "SessionLocal", SessionFactory(db))
    monkeypatch.setattr(reconcile_tasks, "get_connector", lambda _name: Connector)
    monkeypatch.setattr(reconcile_tasks, "resolve_connector_config", lambda *_args: {})
    result = await reconcile_tasks._sync_all()

    assert result == {"lab": 0}
    assert integration.last_status == "success"
    assert integration.failure_count == 0
    assert db.commits == 1


@pytest.mark.asyncio
async def test_integration_failure_auto_disables_after_fifth_failure(monkeypatch):
    integration = Integration(
        name="broken", connector_type="asset_api", config={}, enabled=True, failure_count=4
    )
    db = FakeDB(execute_results=[FakeResult([integration])])

    class Connector:
        def __init__(self, _config):
            pass

        async def fetch_inventory(self):
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr(reconcile_tasks, "SessionLocal", SessionFactory(db))
    monkeypatch.setattr(reconcile_tasks, "get_connector", lambda _name: Connector)
    monkeypatch.setattr(reconcile_tasks, "resolve_connector_config", lambda *_args: {})
    result = await reconcile_tasks._sync_all()

    assert result == {}
    assert integration.last_status == "failed"
    assert integration.failure_count == 5
    assert integration.enabled is False


@pytest.mark.asyncio
async def test_enrichment_upserts_cve_and_recomputes_asset_risk():
    asset = Asset(
        name="web",
        cpe=["cpe:test"],
        criticality="high",
        network_exposure="external",
        control_coverage="none",
        auth_method="password",
        data_classification="Confidential",
        eol_status=False,
    )
    asset.id = "asset-1"
    db = FakeDB(execute_results=[FakeResult(), FakeResult()])

    class Enricher:
        async def enrich_asset(self, _cpes):
            return [
                {
                    "id": "CVE-2026-0001",
                    "cvss_v3": 9.8,
                    "epss_score": 0.9,
                    "kev": True,
                    "matched_cpe": "cpe:test",
                }
            ]

    count = await enrichment_tasks._enrich_one_asset(db, asset, Enricher())
    assert count == 1
    assert asset.risk_tier == "Critical"
    assert any(getattr(item, "id", None) == "CVE-2026-0001" for item in db.added)


@pytest.mark.asyncio
async def test_scan_worker_blocks_unauthorized_db_rows_and_recovers_stale_jobs(monkeypatch):
    stale = Scan(
        scan_type="discovery",
        target="198.51.100.0/28",
        status="running",
        started_at=datetime.now(UTC) - timedelta(hours=3),
    )
    network = ScanNetwork(cidr="203.0.113.0/28", name="not-authorized", enabled=True)
    db = FakeDB(execute_results=[FakeResult([stale]), FakeResult([network])])
    monkeypatch.setattr(scan_tasks, "SessionLocal", SessionFactory(db))
    monkeypatch.setattr(scan_tasks.settings, "SCAN_TIMEOUT_SEC", 60)
    monkeypatch.setattr(scan_tasks.settings, "SCAN_NETWORKS", ["198.51.100.0/28"])

    result = await scan_tasks._run_all_network_scans()
    assert result["status"] == "blocked"
    assert result["recovered_stale"] == 1
    assert stale.status == "failed"
    assert db.commits == 1
