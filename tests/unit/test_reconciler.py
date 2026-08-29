"""Reconciliation identity, source priority, drift, and alert-dedup tests."""

from datetime import UTC, datetime, timedelta

import pytest

from app.models import Alert, Asset
from app.services.reconciler import Reconciler
from tests.support import FakeDB, FakeResult


@pytest.mark.asyncio
async def test_new_network_asset_is_shadow_and_generates_one_alert():
    db = FakeDB(execute_results=[FakeResult(), FakeResult(), FakeResult()])
    reconciler = Reconciler(db)

    asset = await reconciler.reconcile_host(
        "nmap_scan",
        {"ip": "198.51.100.10", "hostname": "lab-node", "services": [{"service": "https"}]},
    )

    assert asset.is_shadow is True
    assert asset.sources == ["nmap_scan"]
    assert len(reconciler.alerts_generated) == 1
    assert any(isinstance(item, Alert) for item in db.added)


@pytest.mark.asyncio
async def test_authoritative_source_merges_by_mac_and_overwrites_fields():
    existing = Asset(
        name="old-name",
        ip="198.51.100.10",
        mac="00:11:22:33:44:55",
        sources=["nmap_scan"],
        attrs={"services": [{"service": "http"}]},
    )
    existing.id = "asset-id"
    db = FakeDB(execute_results=[FakeResult([existing]), FakeResult()])
    reconciler = Reconciler(db)

    merged = await reconciler.reconcile_host(
        "asset_api",
        {
            "mac": "00:11:22:33:44:55",
            "name": "authoritative-name",
            "ip": "198.51.100.20",
            "services": [{"service": "https"}],
            "software_stack": ["nginx"],
        },
    )

    assert merged is existing
    assert merged.name == "authoritative-name"
    assert str(merged.ip) == "198.51.100.20"
    assert set(merged.sources) == {"nmap_scan", "asset_api"}
    assert merged.is_shadow is False
    assert reconciler.alerts_generated[0].alert_type == "drift"


@pytest.mark.asyncio
async def test_stale_and_edr_gap_detection_flags_assets_and_counts_alerts():
    stale = Asset(name="stale", last_seen=datetime.now(UTC) - timedelta(days=45), is_stale=False)
    gap = Asset(name="gap", type="Server", edr_status="None")
    db = FakeDB(
        execute_results=[FakeResult([stale]), FakeResult(), FakeResult([gap]), FakeResult()]
    )
    reconciler = Reconciler(db)

    assert await reconciler.detect_stale_assets() == 1
    assert stale.is_stale is True
    assert await reconciler.detect_edr_gaps() == 1
    assert len(reconciler.alerts_generated) == 2
