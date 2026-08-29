"""High-value API mutation and fail-closed route tests without external services."""

from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api import alerts, assets, integrations, scans, self_security
from app.models import Alert, Asset, Integration
from tests.support import FakeDB, FakeResult, request, user


@pytest.mark.asyncio
async def test_asset_create_and_update_recalculate_risk_and_audit(monkeypatch):
    db = FakeDB(execute_results=[FakeResult([])])
    created = await assets.create_asset(
        assets.AssetCreate(name="api-node", criticality="high", network_exposure="external"),
        request(),
        db,
        user("analyst"),
    )
    assert created["id"]
    asset = next(value for value in db.added if isinstance(value, Asset))
    assert asset.risk_score > 0
    assert db.commits == 1

    db.execute_results = [FakeResult([asset]), FakeResult([])]
    updated = await assets.update_asset(
        asset.id,
        assets.AssetUpdate(control_coverage="full", auth_method="mfa"),
        request(),
        db,
        user("analyst"),
    )
    assert updated["ok"] is True
    assert asset.control_coverage == "full"
    assert asset.auth_method == "mfa"
    assert db.commits == 2


@pytest.mark.asyncio
async def test_alert_resolution_is_idempotent_state_change_and_emits_event(monkeypatch):
    alert = Alert(
        alert_type="shadow_it",
        severity="high",
        title="Shadow asset",
        description="test",
        asset_id=uuid4(),
    )
    alert.id = uuid4()
    db = FakeDB(execute_results=[FakeResult([alert])])
    events = []
    monkeypatch.setattr(alerts, "fire_event_sync", lambda *args: events.append(args))

    result = await alerts.resolve_alert(alert.id, request(), db, user())
    assert result == {"ok": True}
    assert alert.status == "resolved"
    assert alert.resolved_by == "qa-admin"
    assert events and events[0][0] == "alert.resolved"

    db.execute_results = [FakeResult()]
    with pytest.raises(HTTPException) as missing:
        await alerts.resolve_alert(uuid4(), request(), db, user())
    assert missing.value.status_code == 404


def test_scan_models_normalize_and_reject_unsafe_targets(monkeypatch):
    body = scans.ScanNetworkCreate(
        cidr="198.51.100.10/28",
        name="reserved-lab",
        excluded_ips=["198.51.100.15", "198.51.100.15"],
    )
    assert body.cidr == "198.51.100.0/28"
    assert body.excluded_ips == ["198.51.100.15"]
    with pytest.raises(ValueError, match="belong"):
        scans.ScanNetworkCreate(cidr="198.51.100.0/28", name="bad", excluded_ips=["10.0.0.1"])
    monkeypatch.setattr(scans.settings, "SCAN_NETWORKS", [])


@pytest.mark.asyncio
async def test_manual_scan_fails_closed_until_authorized_cidr_exists(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(scans, "settings", type("Settings", (), {"SCAN_NETWORKS": []})())
    with pytest.raises(HTTPException) as blocked:
        await scans.trigger_scan_now(request(), db, user())
    assert blocked.value.status_code == 409


@pytest.mark.asyncio
async def test_integration_creation_encrypts_config_and_rejects_duplicates(monkeypatch):
    db = FakeDB(scalar_results=[None])
    body = integrations.IntegrationCreate(
        name="lab-assets",
        connector_type="asset_api",
        config={"base_url": "https://inventory.example", "api_token": "token-value"},
    )
    result = await integrations.create_integration(body, request(), db, user())
    assert result["id"]
    integration = next(value for value in db.added if isinstance(value, Integration))
    assert integration.config["api_token"]["_kepryx_encrypted"] is True

    db.scalar_results = [uuid4()]
    with pytest.raises(HTTPException) as duplicate:
        await integrations.create_integration(body, request(), db, user())
    assert duplicate.value.status_code == 409


@pytest.mark.asyncio
async def test_self_security_settings_keep_review_gate_mandatory():
    db = FakeDB(execute_results=[FakeResult([])])
    with pytest.raises(HTTPException) as unsafe:
        await self_security.update_settings(
            self_security.SettingsUpdate(auto_update_enabled=True), request(), db, user()
        )
    assert unsafe.value.status_code == 400

    with pytest.raises(HTTPException) as unsafe_approval:
        await self_security.update_settings(
            self_security.SettingsUpdate(require_admin_approval=False), request(), db, user()
        )
    assert unsafe_approval.value.status_code == 400

    settings = self_security.SelfSecuritySettings(id=1)
    db.execute_results = [FakeResult([settings])]
    result = await self_security.update_settings(
        self_security.SettingsUpdate(auto_scan_enabled=False), request(), db, user()
    )
    assert result["changes"] == {"auto_scan_enabled": False}
    assert settings.auto_scan_enabled is False
