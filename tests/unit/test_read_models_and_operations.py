"""Focused coverage for read models, operational workers, and token controls."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from app.api import dashboard, exports
from app.core import api_token_auth, token_blocklist
from app.core.config import settings
from app.models import Alert
from app.models.self_security import SelfSecuritySettings
from app.services import notifications
from app.workers import notification_tasks, retention_tasks, self_security_tasks
from tests.support import FakeDB, FakeResult


class QueueDB:
    """Small async-session double for ordered scalar and execute calls."""

    def __init__(self, *, scalars=None, results=None):
        self.scalars = list(scalars or [])
        self.results = list(results or [])
        self.added = []
        self.commits = 0

    async def scalar(self, _statement):
        return self.scalars.pop(0)

    async def execute(self, _statement):
        return self.results.pop(0)

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        return None

    async def commit(self):
        self.commits += 1


class SessionFactory:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, *_args):
        return None


def _text_response(response):
    async def collect():
        chunks = [chunk async for chunk in response.body_iterator]
        return "".join(chunk.decode() if isinstance(chunk, bytes) else chunk for chunk in chunks)

    return collect


@pytest.mark.asyncio
async def test_dashboard_overview_normalizes_operational_state():
    now = datetime.now(UTC)
    scan = SimpleNamespace(
        id=uuid4(),
        scan_type="discovery",
        target="198.51.100.0/28",
        status="completed",
        hosts_found=4,
        started_at=now - timedelta(minutes=3),
        completed_at=now,
        error=None,
    )
    self_settings = SimpleNamespace(
        last_scan_status="success",
        last_successful_scan_at=now,
        packages_scanned=18,
    )
    open_alert = SimpleNamespace(
        id=uuid4(),
        alert_type="shadow_it",
        severity="high",
        title="Unmanaged host",
        asset_id=uuid4(),
        status="open",
        created_at=now,
    )
    activity = SimpleNamespace(
        id=uuid4(),
        timestamp=now,
        action="asset.updated",
        resource_type="asset",
        resource_id="asset-1",
        severity="info",
    )
    db = QueueDB(
        scalars=[12, 1, 3, 2, 4, 5, 2, 18, 3, 1, 0],
        results=[
            FakeResult([scan]),
            FakeResult([self_settings]),
            FakeResult([("cis-v8", "compliant", 3), ("cis-v8", "gap", 1)]),
            FakeResult([open_alert]),
            FakeResult([activity]),
        ],
    )

    result = await dashboard.dashboard_overview(db)

    assert result["summary"] == {
        "total_assets": 12,
        "critical_assets": 1,
        "high_assets": 3,
        "shadow_assets": 2,
        "open_alerts": 4,
        "kev_cves": 5,
        "enabled_integrations": 2,
        "stale_assets": 1,
        "eol_assets": 0,
    }
    assert result["scan"]["status"] == "completed"
    assert result["self_security"]["findings"] == 3
    assert result["compliance"]["cis-v8"]["compliance_pct"] == 75.0
    assert result["alerts"][0]["type"] == "shadow_it"
    assert result["activity"][0]["action"] == "asset.updated"


@pytest.mark.asyncio
async def test_dashboard_overview_handles_empty_optional_state():
    db = QueueDB(
        scalars=[0] * 11,
        results=[FakeResult([]), FakeResult([]), FakeResult([]), FakeResult([]), FakeResult([])],
    )

    result = await dashboard.dashboard_overview(db)

    assert result["scan"] == {
        "id": None,
        "type": None,
        "target": None,
        "status": "never",
        "hosts_found": 0,
        "started_at": None,
        "completed_at": None,
        "error": None,
    }
    assert result["self_security"]["status"] == "never"
    assert result["compliance"] == {}
    assert result["alerts"] == []


@pytest.mark.asyncio
async def test_inventory_graph_emits_evidence_backed_relationships():
    now = datetime.now(UTC)
    first_id = uuid4()
    second_id = uuid4()
    assets = [
        SimpleNamespace(
            id=first_id,
            name="web-01",
            risk_tier="High",
            risk_score=72.5,
            is_shadow=False,
            segment="production",
            sources=["cmdb", "scanner"],
            dependencies=["postgres", "redis"],
            last_seen=now,
        ),
        SimpleNamespace(
            id=second_id,
            name="lab-01",
            risk_tier="Low",
            risk_score=12.0,
            is_shadow=True,
            segment=None,
            sources=None,
            dependencies=None,
            last_seen=None,
        ),
    ]
    alert = SimpleNamespace(
        id=uuid4(),
        asset_id=first_id,
        title="Open exposure",
        severity="high",
        status="open",
        created_at=now,
    )
    cve = SimpleNamespace(
        id="CVE-2026-0001",
        cvss_v3=9.8,
        epss_score=0.91,
        kev=True,
        last_synced=now,
    )
    asset_cve = SimpleNamespace(
        asset_id=first_id,
        matched_cpe="cpe:2.3:a:example:web:1.0:*:*:*:*:*:*:*",
        discovered_at=now,
    )
    db = QueueDB(results=[FakeResult(assets), FakeResult([alert]), FakeResult([(asset_cve, cve)])])

    result = await dashboard.inventory_graph(db, limit=50)

    node_types = {node["type"] for node in result["nodes"]}
    relations = {edge["relation"] for edge in result["edges"]}
    assert {"asset", "segment", "source", "dependency", "alert", "cve"} <= node_types
    assert {"member_of", "reported_by", "declares", "has_alert", "affected_by"} <= relations
    cve_node = next(node for node in result["nodes"] if node["type"] == "cve")
    assert cve_node["evidence_source"] == "NVD/EPSS/KEV"
    assert result["meta"]["authoritative_sources"] == ["NVD", "EPSS", "CISA KEV", "OSV"]


@pytest.mark.asyncio
async def test_inventory_graph_can_exclude_vulnerabilities_and_is_bounded():
    asset = SimpleNamespace(
        id=uuid4(),
        name="minimal",
        risk_tier="Informational",
        risk_score=0,
        is_shadow=False,
        segment=None,
        sources=[],
        dependencies=[],
        last_seen=None,
    )
    db = QueueDB(results=[FakeResult([asset]), FakeResult([])])

    result = await dashboard.inventory_graph(db, limit=2, include_vulnerabilities=False)

    assert result["meta"]["asset_count"] == 1
    assert all(node["type"] != "cve" for node in result["nodes"])
    assert len(result["nodes"]) <= 2


@pytest.mark.asyncio
async def test_inventory_export_streams_rows_and_neutralizes_formula_cells():
    now = datetime.now(UTC)
    cve_link = SimpleNamespace(
        suppressed=False,
        remediated=False,
        cve=SimpleNamespace(kev=True),
    )
    ignored_link = SimpleNamespace(
        suppressed=True,
        remediated=False,
        cve=SimpleNamespace(kev=True),
    )
    asset = SimpleNamespace(
        id=uuid4(),
        name="=formula-host",
        type="server",
        os=None,
        ip=None,
        mac=None,
        segment=None,
        edr_status=None,
        control_coverage="partial",
        network_exposure="internal",
        auth_method="mfa",
        criticality="high",
        data_classification="Confidential",
        risk_score=81.2,
        risk_tier="High",
        cves=[cve_link, ignored_link],
        eol_status=False,
        is_shadow=True,
        last_seen=now,
        sources=["cmdb"],
    )
    response = await exports.export_inventory(
        FakeDB(execute_results=[FakeResult([asset])]), limit=10
    )
    body = await _text_response(response)()

    assert response.media_type == "text/csv"
    assert "'=formula-host" in body
    assert "High,1,1,no,YES," in body
    assert body.count("CVE Count") == 1


@pytest.mark.asyncio
async def test_alert_and_audit_exports_include_optional_fields():
    now = datetime.now(UTC)
    alert = SimpleNamespace(
        id=uuid4(),
        created_at=now,
        severity="high",
        alert_type="shadow_it",
        title="Shadow host",
        status="resolved",
        asset_id=None,
        resolved_at=now,
        resolved_by="qa-admin",
    )
    audit = SimpleNamespace(
        timestamp=now,
        username=None,
        action="alert.resolved",
        resource_type="alert",
        resource_id="alert-1",
        ip_address=None,
        severity="info",
        user_agent="kepryx-test" * 40,
    )
    alerts_response = await exports.export_alerts(
        FakeDB(execute_results=[FakeResult([alert])]), limit=10
    )
    audit_response = await exports.export_audit(
        FakeDB(execute_results=[FakeResult([audit])]), limit=10
    )
    alerts_body = await _text_response(alerts_response)()
    audit_body = await _text_response(audit_response)()

    assert ",Shadow host,resolved,," in alerts_body
    assert "system,alert.resolved" in audit_body
    assert len(audit_body.splitlines()[-1].split(",")[-1]) <= 202


class FakeRedis:
    def __init__(self, *, mget_values=(None, None), set_result=True, error=None):
        self.mget_values = mget_values
        self.set_result = set_result
        self.error = error
        self.closed = False
        self.calls = []

    async def ping(self):
        if self.error:
            raise self.error
        return True

    async def mget(self, *_keys):
        if self.error:
            raise self.error
        return self.mget_values

    async def setex(self, *args):
        if self.error:
            raise self.error
        self.calls.append(("setex", args))

    async def set(self, *args, **kwargs):
        if self.error:
            raise self.error
        self.calls.append(("set", args, kwargs))
        return self.set_result

    async def aclose(self):
        self.closed = True


def test_token_helpers_handle_valid_and_malformed_claims():
    assert token_blocklist._ttl({"exp": 1_000_000_000_000}) >= 1
    assert token_blocklist._ttl({"exp": "bad"}) == 1
    assert token_blocklist._issued_at_ms({"iat_ms": 123}) == 123
    assert token_blocklist._issued_at_ms({"iat": 1.5}) == 1500
    assert token_blocklist._issued_at_ms({"iat": "bad"}) == 0


@pytest.mark.asyncio
async def test_token_blocklist_revocation_and_refresh_consumption(monkeypatch):
    redis = FakeRedis(mget_values=(None, None), set_result=True)
    monkeypatch.setattr(token_blocklist, "_redis", redis)
    payload = {"jti": "jti-1", "sub": "user-1", "exp": 4_000_000_000, "iat": 1_700_000_000}

    assert await token_blocklist.redis_ready() is True
    assert await token_blocklist.is_token_revoked(payload) is False
    assert await token_blocklist.consume_refresh_token(payload) is True
    await token_blocklist.revoke_token(payload)
    await token_blocklist.revoke_user_tokens("user-1")
    assert [call[0] for call in redis.calls] == ["set", "setex", "setex"]

    redis.mget_values = ("1", None)
    assert await token_blocklist.is_token_revoked(payload) is True
    redis.mget_values = (None, str(1_800_000_000_000))
    assert await token_blocklist.is_token_revoked(payload) is True
    assert await token_blocklist.is_token_revoked({"jti": None, "sub": "user-1"}) is True


@pytest.mark.asyncio
async def test_token_blocklist_fails_closed_when_redis_fails(monkeypatch):
    redis = FakeRedis(error=RedisError("offline"))
    monkeypatch.setattr(token_blocklist, "_redis", redis)

    assert await token_blocklist.redis_ready() is False
    with pytest.raises(token_blocklist.TokenBlocklistUnavailableError):
        await token_blocklist.is_token_revoked({"jti": "x", "sub": "u"})
    with pytest.raises(token_blocklist.TokenBlocklistUnavailableError):
        await token_blocklist.revoke_token({"jti": "x", "exp": 1})
    with pytest.raises(token_blocklist.TokenBlocklistUnavailableError):
        await token_blocklist.revoke_user_tokens("u")


@pytest.mark.asyncio
async def test_token_store_closes_process_local_client(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(token_blocklist, "_redis", redis)

    await token_blocklist.close_token_store()

    assert redis.closed is True
    assert token_blocklist._redis is None


@pytest.mark.asyncio
async def test_api_token_auth_skips_invalid_expired_and_wrong_candidates(monkeypatch):
    expired = SimpleNamespace(
        expires_at=datetime.now(UTC) - timedelta(minutes=1), token_hash="expired"
    )
    valid = SimpleNamespace(expires_at=None, token_hash="valid", last_used=None, usage_count=0)
    db = FakeDB(execute_results=[FakeResult([expired, valid])])
    monkeypatch.setattr(
        api_token_auth, "verify_password", lambda token, hashed: token == "kpx_valid"
    )

    assert await api_token_auth.verify_api_token("bad", db) is None
    result = await api_token_auth.verify_api_token("kpx_valid", db)

    assert result is valid
    assert result.usage_count == 1
    assert result.last_used is not None


@pytest.mark.asyncio
async def test_notifier_dispatches_configured_channels_and_isolates_failure(monkeypatch):
    monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://slack.example.test/hook")
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(settings, "PAGERDUTY_KEY", "pd-key")
    notifier = notifications.Notifier()
    calls = []

    async def slack(_alert):
        calls.append("slack")

    def email(_alert):
        calls.append("email")

    async def pagerduty(_alert):
        raise RuntimeError("pagerduty unavailable")

    def syslog(_alert):
        calls.append("syslog")

    monkeypatch.setattr(notifier, "_slack", slack)
    monkeypatch.setattr(notifier, "_email", email)
    monkeypatch.setattr(notifier, "_pagerduty", pagerduty)
    monkeypatch.setattr(notifier, "_syslog_cef", syslog)

    sent = await notifier.dispatch(
        {"severity": "critical", "title": "test", "alert_type": "qa"},
        ["slack", "email", "pagerduty", "syslog", "unknown"],
    )
    await notifier.close()

    assert sent == ["slack", "email", "syslog"]
    assert calls == ["slack", "email", "syslog"]
    assert notifier._default_channels("critical") == ["slack", "email", "pagerduty", "syslog"]
    assert notifier._default_channels("high") == ["slack", "email", "syslog"]
    assert notifier._default_channels("medium") == ["slack", "syslog"]
    assert notifier._default_channels("low") == ["syslog"]


@pytest.mark.asyncio
async def test_notification_worker_marks_alerts_after_channels_and_webhook(monkeypatch):
    alert = SimpleNamespace(
        id=uuid4(),
        alert_type="shadow_it",
        severity="high",
        title="Shadow host",
        description="test",
        asset_id=uuid4(),
        details={"ip": "198.51.100.10"},
        notified=False,
        status="open",
        notification_channels=None,
    )
    asset = SimpleNamespace(name="lab-host")
    db = FakeDB(execute_results=[FakeResult([(alert, asset)])])
    monkeypatch.setattr(notification_tasks, "SessionLocal", SessionFactory(db))
    events = []

    class FakeNotifier:
        async def dispatch(self, payload):
            events.append(("notify", payload["id"]))
            return ["syslog"]

        async def close(self):
            events.append(("close",))

    async def webhook(*args):
        events.append(("webhook", args[0]))
        raise RuntimeError("receiver down")

    monkeypatch.setattr(notification_tasks, "Notifier", FakeNotifier)
    monkeypatch.setattr(notification_tasks, "fire_event", webhook)

    result = await notification_tasks._dispatch_pending()

    assert result == {"dispatched": 1}
    assert alert.notified is True
    assert alert.notification_channels == ["syslog"]
    assert events[0][0] == "notify"
    assert events[-1] == ("close",)
    assert db.commits == 1


@pytest.mark.asyncio
async def test_retention_passes_are_safe_by_default_and_orchestrated(monkeypatch):
    monkeypatch.setattr(retention_tasks.settings, "RETENTION_DELETE_ENABLED", False)
    assert await retention_tasks._delete_expired_audit_logs() == 0
    assert await retention_tasks._delete_stale_assets() == 0

    db = FakeDB(execute_results=[FakeResult([])])
    monkeypatch.setattr(retention_tasks, "SessionLocal", SessionFactory(db))
    assert await retention_tasks._archive_old_audit_logs() == 0

    async def value(name):
        return {"archive": 2, "delete_logs": 0, "delete_assets": 0, "flag": 1}[name]

    monkeypatch.setattr(retention_tasks, "_archive_old_audit_logs", lambda: value("archive"))
    monkeypatch.setattr(retention_tasks, "_delete_expired_audit_logs", lambda: value("delete_logs"))
    monkeypatch.setattr(retention_tasks, "_delete_stale_assets", lambda: value("delete_assets"))
    monkeypatch.setattr(retention_tasks, "_flag_inactive_users", lambda: value("flag"))

    assert await retention_tasks._enforce_all() == {
        "audit_archived": 2,
        "audit_deleted": 0,
        "assets_deleted": 0,
        "users_flagged": 1,
    }


@pytest.mark.asyncio
async def test_retention_flags_inactive_users_without_duplicate_alerts(monkeypatch):
    inactive = SimpleNamespace(id=uuid4(), username="stale-user", last_login=None)
    db = FakeDB(execute_results=[FakeResult([inactive]), FakeResult([])])
    monkeypatch.setattr(retention_tasks, "SessionLocal", SessionFactory(db))

    count = await retention_tasks._flag_inactive_users()

    assert count == 1
    assert db.commits == 1
    assert isinstance(db.added[0], Alert)
    assert db.added[0].alert_type == "inactive_user"


@pytest.mark.asyncio
async def test_self_security_proposal_gates_do_not_mutate_source(monkeypatch, tmp_path):
    settings_row = SelfSecuritySettings(id=1, last_scan_status="failed")
    db = FakeDB(execute_results=[FakeResult([settings_row])])
    monkeypatch.setattr(self_security_tasks, "SessionLocal", SessionFactory(db))
    assert await self_security_tasks._propose_updates() == {"skipped": "no_recent_successful_scan"}

    settings_row.require_ai_validation = False
    db.execute_results = [FakeResult([settings_row])]
    assert await self_security_tasks._ai_validate_proposals() == {
        "skipped": "ai_validation_disabled"
    }

    prop = SimpleNamespace(package_name="fastapi", status="approved")
    missing = tmp_path / "missing-requirements.in"
    monkeypatch.setattr(self_security_tasks, "REQUIREMENTS_PATH", missing)
    assert await self_security_tasks._prepare_one_update(prop, db) is False
    assert prop.status == "failed"

    requirements = tmp_path / "requirements.in"
    requirements.write_text("fastapi>=0.141.1\nhttpx==0.27.2\n", encoding="utf-8")
    monkeypatch.setattr(self_security_tasks, "REQUIREMENTS_PATH", requirements)
    prop = SimpleNamespace(
        package_name="fastapi",
        current_version="0.141.1",
        target_version="0.142.0",
        cves_fixed=["CVE-2026-0001"],
        status="approved",
        rollback_snapshot={},
        error_message=None,
    )
    db.added.clear()
    assert await self_security_tasks._prepare_one_update(prop, db) is True
    assert prop.status == "ready_for_pr"
    assert "fastapi==0.142.0" in prop.rollback_snapshot["proposal_patch"]
    assert any(isinstance(item, Alert) for item in db.added)


@pytest.mark.asyncio
async def test_self_security_empty_or_cancelled_workflows_are_explicit(monkeypatch):
    db = FakeDB(execute_results=[FakeResult([])])
    monkeypatch.setattr(self_security_tasks, "SessionLocal", SessionFactory(db))

    assert await self_security_tasks._apply_approved_updates() == {
        "prepared_for_pr": 0,
        "failed": 0,
    }
    db.execute_results = [FakeResult([])]
    assert await self_security_tasks._rollback_proposal(str(uuid4())) == {
        "error": "no prepared patch to cancel"
    }
