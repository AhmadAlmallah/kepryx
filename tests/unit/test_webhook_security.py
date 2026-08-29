from types import SimpleNamespace

import httpx
import pytest

from app.api.webhooks import _is_safe_webhook_url
from app.services.webhook_dispatcher import (
    _PinnedIPTransport,
    _resolve_and_check,
    dispatch_one,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://0.0.0.0:8080/callback",
        "http://100.64.0.1:8080/callback",
        "http://[::]:8080/callback",
    ],
)
def test_webhook_registration_rejects_non_global_ip_literals(url):
    safe, reason = _is_safe_webhook_url(url)
    assert not safe
    assert "non-routable" in reason


def test_webhook_registration_rejects_url_credentials():
    safe, reason = _is_safe_webhook_url("https://user:password@example.com/callback")
    assert not safe
    assert "credentials" in reason


def test_webhook_dns_check_rejects_shared_address(monkeypatch):
    monkeypatch.setattr(
        "app.services.webhook_dispatcher.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("100.64.0.1", 0))],
    )
    safe, reason = _resolve_and_check("shared.example.test")
    assert not safe
    assert "non-routable" in reason


@pytest.mark.asyncio
async def test_dispatch_rechecks_legacy_non_global_ip_literal():
    webhook = SimpleNamespace(id="legacy-webhook", url="http://100.64.0.1:8080/callback")

    result = await dispatch_one(webhook, "test.ping", {"ok": True})

    assert result["delivered"] is False
    assert "non-routable" in result["error"]
    assert webhook.last_status == "ssrf_blocked"


@pytest.mark.asyncio
async def test_pinned_transport_preserves_authority_and_sni():
    captured = {}

    async def handler(request):
        captured["url"] = str(request.url)
        captured["host"] = request.headers["host"]
        captured["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(202, request=request)

    mock_transport = httpx.MockTransport(handler)
    transport = _PinnedIPTransport(
        "hooks.example.test",
        "93.184.216.34",
        transport=mock_transport,
    )
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post(
            "https://hooks.example.test:8443/events",
            json={"event": "test"},
        )

    assert response.status_code == 202
    assert captured == {
        "url": "https://93.184.216.34:8443/events",
        "host": "hooks.example.test:8443",
        "sni": "hooks.example.test",
    }
