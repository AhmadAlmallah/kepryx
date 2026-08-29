"""Prove the vendor-neutral Asset Source connector and retry behavior."""

from threading import Thread

import pytest

from app.connectors.asset_api import AssetApiConnector
from demo.asset_source_mock.server import create_server


def _connector(server, **overrides):
    config = {
        "base_url": f"http://127.0.0.1:{server.server_port}",
        "api_token": "simulated-asset-source-token",  # pragma: allowlist secret
    }
    config.update(overrides)
    return AssetApiConnector(config)


@pytest.mark.asyncio
async def test_asset_source_connector_reads_deterministic_fixture():
    server = create_server(port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connector = _connector(server)
        assert await connector.test_connection() is True
        assets = await connector.fetch_inventory()
        assert len(assets) == 24
        assert assets[0]["name"] == "ASSET-SIM-001"
        assert assets[0]["attrs"]["source_record_id"] == "asset-record-001"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_asset_source_connector_retries_transient_server_failures():
    server = create_server(port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assets = await _connector(server, inventory_path="/v1/assets-retry").fetch_inventory()
        assert len(assets) == 24
        assert server.RequestHandlerClass.retry_attempts == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_asset_source_connector_retries_rate_limits():
    server = create_server(port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assets = await _connector(server, inventory_path="/v1/assets-rate-limit").fetch_inventory()
        assert len(assets) == 24
        assert server.RequestHandlerClass.rate_limit_attempts == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_asset_source_connector_fails_after_timeout_retries():
    server = create_server(port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert (
            await _connector(
                server,
                inventory_path="/v1/assets-timeout",
                timeout_sec=0.05,
            ).test_connection()
            is False
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.asyncio
async def test_asset_source_connector_rejects_invalid_credentials():
    server = create_server(port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert await _connector(server, api_token="wrong-token").test_connection() is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
