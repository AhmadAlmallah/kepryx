"""FastAPI contract and authorization smoke tests.

These tests do not require PostgreSQL or Redis for the anonymous and middleware paths. The
separate live smoke harness covers service readiness and database-backed behavior.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as value:
        yield value


@pytest.mark.asyncio
async def test_health_and_security_headers(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_api_documentation_is_disabled_in_test_mode(client):
    for path in ("/docs", "/api/docs", "/openapi.json", "/api/openapi.json", "/redoc"):
        response = await client.get(path)
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_disallowed_host_is_rejected(client):
    response = await client.get("/health", headers={"host": "attacker.example"})
    assert response.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/assets"),
        ("GET", "/api/v1/alerts"),
        ("GET", "/api/v1/compliance/summary"),
        ("GET", "/api/v1/compliance/frameworks"),
        ("GET", "/api/v1/compliance/runs"),
        ("GET", "/api/v1/compliance/runs/00000000-0000-0000-0000-000000000000"),
        ("GET", "/api/v1/compliance/results/00000000-0000-0000-0000-000000000000/lineage"),
        ("POST", "/api/v1/compliance/results/00000000-0000-0000-0000-000000000000/ai-review"),
        ("GET", "/api/v1/dashboard/overview"),
        ("GET", "/api/v1/dashboard/graph/inventory"),
        ("POST", "/api/v1/assistant/chat"),
        ("GET", "/api/v1/self-security/summary"),
        ("GET", "/api/v1/scans"),
        ("GET", "/api/v1/admin/users"),
        ("GET", "/api/v1/api-tokens"),
        ("GET", "/api/v1/webhooks"),
        ("POST", "/api/v1/ws/ticket"),
    ],
)
async def test_protected_routes_reject_anonymous_requests(client, method, path):
    response = await client.request(method, path)
    assert response.status_code == 401, (method, path, response.text)


@pytest.mark.asyncio
async def test_disallowed_cors_origin_is_rejected(client):
    response = await client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_allowed_cors_preflight_is_supported(client):
    response = await client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "https://localhost",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://localhost"
