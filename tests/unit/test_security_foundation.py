"""Regression tests for the security foundation."""

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api.deps import ensure_management_network
from app.api.exports import _csv_safe
from app.core.config import _parse_list_setting, settings
from app.core.connector_secrets import (
    protect_connector_config,
    resolve_connector_config,
    validate_connector_config,
)
from app.core.security import (
    create_access_token,
    decode_token,
    protect_mfa_secret,
    reveal_mfa_secret,
)


def _request(client_host: str, headers: dict[str, str] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (key.lower().encode(), value.encode()) for key, value in (headers or {}).items()
            ],
            "client": (client_host, 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


def test_access_token_round_trip_has_required_claims():
    token = create_access_token("user-123", ["assets:read"], {"role": "viewer"})
    claims = decode_token(token)
    assert claims["sub"] == "user-123"
    assert claims["type"] == "access"
    assert claims["scopes"] == ["assets:read"]
    assert claims["iss"]
    assert claims["aud"]
    assert claims["jti"]


def test_access_token_rejects_reserved_claim_override():
    with pytest.raises(ValueError, match="reserved"):
        create_access_token("user-123", [], {"sub": "attacker"})


def test_mfa_secret_is_encrypted_at_rest():
    secret = "JBSWY3DPEHPK3PXP"  # pragma: allowlist secret
    protected = protect_mfa_secret(secret)
    assert protected.startswith("v1:")
    assert secret not in protected
    assert reveal_mfa_secret(protected) == secret


def test_connector_secret_is_encrypted_and_round_trips():
    raw = {
        "base_url": "https://falcon.example.test",
        "client_id": "client-id",
        "client_secret": "top-secret",  # pragma: allowlist secret
    }
    protected = protect_connector_config("edr_crowdstrike", raw)
    assert protected["client_secret"] != raw["client_secret"]
    assert "top-secret" not in str(protected)
    assert resolve_connector_config("edr_crowdstrike", protected) == raw


def test_connector_validation_blocks_cloud_metadata():
    with pytest.raises(ValueError, match="blocked metadata"):
        validate_connector_config(
            "edr_crowdstrike",
            {
                "base_url": "https://169.254.169.254",
                "client_id": "client-id",
                "client_secret": "secret",  # pragma: allowlist secret
            },
        )


def test_connector_validation_blocks_non_global_literal_without_authorization():
    with pytest.raises(ValueError, match="non-global"):
        validate_connector_config(
            "asset_api",
            {"base_url": "https://127.0.0.1", "api_token": "token"},
        )


def test_connector_validation_allows_explicit_private_cidr(monkeypatch):
    monkeypatch.setattr(settings, "CONNECTOR_ALLOWED_CIDRS", ["10.20.0.0/24"])
    config = validate_connector_config(
        "asset_api",
        {"base_url": "https://10.20.0.10", "api_token": "token"},
    )
    assert config["base_url"] == "https://10.20.0.10"


def test_management_network_blocks_unapproved_client(monkeypatch):
    monkeypatch.setattr(settings, "MANAGEMENT_CIDRS", ["10.20.0.0/24"])
    with pytest.raises(HTTPException) as exc_info:
        ensure_management_network(_request("192.0.2.10"))
    assert exc_info.value.status_code == 403


def test_management_network_uses_real_ip_from_trusted_proxy(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_CIDRS", ["172.29.0.0/24"])
    monkeypatch.setattr(settings, "MANAGEMENT_CIDRS", ["192.0.2.0/24"])
    request = _request("172.29.0.2", {"X-Real-IP": "192.0.2.10"})
    ensure_management_network(request)


def test_connector_resolution_rejects_plaintext_legacy_secret():
    with pytest.raises(ValueError, match="not encrypted"):
        resolve_connector_config(
            "edr_crowdstrike",
            {
                "base_url": "https://falcon.example.test",
                "client_id": "client-id",
                "client_secret": "plaintext",  # pragma: allowlist secret
            },
        )


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_formula_prefixes_are_neutralized(prefix):
    assert _csv_safe(f"{prefix}payload").startswith("'")


def test_list_settings_accept_json_and_comma_delimited_values():
    assert _parse_list_setting("ALLOWED_HOSTS", '["a.example", "b.example"]') == [
        "a.example",
        "b.example",
    ]
    assert _parse_list_setting("ALLOWED_HOSTS", "a.example, b.example") == [
        "a.example",
        "b.example",
    ]
