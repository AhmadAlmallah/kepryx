"""Validation and field-level encryption for integration connector configs."""

import ipaddress
import secrets
from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

from croniter import croniter  # type: ignore[import-untyped, unused-ignore]

from app.core.config import settings
from app.core.encryption import decrypt_secret, encrypt_secret

_SCHEMAS = {
    "edr_crowdstrike": {
        "required": {"base_url", "client_id", "client_secret"},
        "optional": set(),
        "secret": {"client_secret"},
        "urls": {"base_url"},
    },
    "vuln_nessus": {
        "required": {"base_url", "access_key", "secret_key"},
        "optional": {"verify_ssl"},
        "secret": {"access_key", "secret_key"},
        "urls": {"base_url"},
    },
    "ad_ldap": {
        "required": {"server", "base_dn", "bind_dn", "bind_password"},
        "optional": {"ca_certs_file", "filter"},
        "secret": {"bind_password"},
        "urls": {"server"},
    },
    "cloud_aws": {
        "required": {"regions"},
        "optional": {
            "access_key_id",
            "secret_access_key",
            "role_arn",
            "use_assume_role",
        },
        "secret": {"access_key_id", "secret_access_key"},
        "urls": set(),
    },
    "dhcp_dns": {
        "required": {"provider", "base_url"},
        "optional": {"username", "password", "verify_ssl"},
        "secret": {"username", "password"},
        "urls": {"base_url"},
    },
    "asset_api": {
        "required": {"base_url", "api_token"},
        "optional": {"inventory_path", "timeout_sec"},
        "secret": {"api_token"},
        "urls": {"base_url"},
    },
}

_BLOCKED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
}


def validate_schedule(schedule: str) -> str:
    if not croniter.is_valid(schedule):
        raise ValueError("schedule_cron must be a valid five-field cron expression")
    return schedule


def _validate_url(field: str, value: str) -> None:
    parsed = urlparse(value)
    allowed_schemes = {"ldaps"} if field == "server" else {"https"}
    if settings.ALLOW_INSECURE_CONNECTORS:
        allowed_schemes.update({"http", "ldap"})
    if parsed.scheme not in allowed_schemes or not parsed.hostname:
        raise ValueError(f"{field} must use one of {sorted(allowed_schemes)} and include a host")
    host = parsed.hostname.lower()
    if host in _BLOCKED_HOSTS:
        raise ValueError(f"{field} targets a blocked metadata endpoint")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Hostnames remain valid for providers and internal DNS. Their runtime
        # egress must still be restricted by the deployment network policy.
        return

    if address.is_global:
        return
    try:
        explicitly_allowed = any(
            address.version == network.version and address in network
            for network in (
                ipaddress.ip_network(cidr, strict=False)
                for cidr in settings.CONNECTOR_ALLOWED_CIDRS
            )
        )
    except ValueError as exc:
        raise ValueError("CONNECTOR_ALLOWED_CIDRS contains an invalid CIDR") from exc
    if explicitly_allowed:
        return
    raise ValueError(
        f"{field} cannot target a private, loopback, link-local, reserved, or other "
        "non-global address unless its CIDR is in CONNECTOR_ALLOWED_CIDRS"
    )


def validate_connector_config(connector_type: str, config: dict[str, Any]) -> dict[str, Any]:
    schema = _SCHEMAS.get(connector_type)
    if not schema:
        raise ValueError("Unknown connector type")
    supplied = set(config)
    missing = schema["required"] - supplied
    unknown = supplied - schema["required"] - schema["optional"]
    if missing:
        raise ValueError(f"Missing connector fields: {sorted(missing)}")
    if unknown:
        raise ValueError(f"Unknown connector fields: {sorted(unknown)}")
    for field in schema["urls"]:
        _validate_url(field, str(config[field]))
    if connector_type == "cloud_aws":
        regions = config.get("regions")
        if (
            not isinstance(regions, list)
            or not regions
            or not all(isinstance(region, str) and region for region in regions)
        ):
            raise ValueError("AWS regions must be a non-empty list of region names")
        static_pair = bool(config.get("access_key_id")) == bool(config.get("secret_access_key"))
        if not static_pair:
            raise ValueError("AWS access_key_id and secret_access_key must be supplied together")
        if not config.get("role_arn") and not config.get("access_key_id"):
            # Default credential chain is allowed for workload identity.
            config = {**config, "use_assume_role": False}
    if config.get("verify_ssl") is False and not settings.ALLOW_INSECURE_CONNECTORS:
        raise ValueError("verify_ssl=false requires ALLOW_INSECURE_CONNECTORS=true")
    if connector_type == "dhcp_dns":
        if config.get("provider") not in {"infoblox", "kea"}:
            raise ValueError("provider must be infoblox or kea")
        if config.get("provider") == "infoblox" and not all(
            config.get(field) for field in ("username", "password")
        ):
            raise ValueError("Infoblox requires username and password")
    return deepcopy(config)


def protect_connector_config(connector_type: str, config: dict[str, Any]) -> dict[str, Any]:
    protected = validate_connector_config(connector_type, config)
    for field in _SCHEMAS[connector_type]["secret"]:
        value = protected.get(field)
        if value in (None, ""):
            continue
        salt = secrets.token_urlsafe(24)
        protected[field] = {
            "_kepryx_encrypted": True,
            "ciphertext": encrypt_secret(str(value), salt),
            "salt": salt,
        }
    return protected


def resolve_connector_config(connector_type: str, config: dict[str, Any]) -> dict[str, Any]:
    resolved = deepcopy(config)
    for field in _SCHEMAS[connector_type]["secret"]:
        value = resolved.get(field)
        if value in (None, ""):
            continue
        if not isinstance(value, dict) or value.get("_kepryx_encrypted") is not True:
            raise ValueError(f"Connector secret {field} is not encrypted; rotate the integration")
        resolved[field] = decrypt_secret(value["ciphertext"], value["salt"])
    return resolved
