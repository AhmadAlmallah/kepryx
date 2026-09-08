"""Connector framework — pluggable integrations for data sources."""

from abc import ABC, abstractmethod
from typing import Any


class BaseConnector(ABC):
    """All connectors implement fetch_inventory() returning normalized asset dicts."""

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @abstractmethod
    async def fetch_inventory(self) -> list[dict]:
        """Return list of asset dicts with at minimum: name, ip or mac."""
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        """Verify credentials and reachability."""
        ...


# Registry
_CONNECTORS: dict[str, type[BaseConnector]] = {}

# Keep operator-facing metadata beside the connector registry. The API exposes
# this as additive metadata so clients can render the available connector set
# without maintaining a second hard-coded list.
_CONNECTOR_METADATA: dict[str, dict[str, object]] = {
    "ad_ldap": {
        "label": "Active Directory / LDAP",
        "description": "Directory-backed identity and computer inventory.",
        "read_only": True,
    },
    "asset_api": {
        "label": "Asset API",
        "description": "Generic inventory provider using a normalized asset API.",
        "read_only": True,
    },
    "cloud_aws": {
        "label": "AWS",
        "description": "AWS account inventory using the configured credential chain.",
        "read_only": True,
    },
    "dhcp_dns": {
        "label": "DHCP / DNS",
        "description": "Lease and name-service observations from the configured provider.",
        "read_only": True,
    },
    "edr_crowdstrike": {
        "label": "CrowdStrike",
        "description": "Endpoint inventory from the configured CrowdStrike tenant.",
        "read_only": True,
    },
    "fleetdm": {
        "label": "FleetDM",
        "description": "Enrolled endpoint-management and osquery inventory; not EDR evidence.",
        "read_only": True,
    },
    "netbox": {
        "label": "NetBox",
        "description": "Network source-of-truth device inventory; not packet monitoring.",
        "read_only": True,
    },
    "vuln_nessus": {
        "label": "Nessus",
        "description": "Completed-scan host observations from the configured Nessus server.",
        "read_only": True,
    },
}


def register_connector(name: str):
    def decorator(cls):
        _CONNECTORS[name] = cls
        return cls

    return decorator


def get_connector(name: str) -> type[BaseConnector] | None:
    # Lazy import to avoid circular deps
    from app.connectors import (  # noqa
        ad_ldap,
        asset_api,
        cloud_aws,
        dhcp_dns,
        edr_crowdstrike,
        fleetdm,
        netbox,
        vuln_nessus,
    )

    return _CONNECTORS.get(name)


def list_connectors() -> list[str]:
    from app.connectors import (  # noqa
        ad_ldap,
        asset_api,
        cloud_aws,
        dhcp_dns,
        edr_crowdstrike,
        fleetdm,
        netbox,
        vuln_nessus,
    )

    return list(_CONNECTORS.keys())


def connector_metadata(name: str) -> dict[str, object]:
    """Return safe, non-secret presentation metadata for a connector."""

    metadata = _CONNECTOR_METADATA.get(name, {})
    return {"name": name, **metadata}
