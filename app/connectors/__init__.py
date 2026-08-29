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
        vuln_nessus,
    )

    return list(_CONNECTORS.keys())
