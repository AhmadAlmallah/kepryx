"""DHCP/DNS connector — pulls leases for shadow IT detection."""

import logging

import httpx

from app.connectors import BaseConnector, register_connector

logger = logging.getLogger(__name__)


@register_connector("dhcp_dns")
class DHCPDNSConnector(BaseConnector):
    """
    Generic DHCP/DNS connector. Supports Infoblox WAPI and ISC Kea REST.

    Config:
      provider: infoblox | kea
      base_url: https://infoblox.local/wapi/v2.12
      username: <encrypted by the integration service>
      password: <encrypted by the integration service>
      verify_ssl: true
    """

    async def fetch_inventory(self) -> list[dict]:
        provider = self.config.get("provider", "infoblox").lower()
        if provider == "infoblox":
            return await self._fetch_infoblox()
        if provider == "kea":
            return await self._fetch_kea()
        return []

    async def _fetch_infoblox(self) -> list[dict]:
        async with httpx.AsyncClient(
            timeout=60.0,
            verify=self.config.get("verify_ssl", True),
            auth=(self.config["username"], self.config["password"]),
        ) as client:
            r = await client.get(
                f"{self.config['base_url']}/lease",
                params={
                    "_return_fields": "address,hardware,client_hostname,binding_state,starts,ends",
                    "_max_results": 5000,
                    "binding_state": "ACTIVE",
                },
            )
            r.raise_for_status()
            assets = []
            for lease in r.json():
                if lease.get("binding_state") != "ACTIVE":
                    continue
                assets.append(
                    {
                        "name": lease.get("client_hostname") or lease.get("address"),
                        "hostname": lease.get("client_hostname"),
                        "ip": lease.get("address"),
                        "mac": lease.get("hardware"),
                        "type": "Unknown",
                        "segment": "DHCP",
                        "attrs": {
                            "lease_start": lease.get("starts"),
                            "lease_end": lease.get("ends"),
                            "binding": lease.get("binding_state"),
                        },
                    }
                )
            return assets

    async def _fetch_kea(self) -> list[dict]:
        async with httpx.AsyncClient(
            timeout=60.0, verify=self.config.get("verify_ssl", True)
        ) as client:
            r = await client.post(
                self.config["base_url"],
                json={"command": "lease4-get-all", "service": ["dhcp4"]},
            )
            r.raise_for_status()
            data = r.json()
            assets = []
            for resp in data:
                for lease in resp.get("arguments", {}).get("leases", []):
                    assets.append(
                        {
                            "name": lease.get("hostname") or lease.get("ip-address"),
                            "ip": lease.get("ip-address"),
                            "mac": lease.get("hw-address"),
                            "hostname": lease.get("hostname"),
                            "type": "Unknown",
                            "segment": "DHCP",
                            "attrs": {
                                "state": lease.get("state"),
                                "subnet_id": lease.get("subnet-id"),
                            },
                        }
                    )
            return assets

    async def test_connection(self) -> bool:
        try:
            async with httpx.AsyncClient(
                timeout=10.0, verify=self.config.get("verify_ssl", True)
            ) as client:
                if self.config.get("provider") == "infoblox":
                    r = await client.get(
                        f"{self.config['base_url']}/network",
                        auth=(self.config["username"], self.config["password"]),
                        params={"_max_results": 1},
                    )
                    return r.status_code == 200
            return True
        except Exception as e:
            logger.error(f"DHCP test failed: {e}")
            return False
