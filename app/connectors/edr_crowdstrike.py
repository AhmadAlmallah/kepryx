"""CrowdStrike Falcon EDR connector."""

import logging

import httpx

from app.connectors import BaseConnector, register_connector

logger = logging.getLogger(__name__)


@register_connector("edr_crowdstrike")
class CrowdStrikeConnector(BaseConnector):
    """
    Config:
      base_url: https://api.crowdstrike.com
      client_id: <oauth2 client id>
      client_secret: <encrypted by the integration service>
    """

    async def _token(self, client: httpx.AsyncClient) -> str:
        r = await client.post(
            f"{self.config['base_url']}/oauth2/token",
            data={
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]

    async def fetch_inventory(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            token = await self._token(client)
            headers = {"Authorization": f"Bearer {token}"}

            # Query device IDs
            ids_resp = await client.get(
                f"{self.config['base_url']}/devices/queries/devices/v1",
                params={"limit": 5000},
                headers=headers,
            )
            ids_resp.raise_for_status()
            device_ids = ids_resp.json().get("resources", [])

            assets = []
            # Batch detail fetch (100 per request)
            for batch_start in range(0, len(device_ids), 100):
                batch = device_ids[batch_start : batch_start + 100]
                detail = await client.get(
                    f"{self.config['base_url']}/devices/entities/devices/v2",
                    params=[("ids", did) for did in batch],
                    headers=headers,
                )
                detail.raise_for_status()
                for d in detail.json().get("resources", []):
                    assets.append(
                        {
                            "name": d.get("hostname"),
                            "hostname": d.get("hostname"),
                            "ip": d.get("local_ip") or d.get("external_ip"),
                            "mac": d.get("mac_address"),
                            "os": f"{d.get('os_version', '')} {d.get('os_build', '')}".strip(),
                            "type": "Server"
                            if "server" in (d.get("product_type_desc", "")).lower()
                            else "Endpoint",
                            "edr_status": f"CrowdStrike {d.get('agent_version', '')}",
                            "control_coverage": "full",
                            "auth_method": "mfa",
                            "segment": d.get("site_name") or "Corporate",
                            "attrs": {
                                "device_id": d.get("device_id"),
                                "first_seen": d.get("first_seen"),
                                "last_seen": d.get("last_seen"),
                                "policies": d.get("policies", []),
                            },
                        }
                    )
            return [a for a in assets if a.get("name")]

    async def test_connection(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await self._token(client)
            return True
        except Exception as e:
            logger.error(f"CrowdStrike test failed: {e}")
            return False
