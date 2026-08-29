"""Tenable Nessus connector."""

import logging

import httpx

from app.connectors import BaseConnector, register_connector

logger = logging.getLogger(__name__)


@register_connector("vuln_nessus")
class NessusConnector(BaseConnector):
    """
    Config:
      base_url: https://nessus.example.local:8834
      access_key: <encrypted by the integration service>
      secret_key: <encrypted by the integration service>
      verify_ssl: true
    """

    def _headers(self) -> dict:
        return {
            "X-ApiKeys": f"accessKey={self.config['access_key']}; secretKey={self.config['secret_key']}"
        }

    async def fetch_inventory(self) -> list[dict]:
        async with httpx.AsyncClient(
            timeout=60.0, verify=self.config.get("verify_ssl", True)
        ) as client:
            # Get all scan results
            scans = await client.get(f"{self.config['base_url']}/scans", headers=self._headers())
            scans.raise_for_status()
            scan_list = scans.json().get("scans", [])

            assets_map: dict[str, dict] = {}
            for scan in scan_list:
                if scan.get("status") != "completed":
                    continue
                detail = await client.get(
                    f"{self.config['base_url']}/scans/{scan['id']}",
                    headers=self._headers(),
                )
                if detail.status_code != 200:
                    continue
                data = detail.json()
                for host in data.get("hosts", []):
                    ip = host.get("hostname") or host.get("host-ip")
                    if not ip:
                        continue
                    key = ip
                    if key not in assets_map:
                        assets_map[key] = {
                            "name": host.get("hostname") or ip,
                            "ip": host.get("host-ip"),
                            "hostname": host.get("hostname"),
                            "type": "Unknown",
                            "os": host.get("operating-system"),
                            "vulnerabilities": {
                                "critical": host.get("critical", 0),
                                "high": host.get("high", 0),
                                "medium": host.get("medium", 0),
                                "low": host.get("low", 0),
                            },
                            "attrs": {"scan_ids": [scan["id"]]},
                        }
                    else:
                        assets_map[key]["attrs"]["scan_ids"].append(scan["id"])
            return list(assets_map.values())

    async def test_connection(self) -> bool:
        try:
            async with httpx.AsyncClient(
                timeout=10.0, verify=self.config.get("verify_ssl", True)
            ) as client:
                r = await client.get(
                    f"{self.config['base_url']}/server/status", headers=self._headers()
                )
                return r.status_code == 200
        except Exception as e:
            logger.error(f"Nessus test failed: {e}")
            return False
