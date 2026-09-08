"""FleetDM endpoint inventory connector.

FleetDM is used here as an endpoint-management and osquery inventory source.
This connector reads enrolled hosts only; it does not treat FleetDM as an EDR
or claim that an enrolled host has endpoint detection coverage.
"""

import logging
from typing import Any
from urllib.parse import urlparse

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from app.connectors import BaseConnector, register_connector

logger = logging.getLogger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (httpx.NetworkError, httpx.TimeoutException)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status in {408, 429} or status >= 500
    return False


def _clean_ip(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    return value.split("/", 1)[0]


def _software_names(software: Any) -> list[str]:
    if not isinstance(software, list):
        return []
    names: list[str] = []
    for item in software:
        if isinstance(item, str) and item:
            names.append(item[:128])
        elif isinstance(item, dict):
            name = item.get("name") or item.get("display_name")
            version = item.get("version")
            if name:
                names.append(f"{name} {version}".strip()[:128])
    return list(dict.fromkeys(names))[:100]


@register_connector("fleetdm")
class FleetDMConnector(BaseConnector):
    """Read enrolled FleetDM hosts through the documented REST API.

    Config: ``base_url``, ``api_token``, and optional ``hosts_path``,
    ``per_page``, ``timeout_sec``, and ``verify_ssl``. FleetDM API tokens are
    sent as ``Authorization: Bearer`` and are never logged.
    """

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = str(config["base_url"]).rstrip("/")
        self.hosts_path = str(config.get("hosts_path", "/api/v1/fleet/hosts"))
        self.per_page = int(config.get("per_page", 50))
        self.max_pages = int(config.get("max_pages", 100))
        self.max_assets = int(config.get("max_assets", 10000))
        self.timeout = float(config.get("timeout_sec", 15))
        self.verify_ssl = bool(config.get("verify_ssl", True))

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, min=0.1, max=1),
        reraise=True,
    )
    async def _get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        request_url = (
            path if urlparse(path).scheme else f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        )
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.config['api_token']}",
                "Accept": "application/json",
            },
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=False,
        ) as client:
            response = await client.get(request_url, params=params)
        if response.status_code in {408, 429} or response.status_code >= 500:
            raise httpx.HTTPStatusError(
                f"FleetDM returned retryable HTTP {response.status_code}",
                request=response.request,
                response=response,
            )
        response.raise_for_status()
        return response

    def _next_path(self, value: Any) -> str | None:
        if not value or not isinstance(value, str):
            return None
        parsed = urlparse(value)
        base = urlparse(self.base_url)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme != base.scheme or parsed.netloc != base.netloc:
                raise ValueError("FleetDM pagination URL changed API origin")
            return parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return value if value.startswith("/") else None

    @staticmethod
    def _normalize_host(host: dict[str, Any]) -> dict[str, Any] | None:
        name = host.get("display_name") or host.get("hostname") or host.get("computer_name")
        if not name:
            name = host.get("uuid") or (f"fleet-host-{host['id']}" if host.get("id") else None)
        if not name:
            return None

        platform = str(host.get("platform") or "").strip()
        os_name = str(host.get("os_name") or "").strip()
        os_version = str(host.get("os_version") or host.get("os_version_name") or "").strip()
        os_value = " ".join(part for part in (os_name, os_version) if part) or platform or None
        host_id = host.get("id")
        status = host.get("status") or "unknown"
        return {
            "name": str(name),
            "hostname": host.get("hostname"),
            "type": "Endpoint",
            "os": os_value,
            "ip": _clean_ip(host.get("primary_ip") or host.get("ipv4")),
            "mac": host.get("primary_mac"),
            "segment": "Endpoint-Lab",
            # Fleet enrollment is endpoint-management evidence, not EDR evidence.
            "edr_status": "N/A (FleetDM)",
            "control_coverage": "full",
            "network_exposure": "internal",
            "auth_method": "none",
            "criticality": "medium",
            "data_classification": "Internal",
            "software_stack": _software_names(host.get("software")),
            "attrs": {
                "provider": "fleetdm",
                "provider_id": host_id,
                "uuid": host.get("uuid"),
                "hardware_serial": host.get("hardware_serial"),
                "platform": platform or None,
                "status": status,
                "seen_time": host.get("seen_time"),
                "updated_at": host.get("updated_at"),
                "management_evidence": "FleetDM enrolled host",
                "edr_coverage_observed": False,
            },
        }

    async def fetch_inventory(self) -> list[dict]:
        page = 0
        page_count = 0
        path: str | None = self.hosts_path
        assets: list[dict] = []
        seen_paths: set[str] = set()
        while path:
            if path in seen_paths:
                raise ValueError("FleetDM pagination repeated a page URL")
            if page_count >= self.max_pages:
                raise ValueError("FleetDM pagination exceeded max_pages")
            seen_paths.add(path)
            page_count += 1
            response = await self._get(
                path,
                params=None if "?" in path else {"page": page, "per_page": self.per_page},
            )
            payload = response.json()
            hosts = payload.get("hosts") if isinstance(payload, dict) else None
            if not isinstance(hosts, list):
                raise ValueError("FleetDM response must contain a hosts array")
            assets.extend(
                normalized
                for host in hosts
                if isinstance(host, dict)
                for normalized in [self._normalize_host(host)]
                if normalized is not None
            )
            if len(assets) > self.max_assets:
                raise ValueError("FleetDM inventory exceeded max_assets")
            meta = payload.get("meta", {}) if isinstance(payload, dict) else {}
            next_path = self._next_path(meta.get("next")) if isinstance(meta, dict) else None
            if next_path is None and isinstance(meta, dict) and meta.get("has_next_results"):
                page += 1
                next_path = self.hosts_path
            path = next_path
            if path == self.hosts_path and page == 0:
                page += 1
            if not meta.get("has_next_results", False) and next_path is None:
                break
        return assets

    async def test_connection(self) -> bool:
        try:
            response = await self._get(self.hosts_path, params={"page": 0, "per_page": 1})
            payload = response.json()
            return isinstance(payload, dict) and isinstance(payload.get("hosts"), list)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("FleetDM connection test failed: %s", type(exc).__name__)
            return False
