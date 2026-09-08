"""NetBox network inventory/source-of-truth connector."""

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


def _value(item: Any, key: str) -> Any:
    return item.get(key) if isinstance(item, dict) else None


def _address(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("address")
    if not isinstance(value, str) or not value:
        return None
    return value.split("/", 1)[0]


@register_connector("netbox")
class NetBoxConnector(BaseConnector):
    """Read NetBox devices through its paginated REST API.

    Config: ``base_url``, ``api_token``, and optional ``devices_path``,
    ``token_scheme``, ``timeout_sec``, and ``verify_ssl``. ``Bearer`` is the
    default for NetBox v2 tokens; ``Token`` remains available for legacy v1
    tokens. The connector is read-only and does not create or modify NetBox
    objects.
    """

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = str(config["base_url"]).rstrip("/")
        self.devices_path = str(config.get("devices_path", "/api/dcim/devices/"))
        self.token_scheme = str(config.get("token_scheme", "bearer")).lower()
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
        scheme = "Token" if self.token_scheme == "token" else "Bearer"  # noqa: S105  # nosec B105 - auth scheme name, not a credential
        request_url = (
            path if urlparse(path).scheme else f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        )
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"{scheme} {self.config['api_token']}",
                "Accept": "application/json",
            },
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=False,
        ) as client:
            response = await client.get(request_url, params=params)
        if response.status_code in {408, 429} or response.status_code >= 500:
            raise httpx.HTTPStatusError(
                f"NetBox returned retryable HTTP {response.status_code}",
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
                raise ValueError("NetBox pagination URL changed API origin")
            return parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return value if value.startswith("/") else None

    def _normalize_device(self, device: dict[str, Any]) -> dict[str, Any] | None:
        name = device.get("name") or device.get("display") or device.get("id")
        if not name:
            return None
        device_type = _value(device.get("device_type"), "model") or _value(
            device.get("device_type"), "display"
        )
        role = _value(device.get("role"), "name")
        platform = _value(device.get("platform"), "name")
        site = _value(device.get("site"), "name") or "Network"
        primary_ip = _address(device.get("primary_ip4") or device.get("primary_ip"))
        software = [item for item in (platform, device_type, role) if item]
        return {
            "name": str(name),
            "hostname": str(name),
            "type": "Network Device",
            "os": str(platform or device_type) if (platform or device_type) else None,
            "ip": primary_ip,
            "mac": device.get("primary_mac_address"),
            "segment": str(site),
            # NetBox inventory is not endpoint detection telemetry.
            "edr_status": "N/A (NetBox)",
            "control_coverage": "partial",
            "network_exposure": "internal",
            "auth_method": "none",
            "criticality": "medium",
            "data_classification": "Internal",
            "software_stack": list(dict.fromkeys(str(item)[:128] for item in software)),
            "attrs": {
                "provider": "netbox",
                "provider_id": device.get("id"),
                "provider_url": device.get("url"),
                "site": site,
                "role": role,
                "device_type": device_type,
                "status": _value(device.get("status"), "value")
                or _value(device.get("status"), "label"),
                "inventory_evidence": "NetBox device record",
                "edr_coverage_observed": False,
            },
        }

    async def fetch_inventory(self) -> list[dict]:
        path: str | None = self.devices_path
        assets: list[dict] = []
        page_count = 0
        seen_paths: set[str] = set()
        while path:
            if path in seen_paths:
                raise ValueError("NetBox pagination repeated a page URL")
            if page_count >= self.max_pages:
                raise ValueError("NetBox pagination exceeded max_pages")
            seen_paths.add(path)
            page_count += 1
            response = await self._get(path)
            payload = response.json()
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list):
                raise ValueError("NetBox response must contain a results array")
            assets.extend(
                normalized
                for device in results
                if isinstance(device, dict)
                for normalized in [self._normalize_device(device)]
                if normalized is not None
            )
            if len(assets) > self.max_assets:
                raise ValueError("NetBox inventory exceeded max_assets")
            path = self._next_path(payload.get("next")) if isinstance(payload, dict) else None
        return assets

    async def test_connection(self) -> bool:
        try:
            response = await self._get(self.devices_path, params={"limit": 1})
            payload = response.json()
            return isinstance(payload, dict) and isinstance(payload.get("results"), list)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("NetBox connection test failed: %s", type(exc).__name__)
            return False
