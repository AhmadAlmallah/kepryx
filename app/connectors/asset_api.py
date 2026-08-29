"""Vendor-neutral Asset Source API connector."""

import logging
from typing import Any

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


@register_connector("asset_api")
class AssetApiConnector(BaseConnector):
    """Read normalized assets from a small vendor-neutral HTTP inventory API.

    Config: ``base_url``, ``api_token``, and optional ``inventory_path`` or
    ``timeout_sec``. The token is supplied as ``X-API-Key`` and is never logged.
    Retryable 408, 429, 5xx, network, and timeout failures are retried three times;
    authentication and other 4xx responses fail closed.
    """

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = str(config["base_url"]).rstrip("/")
        self.inventory_path = str(config.get("inventory_path", "/v1/assets"))
        self.timeout = float(config.get("timeout_sec", 10))

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, min=0.1, max=1),
        reraise=True,
    )
    async def _get(self, path: str) -> httpx.Response:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-API-Key": str(self.config["api_token"])},
            timeout=self.timeout,
            follow_redirects=False,
        ) as client:
            response = await client.get(path)
        if response.status_code in {408, 429} or response.status_code >= 500:
            raise httpx.HTTPStatusError(
                f"Asset Source API returned retryable HTTP {response.status_code}",
                request=response.request,
                response=response,
            )
        response.raise_for_status()
        return response

    async def test_connection(self) -> bool:
        try:
            response = await self._get(self.inventory_path)
            payload = response.json()
            return isinstance(payload, dict) and isinstance(payload.get("assets"), list)
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Asset Source API connection test failed: %s", type(exc).__name__)
            return False

    async def fetch_inventory(self) -> list[dict]:
        response = await self._get(self.inventory_path)
        payload = response.json()
        assets = payload.get("assets") if isinstance(payload, dict) else None
        if not isinstance(assets, list):
            raise ValueError("Asset Source API response must contain an assets array")
        return [asset for asset in assets if isinstance(asset, dict)]
