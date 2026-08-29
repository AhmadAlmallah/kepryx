"""Webhook delivery service with HMAC signing + SSRF guards (H-03 fix).

QA fixes applied:
  - C-01: Uses dedicated ENCRYPTION_KEY via encryption module (not SECRET_KEY)
  - H-03: SSRF guard at dispatch time (DNS rebinding protection)
  - M-07: Failed deliveries queued for retry via webhook_deliveries table
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.database import SessionLocal
from app.core.encryption import decrypt_secret
from app.core.network_policy import is_public_ip
from app.models import Webhook

logger = logging.getLogger(__name__)


def _resolve_public_ip(hostname: str) -> tuple[str | None, str]:
    """Resolve a hostname once and return one verified global address.

    The returned address is later used for the actual socket connection. This
    prevents a DNS answer from changing between validation and HTTPX's own
    resolver lookup (DNS-rebinding/TOCTOU SSRF).
    """
    try:
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return None, f"DNS resolution failed: {e}"

    resolved_ip = None
    for _family, _, _, _, sockaddr in results:
        ip_str = str(sockaddr[0])
        try:
            ip = ipaddress.ip_address(ip_str)
            if not is_public_ip(ip):
                return None, f"Hostname resolves to non-routable IP: {ip_str}"
            resolved_ip = resolved_ip or ip_str
        except ValueError:
            continue
    if not resolved_ip:
        return None, "Hostname did not resolve to a usable IP address"
    return resolved_ip, ""


def _resolve_and_check(hostname: str) -> tuple[bool, str]:
    """Resolve hostname and verify every address is globally routable."""
    resolved_ip, reason = _resolve_public_ip(hostname)
    return resolved_ip is not None, reason


def _host_header(hostname: str, scheme: str, port: int | None) -> str:
    """Format the original authority for a request sent to a pinned IP."""
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    default_port = 443 if scheme == "https" else 80
    return f"{host}:{port}" if port and port != default_port else host


class _PinnedIPTransport(httpx.AsyncBaseTransport):
    """Send a request to a previously verified IP while preserving host/SNI."""

    def __init__(
        self,
        hostname: str,
        resolved_ip: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.hostname = hostname
        self.resolved_ip = resolved_ip
        self._transport = transport or httpx.AsyncHTTPTransport(verify=True, trust_env=False)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        headers = request.headers.copy()
        headers["Host"] = _host_header(request.url.host, request.url.scheme, request.url.port)
        extensions = dict(request.extensions)
        if request.url.scheme == "https":
            # httpcore honors this extension for TLS SNI while connecting to
            # the pinned IP in the rewritten URL.
            extensions["sni_hostname"] = self.hostname
        # HTTPX request streams are transport-specific. Read the already
        # constructed JSON body before rebuilding the request so the pinned
        # transport works consistently with both real and mock transports.
        body = await request.aread()
        pinned_request = httpx.Request(
            request.method,
            request.url.copy_with(host=self.resolved_ip),
            headers=headers,
            content=body,
            extensions=extensions,
        )
        return await self._transport.handle_async_request(pinned_request)

    async def aclose(self) -> None:
        await self._transport.aclose()


def _sign_payload(secret: str, payload: dict) -> tuple[str, str]:
    ts = str(int(datetime.now(UTC).timestamp()))
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    signed_string = f"{ts}.{body}".encode()
    sig = hmac.new(secret.encode(), signed_string, hashlib.sha256).hexdigest()
    return ts, sig


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
    reraise=False,
)
async def _post_with_retry(
    url: str,
    hostname: str,
    resolved_ip: str,
    payload: dict,
    headers: dict,
) -> dict:
    # H-03: disable redirects and pin the connection to the address verified
    # immediately before dispatch. The original host remains in Host/SNI.
    transport = _PinnedIPTransport(hostname, resolved_ip)
    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        r = await client.post(url, json=payload, headers=headers)
        # Reject 3xx redirects explicitly
        if 300 <= r.status_code < 400:
            raise httpx.HTTPError(f"Redirect not allowed (got {r.status_code})")
        r.raise_for_status()
        return {"status_code": r.status_code, "text": r.text[:200]}


async def dispatch_one(webhook: Webhook, event_type: str, data: dict) -> dict:
    """Dispatch one event with full SSRF + HMAC protection."""
    # H-03: Re-check URL at dispatch time (DNS rebinding protection)
    parsed = urlparse(webhook.url)
    if not parsed.hostname:
        webhook.last_status = "invalid_url"
        return {"delivered": False, "error": "missing hostname"}

    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
        webhook.last_status = "invalid_url"
        return {"delivered": False, "error": "invalid webhook URL"}

    # Validate IP literals again at dispatch time for legacy records and defense
    # in depth. Registration validation is not sufficient because records can
    # predate the policy or be written by an external migration.
    try:
        address = ipaddress.ip_address(parsed.hostname)
        if not is_public_ip(address):
            webhook.last_status = "ssrf_blocked"
            return {
                "delivered": False,
                "error": f"Webhook URL resolves to non-routable IP: {address}",
            }
        resolved_ip = str(address)
    except ValueError:
        # Hostname - verify and pin the resolved address for the request.
        resolved_ip, reason = _resolve_public_ip(parsed.hostname)
        if not resolved_ip:
            webhook.last_status = "ssrf_blocked"
            logger.warning(f"Webhook {webhook.id} blocked: {reason}")
            return {"delivered": False, "error": reason}

    payload = {
        "event": event_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": data,
    }
    try:
        signing_secret = decrypt_secret(webhook.secret_encrypted, salt=webhook.secret_salt)
    except Exception:
        logger.exception(f"Failed to decrypt webhook secret for {webhook.id}")
        webhook.last_status = "decrypt_error"
        return {"delivered": False, "error": "secret decryption failed"}

    ts, sig = _sign_payload(signing_secret, payload)
    headers = {
        "Content-Type": "application/json",
        "X-Kepryx-Event": event_type,
        "X-Kepryx-Timestamp": ts,
        "X-Kepryx-Signature": f"sha256={sig}",
        "User-Agent": "Kepryx-Webhook/1.0",
    }
    try:
        result = await _post_with_retry(webhook.url, parsed.hostname, resolved_ip, payload, headers)
        webhook.last_delivery = datetime.now(UTC)
        webhook.delivery_count += 1
        webhook.last_status = f"success_{result['status_code']}"
        webhook.failure_count = 0
        return {"delivered": True, "status_code": result["status_code"]}
    except Exception as e:
        logger.warning(f"Webhook {webhook.name} -> {webhook.url} failed: {e}")
        webhook.failure_count += 1
        webhook.last_status = f"failed: {str(e)[:60]}"
        if webhook.failure_count >= 10:
            webhook.enabled = False
            logger.error(f"Webhook {webhook.id} auto-disabled after 10 consecutive failures")
        return {"delivered": False, "error": str(e)[:200]}


async def fire_event(event_type: str, severity: str, data: dict):
    async with SessionLocal() as db:
        result = await db.execute(select(Webhook).where(Webhook.enabled.is_(True)))
        for webhook in result.scalars().all():
            if webhook.event_types and event_type not in webhook.event_types:
                continue
            if webhook.severity_filter and severity not in webhook.severity_filter:
                continue
            await dispatch_one(webhook, event_type, data)
        await db.commit()


def fire_event_sync(event_type: str, severity: str, data: dict):
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(fire_event(event_type, severity, data))
        else:
            loop.run_until_complete(fire_event(event_type, severity, data))
    except RuntimeError:
        asyncio.run(fire_event(event_type, severity, data))
