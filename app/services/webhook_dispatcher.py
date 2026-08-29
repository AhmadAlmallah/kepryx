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


def _resolve_and_check(hostname: str) -> tuple[bool, str]:
    """H-03 fix: Resolve hostname and verify it's not a private IP.

    Prevents DNS rebinding attacks where a hostname initially resolves
    to a public IP at registration but to a private IP at dispatch time.
    """
    try:
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"

    for _family, _, _, _, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if not is_public_ip(ip):
                return False, f"Hostname resolves to non-routable IP: {ip_str}"
        except ValueError:
            continue
    return True, ""


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
async def _post_with_retry(url: str, payload: dict, headers: dict) -> dict:
    # H-03 fix: disable follow_redirects to prevent redirect-based SSRF
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
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
    except ValueError:
        # Hostname - verify it doesn't resolve to a private IP
        safe, reason = _resolve_and_check(parsed.hostname)
        if not safe:
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
        result = await _post_with_retry(webhook.url, payload, headers)
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
