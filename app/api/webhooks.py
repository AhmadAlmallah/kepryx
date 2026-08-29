"""Webhook management - hardened encryption (C-01 fix).

C-01: Use dedicated ENCRYPTION_KEY for data-at-rest. Per-record salt prevents
identical-secret-detection. KDF: PBKDF2-SHA256 with 480k iterations (OWASP 2023).

The encryption is symmetric (Fernet/AES-128) because the dispatcher needs
plaintext to sign outbound webhooks. For multi-region deployments, route
to AWS KMS / GCP KMS / Azure Key Vault via the abstraction in encryption.py.
"""

import ipaddress
import secrets as secrets_module
from datetime import UTC, datetime
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, HttpUrl, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_admin
from app.core.database import get_db
from app.core.encryption import encrypt_secret
from app.core.network_policy import is_public_ip
from app.core.security import hash_password
from app.models import Webhook

router = APIRouter()


def _is_safe_webhook_url(url: str) -> tuple[bool, str]:
    """H-03 fix: block SSRF via private IP ranges and unsafe schemes."""
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Only http/https allowed, got {parsed.scheme}"
    if not parsed.hostname:
        return False, "Missing hostname"

    if parsed.username or parsed.password:
        return False, "Webhook URLs must not contain username or password credentials"

    # Block obvious local hostnames
    blocked_hosts = {"localhost", "metadata.google.internal", "metadata"}
    if parsed.hostname.lower() in blocked_hosts:
        return False, f"Blocked hostname: {parsed.hostname}"

    # Try to resolve to an IP and check against private ranges
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if not is_public_ip(ip):
            return False, f"Webhook URL resolves to non-routable IP: {ip}"
    except ValueError:
        # It's a hostname, not an IP literal — DNS resolution check would happen at dispatch time
        # We do the IP check at dispatch_one() to handle DNS rebinding
        pass

    return True, ""


class WebhookCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=128)
    url: HttpUrl
    event_types: list[str] = Field(default_factory=lambda: ["alert.created"])
    severity_filter: list[str] = Field(default_factory=lambda: ["critical", "high"])

    @field_validator("url")
    @classmethod
    def url_must_be_safe(cls, v):
        safe, reason = _is_safe_webhook_url(str(v))
        if not safe:
            raise ValueError(reason)
        return v


KNOWN_EVENTS = {
    "alert.created",
    "alert.resolved",
    "asset.created",
    "asset.updated",
    "asset.shadow_detected",
    "scan.completed",
    "scan.failed",
    "self_security.cve_found",
    "self_security.update_proposed",
    "compliance.audit_complete",
    "integration.failed",
}


@router.post("", dependencies=[Depends(require_admin)])
async def create_webhook(
    body: WebhookCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    invalid = set(body.event_types) - KNOWN_EVENTS
    if invalid:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unknown events: {sorted(invalid)}. Known: {sorted(KNOWN_EVENTS)}",
        )

    plaintext_secret = secrets_module.token_urlsafe(32)
    salt = secrets_module.token_urlsafe(24)
    encrypted = encrypt_secret(plaintext_secret, salt=salt)

    webhook = Webhook(
        name=body.name,
        url=str(body.url),
        secret_hash=hash_password(plaintext_secret),
        secret_prefix=plaintext_secret[:8],
        secret_encrypted=encrypted,
        secret_salt=salt,
        event_types=body.event_types,
        severity_filter=body.severity_filter,
    )
    db.add(webhook)
    await audit(
        request,
        "webhook_created",
        user,
        db,
        resource_type="webhook",
        resource_id=str(webhook.id),
        details={
            "name": body.name,
            "events": body.event_types,
            "url_host": urlparse(str(body.url)).hostname,
        },
    )
    await db.commit()
    return {
        "id": str(webhook.id),
        "name": webhook.name,
        "url": webhook.url,
        "secret": plaintext_secret,
        "event_types": webhook.event_types,
        "warning": "Save this signing secret NOW. It will NEVER be shown again.",
    }


@router.get("", dependencies=[Depends(require_admin)])
async def list_webhooks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Webhook).order_by(Webhook.created_at.desc()))
    return [
        {
            "id": str(w.id),
            "name": w.name,
            "url": w.url,
            "secret_prefix": w.secret_prefix + "...",
            "event_types": w.event_types,
            "severity_filter": w.severity_filter,
            "enabled": w.enabled,
            "created_at": w.created_at.isoformat() if w.created_at else None,
            "last_delivery": w.last_delivery.isoformat() if w.last_delivery else None,
            "delivery_count": w.delivery_count,
            "failure_count": w.failure_count,
            "last_status": w.last_status,
        }
        for w in result.scalars().all()
    ]


@router.post("/{webhook_id}/test", dependencies=[Depends(require_admin)])
async def test_webhook(webhook_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    from app.services.webhook_dispatcher import dispatch_one

    delivery_result = await dispatch_one(
        webhook,
        "test.ping",
        {
            "message": "Test ping from Kepryx",
            "timestamp": datetime.now(UTC).isoformat(),
        },
    )
    await db.commit()
    return delivery_result


@router.post("/{webhook_id}/rotate-secret", dependencies=[Depends(require_admin)])
async def rotate_secret(
    webhook_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    new_secret = secrets_module.token_urlsafe(32)
    new_salt = secrets_module.token_urlsafe(24)
    webhook.secret_hash = hash_password(new_secret)
    webhook.secret_prefix = new_secret[:8]
    webhook.secret_encrypted = encrypt_secret(new_secret, salt=new_salt)
    webhook.secret_salt = new_salt
    await audit(
        request,
        "webhook_secret_rotated",
        user,
        db,
        resource_type="webhook",
        resource_id=str(webhook_id),
    )
    await db.commit()
    return {"secret": new_secret, "warning": "Save this secret. It will not be shown again."}


@router.delete("/{webhook_id}", dependencies=[Depends(require_admin)])
async def delete_webhook(
    webhook_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    await db.delete(webhook)
    await audit(
        request, "webhook_deleted", user, db, resource_type="webhook", resource_id=str(webhook_id)
    )
    await db.commit()
    return {"deleted": True}
