"""API tokens for service-to-service authentication.

Use cases:
  - SOAR sending data into Kepryx (e.g., enriched alerts from XSOAR)
  - Backup scripts pulling asset CSVs
  - CI pipelines triggering compliance audits
  - SIEM pushing context data

Tokens are stored as Argon2id hashes. Plaintext shown ONCE at creation.
Tokens can be scoped to specific endpoints and have expiry dates.
"""

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_admin
from app.core.database import get_db
from app.core.security import hash_password
from app.models import APIToken

router = APIRouter()


# ─── Pydantic ───
class TokenCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=128)
    scopes: list[str] = Field(default_factory=list)
    expires_in_days: int | None = Field(default=90, ge=1, le=3650)


class TokenResponse(BaseModel):
    id: str
    name: str
    token_prefix: str
    scopes: list[str]
    created_by: str
    created_at: str
    expires_at: str | None
    last_used: str | None
    revoked: bool
    usage_count: int


ALLOWED_SCOPES = {
    "assets:read",
    "assets:write",
    "alerts:read",
    "alerts:resolve",
    "scans:trigger",
    "scans:read",
    "compliance:read",
    "integrations:read",
    "self_security:read",
    "audit:read",
    "exports:read",
    "*",  # admin-only - full access
}


@router.post("", dependencies=[Depends(require_admin)])
async def create_token(
    body: TokenCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Create a new API token. Plaintext shown ONCE in response."""
    invalid = set(body.scopes) - ALLOWED_SCOPES
    if invalid:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Invalid scopes: {sorted(invalid)}. Allowed: {sorted(ALLOWED_SCOPES)}",
        )
    plaintext = "kpx_" + secrets.token_urlsafe(32)
    prefix = plaintext[:12]
    token_hash = hash_password(plaintext)
    expires = None
    if body.expires_in_days:
        expires = datetime.now(UTC) + timedelta(days=body.expires_in_days)
    token = APIToken(
        name=body.name,
        token_hash=token_hash,
        token_prefix=prefix,
        scopes=body.scopes,
        created_by=user.username,
        expires_at=expires,
    )
    db.add(token)
    await audit(
        request,
        "api_token_created",
        user,
        db,
        resource_type="api_token",
        resource_id=str(token.id),
        details={"name": body.name, "scopes": body.scopes},
    )
    await db.commit()
    return {
        "id": str(token.id),
        "name": token.name,
        "token": plaintext,
        "token_prefix": prefix,
        "scopes": body.scopes,
        "expires_at": expires.isoformat() if expires else None,
        "warning": "Store this token securely. It will not be shown again.",
    }


@router.get("", dependencies=[Depends(require_admin)])
async def list_tokens(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(APIToken).order_by(APIToken.created_at.desc()))
    tokens = result.scalars().all()
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "token_prefix": t.token_prefix,
            "scopes": t.scopes,
            "created_by": t.created_by,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "expires_at": t.expires_at.isoformat() if t.expires_at else None,
            "last_used": t.last_used.isoformat() if t.last_used else None,
            "revoked": t.revoked,
            "usage_count": t.usage_count,
        }
        for t in tokens
    ]


@router.post("/{token_id}/revoke", dependencies=[Depends(require_admin)])
async def revoke_token(
    token_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    result = await db.execute(select(APIToken).where(APIToken.id == token_id))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    token.revoked = True
    await audit(
        request, "api_token_revoked", user, db, resource_type="api_token", resource_id=str(token_id)
    )
    await db.commit()
    return {"revoked": True}
