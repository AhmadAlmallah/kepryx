"""Verification for scoped service API tokens."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_password
from app.models import APIToken


async def verify_api_token(token: str, db: AsyncSession) -> APIToken | None:
    if not token or not token.startswith("kpx_"):
        return None
    result = await db.execute(
        select(APIToken).where(
            APIToken.token_prefix == token[:12],
            APIToken.revoked.is_(False),
        )
    )
    now = datetime.now(UTC)
    for candidate in result.scalars().all():
        if candidate.expires_at and candidate.expires_at < now:
            continue
        if verify_password(token, candidate.token_hash):
            candidate.last_used = now
            candidate.usage_count += 1
            return candidate
    return None
