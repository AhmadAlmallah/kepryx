"""Redis-backed JWT revocation and refresh-token replay protection."""

import logging
import time
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)
_redis: Redis | None = None


class TokenBlocklistUnavailableError(RuntimeError):
    """Raised when token revocation state cannot be verified safely."""


def _client() -> Redis:
    global _redis
    if _redis is None:
        _redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


async def redis_ready() -> bool:
    """Return dependency health without leaking connection details."""
    try:
        return bool(await _client().ping())
    except (RedisError, OSError):
        return False


async def close_token_store() -> None:
    """Release the process-local Redis connection pool during shutdown."""
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None


def _ttl(payload: dict[str, Any]) -> int:
    try:
        return max(1, int(payload["exp"]) - int(time.time()))
    except (KeyError, TypeError, ValueError):
        return 1


def _issued_at_ms(payload: dict[str, Any]) -> int:
    try:
        return int(payload.get("iat_ms") or (float(payload["iat"]) * 1000))
    except (KeyError, TypeError, ValueError):
        return 0


async def is_token_revoked(payload: dict[str, Any]) -> bool:
    """Check JTI and user-wide revocation state. Redis failure is fail-closed."""
    jti = payload.get("jti")
    subject = payload.get("sub")
    if not jti or not subject:
        return True
    try:
        redis = _client()
        revoked_jti, revoked_after = await redis.mget(
            f"token:revoked:{jti}",
            f"token:revoked_after:{subject}",
        )
        if revoked_jti:
            return True
        if revoked_after and _issued_at_ms(payload) <= int(revoked_after):
            return True
        return False
    except (RedisError, OSError, ValueError) as exc:
        logger.error("Token revocation state unavailable")
        raise TokenBlocklistUnavailableError from exc


async def revoke_token(payload: dict[str, Any]) -> None:
    jti = payload.get("jti")
    if not jti:
        return
    try:
        await _client().setex(f"token:revoked:{jti}", _ttl(payload), "1")
    except (RedisError, OSError) as exc:
        logger.error("Failed to revoke token")
        raise TokenBlocklistUnavailableError from exc


async def consume_refresh_token(payload: dict[str, Any]) -> bool:
    """Atomically mark a refresh JTI used; False means replay or revocation."""
    if await is_token_revoked(payload):
        return False
    jti = payload.get("jti")
    if not jti:
        return False
    try:
        consumed = await _client().set(
            f"token:revoked:{jti}",
            "refresh_consumed",
            ex=_ttl(payload),
            nx=True,
        )
        return bool(consumed)
    except (RedisError, OSError) as exc:
        logger.error("Failed to consume refresh token")
        raise TokenBlocklistUnavailableError from exc


async def revoke_user_tokens(user_id: str) -> None:
    """Invalidate every token issued to a user before this instant."""
    retention = settings.JWT_REFRESH_TTL_DAYS * 24 * 60 * 60 + 60
    try:
        await _client().setex(
            f"token:revoked_after:{user_id}",
            retention,
            str(time.time_ns() // 1_000_000),
        )
    except (RedisError, OSError) as exc:
        logger.error("Failed to revoke user sessions")
        raise TokenBlocklistUnavailableError from exc
