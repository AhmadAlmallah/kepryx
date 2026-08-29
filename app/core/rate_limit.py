"""Per-user / per-IP rate limiting via Redis (H-01, M-06).

Used as FastAPI dependency:
    @router.post("/import", dependencies=[Depends(per_user_rate_limit("bulk_import", 3, 60))])
"""

import logging
from ipaddress import ip_address, ip_network

from fastapi import HTTPException, Request, status
from redis.asyncio import Redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis: Redis | None = None


def get_request_ip(request: Request) -> str:
    """Use forwarding headers only when the direct peer is a trusted proxy."""
    peer = request.client.host if request.client else "unknown"
    # Caddy sets X-Real-IP explicitly; retain X-Forwarded-For support for
    # deployments that put another trusted proxy in front of the API.
    forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
    if not forwarded or peer == "unknown":
        return peer
    try:
        trusted = any(
            ip_address(peer) in ip_network(cidr, strict=False)
            for cidr in settings.TRUSTED_PROXY_CIDRS
        )
        if not trusted:
            return peer
        candidate = forwarded.split(",", 1)[0].strip()
        return str(ip_address(candidate))
    except ValueError:
        return peer


async def _get_redis() -> Redis:
    global _redis
    if _redis is None:
        _redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


def per_user_rate_limit(key: str, limit: int, window_seconds: int):
    """Returns a FastAPI dependency that limits N requests per window per user.

    Args:
      key: identifier for this rate limit bucket (e.g. "bulk_import")
      limit: max requests in window
      window_seconds: time window length
    """

    async def dependency(request: Request):
        # Try to get authenticated user from request state
        user_id = "anonymous"
        if hasattr(request.state, "user") and request.state.user:
            user_id = str(request.state.user.id)
        else:
            # Fall back to IP
            user_id = get_request_ip(request)

        try:
            r = await _get_redis()
            bucket_key = f"ratelimit:{key}:{user_id}"
            count = await r.incr(bucket_key)
            if count == 1:
                await r.expire(bucket_key, window_seconds)
            if count > limit:
                ttl = await r.ttl(bucket_key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "rate_limit_exceeded",
                        "key": key,
                        "limit": limit,
                        "window_seconds": window_seconds,
                        "retry_after_seconds": ttl,
                    },
                    headers={"Retry-After": str(ttl)},
                )
        except HTTPException:
            raise
        except Exception as e:
            # Rate limits protect expensive and security-sensitive operations.
            # If Redis is unavailable, fail closed instead of silently removing
            # the control.
            logger.error("Rate limit service unavailable: %s", e)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "rate_limit_service_unavailable"},
            ) from e

    return dependency


def per_ip_rate_limit(key: str, limit: int, window_seconds: int):
    """Strict IP-based rate limit (M-06 fix: distributed brute-force on /login)."""

    async def dependency(request: Request):
        ip = get_request_ip(request)

        try:
            r = await _get_redis()
            bucket_key = f"ratelimit:ip:{key}:{ip}"
            count = await r.incr(bucket_key)
            if count == 1:
                await r.expire(bucket_key, window_seconds)
            if count > limit:
                ttl = await r.ttl(bucket_key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={"error": "ip_rate_limit", "retry_after": ttl},
                    headers={"Retry-After": str(ttl)},
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error("IP rate limit service unavailable")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "rate_limit_service_unavailable"},
            ) from e

    return dependency
