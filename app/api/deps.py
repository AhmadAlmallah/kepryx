"""API dependencies: JWT auth, RBAC, IP allowlist, audit."""

import logging
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api_token_auth import verify_api_token
from app.core.config import settings
from app.core.database import get_db
from app.core.pii import _hash_value, _mask_user_agent, redact_pii
from app.core.rate_limit import get_request_ip
from app.core.security import decode_token
from app.core.token_blocklist import TokenBlocklistUnavailableError, is_token_revoked
from app.models import APIToken, AuditLog, User

logger = logging.getLogger(__name__)

# These scopes can expose sensitive operational data or trigger control-plane
# actions.  They must remain inside the same management-network boundary as
# administrator JWTs, including when a scoped service token is used.
MANAGEMENT_SCOPES = frozenset(
    {
        "scans:trigger",
        "alerts:resolve",
        "audit:read",
        "integrations:read",
        "*",
    }
)


def scope_requires_management(scope: str) -> bool:
    """Return whether a service-token scope requires the management network."""
    return scope in MANAGEMENT_SCOPES


oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")
oauth2_optional = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/login",
    auto_error=False,
)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass
class APIPrincipal:
    username: str
    role: str = "service"
    id: None = None
    token_id: str | None = None


async def _jwt_user(token: str, db: AsyncSession) -> User:
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
        if await is_token_revoked(payload):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revoked")
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    except TokenBlocklistUnavailableError as e:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Authentication service unavailable",
        ) from e

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User inactive")
    return user


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    return await _jwt_user(token, db)


def require_scope(scope: str, *user_roles: str):
    """Accept either a scoped API key or a JWT user with an allowed role."""

    async def checker(
        request: Request,
        bearer: str | None = Depends(oauth2_optional),
        api_key: str | None = Depends(api_key_header),
        db: AsyncSession = Depends(get_db),
    ) -> User | APIPrincipal:
        if bearer and api_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Use one authentication method")
        if api_key:
            token: APIToken | None = await verify_api_token(api_key, db)
            if not token:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API token")
            if "*" not in token.scopes and scope not in token.scopes:
                raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing scope: {scope}")
            if "*" in token.scopes or scope_requires_management(scope):
                ensure_management_network(request)
            return APIPrincipal(
                username=f"api_token:{token.name}",
                token_id=str(token.id),
            )
        if not bearer:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
        user = await _jwt_user(bearer, db)
        if user.role not in user_roles and user.role != "admin":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        if user.role == "admin":
            ensure_management_network(request)
        return user

    return checker


def require_role(*roles: str, management_only: bool = False):
    """RBAC decorator factory with optional management-network enforcement."""

    async def checker(
        request: Request,
        user: User = Depends(get_current_user),
    ) -> User:
        if user.role not in roles and user.role != "admin":
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"Requires role: {roles}, have: {user.role}"
            )
        # An admin principal is privileged even when it reaches a route whose
        # normal role gate also permits analysts or viewers.
        if management_only or user.role == "admin":
            ensure_management_network(request)
        return user

    return checker


require_admin = require_role("admin", management_only=True)
require_analyst = require_role("admin", "analyst")
require_viewer = require_role("admin", "analyst", "viewer")
require_authenticated = get_current_user


def ensure_management_network(request: Request) -> None:
    """Fail closed unless the request client belongs to a configured CIDR."""
    client_ip = get_request_ip(request)
    try:
        address = ip_address(client_ip)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Management network access required"
        ) from exc

    try:
        allowed = any(
            address.version == network.version and address in network
            for network in (ip_network(cidr, strict=False) for cidr in settings.MANAGEMENT_CIDRS)
        )
    except ValueError as exc:
        logger.error("Invalid MANAGEMENT_CIDRS configuration")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Management network policy unavailable"
        ) from exc
    if not allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Management network access required")


async def check_ip_allowlist(request: Request, db: AsyncSession = Depends(get_db)):
    """FastAPI dependency for the configured management-network boundary."""
    del db
    ensure_management_network(request)


async def audit(
    request: Request,
    action: str,
    user: User | None,
    db: AsyncSession,
    resource_type: str | None = None,
    resource_id: str | None = None,
    severity: str = "info",
    details: dict | None = None,
):
    entry = AuditLog(
        username=user.username if user else None,
        user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=None,
        user_agent=_mask_user_agent(request.headers.get("user-agent", ""))[:512],
        severity=severity,
        details=redact_pii(
            {
                **(details or {}),
                "source_ip_hash": _hash_value(request.client.host, "audit-ip")
                if request.client
                else None,
            }
        ),
    )
    db.add(entry)
    await db.flush()
