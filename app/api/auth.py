"""Auth endpoints — login, refresh, MFA, password change."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import per_ip_rate_limit
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_mfa_secret,
    hash_password,
    mfa_provisioning_uri,
    mfa_secret_is_protected,
    protect_mfa_secret,
    verify_mfa,
    verify_password,
)
from app.core.token_blocklist import (
    TokenBlocklistUnavailableError,
    consume_refresh_token,
    revoke_user_tokens,
)
from app.models import User

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a credential
    expires_in: int


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class MFAEnrollRequest(BaseModel):
    current_password: str = Field(min_length=1)


class MFAConfirmRequest(BaseModel):
    current_password: str = Field(min_length=1)
    code: str = Field(pattern=r"^\d{6}$")


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(per_ip_rate_limit("login", 10, 60))],
)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    # Constant-time check to mitigate enum
    if not user:
        # Still hash to keep timing comparable
        hash_password("dummy")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if user.locked_until and user.locked_until > datetime.now(UTC):
        mins = int((user.locked_until - datetime.now(UTC)).total_seconds() / 60)
        await audit(request, "login_blocked_lockout", user, db, severity="warning")
        await db.commit()
        raise HTTPException(status.HTTP_423_LOCKED, f"Account locked for {mins}m")

    if not verify_password(body.password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now(UTC) + timedelta(minutes=settings.LOCKOUT_DURATION_MIN)
            await audit(
                request,
                "account_locked",
                user,
                db,
                severity="critical",
                details={"attempts": user.failed_attempts},
            )
        else:
            await audit(
                request,
                "login_failed",
                user,
                db,
                severity="warning",
                details={"attempts": user.failed_attempts},
            )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if user.mfa_enabled:
        if not body.mfa_code or not verify_mfa(user.mfa_secret, body.mfa_code):
            user.failed_attempts += 1
            if user.failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.now(UTC) + timedelta(
                    minutes=settings.LOCKOUT_DURATION_MIN
                )
            await audit(request, "mfa_failed", user, db, severity="warning")
            await db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA required or invalid")
        if not mfa_secret_is_protected(user.mfa_secret):
            user.mfa_secret = protect_mfa_secret(user.mfa_secret)

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(UTC)
    await audit(request, "login_success", user, db)

    access = create_access_token(str(user.id), scopes=[user.role])
    refresh = create_refresh_token(str(user.id))
    await db.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.JWT_ACCESS_TTL_MIN * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")
        if not await consume_refresh_token(payload):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token revoked or reused")
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    except TokenBlocklistUnavailableError as e:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Authentication service unavailable",
        ) from e

    result = await db.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User inactive")

    return TokenResponse(
        access_token=create_access_token(str(user.id), scopes=[user.role]),
        refresh_token=create_refresh_token(str(user.id)),
        expires_in=settings.JWT_ACCESS_TTL_MIN * 60,
    )


@router.post("/mfa/enroll")
async def mfa_enroll(
    body: MFAEnrollRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA already enabled")
    if not verify_password(body.current_password, user.password_hash):
        await audit(request, "mfa_enroll_failed", user, db, severity="warning")
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    secret = generate_mfa_secret()
    user.mfa_secret = protect_mfa_secret(secret)
    await audit(request, "mfa_enrolled", user, db)
    await db.commit()
    return {
        "secret": secret,
        "provisioning_uri": mfa_provisioning_uri(secret, user.username),
    }


@router.post("/mfa/confirm")
async def mfa_confirm(
    body: MFAConfirmRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Run mfa/enroll first")
    if not verify_password(body.current_password, user.password_hash):
        await audit(request, "mfa_confirm_failed", user, db, severity="warning")
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    if not verify_mfa(user.mfa_secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA code")
    user.mfa_enabled = True
    await audit(request, "mfa_confirmed", user, db)
    await db.commit()
    return {"mfa_enabled": True}


@router.post("/password")
async def change_password(
    body: PasswordChange,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password wrong")
    from app.core.password_policy import PasswordPolicyError, validate_password

    try:
        validate_password(body.new_password, user.username)
    except PasswordPolicyError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    user.password_hash = hash_password(body.new_password)
    try:
        await revoke_user_tokens(str(user.id))
    except TokenBlocklistUnavailableError as e:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Could not revoke active sessions; password was not changed",
        ) from e
    await audit(request, "password_changed", user, db)
    await db.commit()
    return {"ok": True}


@router.get("/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "last_login": user.last_login,
    }
