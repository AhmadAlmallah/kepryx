"""Admin: user management, audit log access, system status."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_admin
from app.core.config import settings
from app.core.database import get_db
from app.core.security import hash_password
from app.models import AuditLog, User

router = APIRouter()


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "viewer"


@router.get("/users", dependencies=[Depends(require_admin)])
async def list_users(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User))
    return [
        {
            "id": str(u.id),
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "mfa_enabled": u.mfa_enabled,
            "is_active": u.is_active,
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "locked_until": u.locked_until.isoformat() if u.locked_until else None,
        }
        for u in result.scalars().all()
    ]


@router.post("/users", status_code=201)
async def create_user(
    body: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    from app.core.password_policy import PasswordPolicyError, validate_password

    try:
        validate_password(body.password, body.username)
    except PasswordPolicyError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid role")

    new_user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(new_user)
    await audit(
        request,
        "user_created",
        user,
        db,
        resource_type="user",
        details={"username": body.username, "role": body.role},
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "User already exists") from exc
    return {"id": str(new_user.id)}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: UUID, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)
):
    if str(user.id) == str(user_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot delete self")
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    target.is_active = False
    await audit(
        request, "user_deactivated", user, db, resource_type="user", resource_id=str(user_id)
    )
    await db.commit()
    return {"ok": True}


@router.get("/audit", dependencies=[Depends(require_admin)])
async def audit_log(
    db: AsyncSession = Depends(get_db),
    limit: int = 200,
    severity: str | None = None,
    action: str | None = None,
):
    q = select(AuditLog)
    if severity:
        q = q.where(AuditLog.severity == severity)
    if action:
        q = q.where(AuditLog.action == action)
    q = q.order_by(AuditLog.timestamp.desc()).limit(limit)
    result = await db.execute(q)
    return [
        {
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "username": a.username,
            "action": a.action,
            "resource_type": a.resource_type,
            "resource_id": a.resource_id,
            "ip_address": str(a.ip_address) if a.ip_address else None,
            "severity": a.severity,
            "details": a.details,
        }
        for a in result.scalars().all()
    ]


@router.get("/system/status", dependencies=[Depends(require_admin)])
async def system_status(db: AsyncSession = Depends(get_db)):
    from app.models import Alert, Asset, Integration, Scan

    return {
        "environment": settings.ENVIRONMENT,
        "version": "0.9.0",
        "stats": {
            "assets": await db.scalar(select(func.count(Asset.id))),
            "open_alerts": await db.scalar(
                select(func.count(Alert.id)).where(Alert.status == "open")
            ),
            "integrations_enabled": await db.scalar(
                select(func.count(Integration.id)).where(Integration.enabled.is_(True))
            ),
            "scans_24h": await db.scalar(select(func.count(Scan.id))),
            "users_active": await db.scalar(
                select(func.count(User.id)).where(User.is_active.is_(True))
            ),
        },
        "security": {
            "session_timeout_min": settings.SESSION_TIMEOUT_MIN,
            "max_login_attempts": settings.MAX_LOGIN_ATTEMPTS,
            "lockout_duration_min": settings.LOCKOUT_DURATION_MIN,
            "jwt_access_ttl_min": settings.JWT_ACCESS_TTL_MIN,
            "password_min_len": settings.PASSWORD_MIN_LEN,
        },
    }
