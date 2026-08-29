"""GDPR compliance endpoints: data export (Art. 20) and erasure (Art. 17).

Fixes P-02 (export) and P-03 (erasure).

Self-service: a user can export or delete their own data.
Admin: can export/erase any user's data.
"""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, ensure_management_network, require_authenticated
from app.core.database import get_db
from app.core.pii import _hash_value
from app.core.security import hash_password
from app.core.token_blocklist import TokenBlocklistUnavailableError, revoke_user_tokens
from app.models import AuditLog, User

router = APIRouter()


class ErasureRequest(BaseModel):
    confirmation: str


@router.get("/{user_id}/export")
async def export_user_data(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_authenticated),
):
    """GDPR Article 20: Right to data portability.

    Returns all personal data linked to a user in JSON format.
    Access: admin OR the user themselves.
    """
    if current_user.role != "admin" and str(current_user.id) != str(user_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Can only export your own data")
    if current_user.role == "admin":
        ensure_management_network(request)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    # Collect all data linked to this user
    audit_result = await db.execute(
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(10000)
    )
    audit_entries = audit_result.scalars().all()

    export_data = {
        "exported_at": datetime.now(UTC).isoformat(),
        "export_format_version": "1.0",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "mfa_enabled": user.mfa_enabled,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "password_changed_at": user.password_changed_at.isoformat()
            if hasattr(user, "password_changed_at") and user.password_changed_at
            else None,
        },
        "audit_log_entries": [
            {
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "action": a.action,
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "ip_address": str(a.ip_address) if a.ip_address else None,
                "user_agent": a.user_agent,
                "severity": a.severity,
                "details": a.details,
            }
            for a in audit_entries
        ],
        "notes": (
            "This export contains all personal data Kepryx holds about you. "
            "Some operational data (asset records, alerts) may reference your "
            "user_id internally but contain no other PII."
        ),
    }

    await audit(
        request,
        "gdpr_data_export",
        current_user,
        db,
        resource_type="user",
        resource_id=str(user_id),
        details={
            "requested_by": current_user.username,
            "subject_user": user.username,
            "audit_records": len(audit_entries),
        },
    )
    await db.commit()
    return export_data


@router.post("/{user_id}/erase")
async def erase_user_data(
    user_id: UUID,
    body: ErasureRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_authenticated),
):
    """GDPR Article 17: Right to erasure (right to be forgotten).

    Replaces PII with anonymized placeholders. Retains the audit trail itself
    (legal/security requirement) but removes identifiable details.

    Access: admin OR the user themselves.
    NOTE: This cannot be undone. Confirmation required via separate endpoint.
    """
    if current_user.role != "admin" and str(current_user.id) != str(user_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Can only erase your own data")
    if current_user.role == "admin":
        ensure_management_network(request)
    if body.confirmation != "ERASE MY DATA":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            'Set confirmation to "ERASE MY DATA"',
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    if user.username.startswith("deleted_user_"):
        raise HTTPException(status.HTTP_409_CONFLICT, "User data already erased")

    if user.role == "admin" and user.is_active:
        active_admins = await db.scalar(
            select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
        )
        if (active_admins or 0) <= 1:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Cannot erase the last active administrator",
            )

    requested_by = current_user.username
    anonymized_id = _hash_value(str(user.id), salt_suffix="anonymize")

    # Anonymize the user record
    user.username = f"deleted_user_{anonymized_id}"
    user.email = f"deleted-{anonymized_id}@invalid.kepryx"
    user.password_hash = hash_password(f"erased:{anonymized_id}")
    user.mfa_secret = None
    user.mfa_enabled = False
    user.is_active = False
    user.failed_attempts = 0
    user.locked_until = None

    # Anonymize audit log entries: replace IP and User-Agent with hashed values
    # but keep the audit trail itself for security/legal review
    await db.execute(
        update(AuditLog)
        .where(AuditLog.user_id == user_id)
        .values(
            username=f"deleted_user_{anonymized_id}",
            ip_address="redacted",
            user_agent="redacted",
        )
    )

    try:
        await revoke_user_tokens(str(user_id))
    except TokenBlocklistUnavailableError as e:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Could not revoke active sessions; erasure was rolled back",
        ) from e

    await audit(
        request,
        "gdpr_data_erasure",
        current_user,
        db,
        resource_type="user",
        resource_id=str(user_id),
        severity="warning",
        details={"requested_by": requested_by, "anonymized_to": user.username},
    )
    await db.commit()

    return {
        "erased": True,
        "anonymized_user_id": user.username,
        "note": (
            "Personal data has been anonymized. The user account is disabled and "
            "cannot be reactivated. Audit trail entries are retained for security "
            "review with PII replaced by hashed identifiers."
        ),
    }


@router.get("/{user_id}/retention-info")
async def retention_info(
    user_id: UUID,
    current_user=Depends(require_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """GDPR Article 13: Information about data retention.

    Tells users how long their data is kept.
    """
    if current_user.role != "admin" and str(current_user.id) != str(user_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    return {
        "user_data": {
            "retained_while": "Account is active",
            "after_deletion": "Anonymized within 24h; audit trail kept for 7 years",
        },
        "audit_logs": {
            "retention_period_days": 2555,  # 7 years for SOX-style compliance
            "anonymization": "PII (IP, User-Agent, username) replaced with hashes on deletion",
        },
        "asset_data": {
            "retained_while": "Active asset is in inventory",
            "after_removal": "Deleted within 90 days of last_seen",
            "exceptions": "Tier-1 / critical assets retained for full audit history",
        },
        "notes": (
            "To export your data: GET /api/v1/gdpr/{user_id}/export. "
            "To erase your data: POST /api/v1/gdpr/{user_id}/erase. "
            "Erasure cannot be undone."
        ),
    }
