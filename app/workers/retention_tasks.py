"""Data retention enforcement (P-01 fix).

Scheduled tasks that enforce retention policies:
  - Audit logs: mark for archive after 365 days; deletion is operator-enabled
  - Inactive assets: delete only when explicitly enabled (except tier-1/critical)
  - Inactive users (no login 365+ days): flag for review

Run daily at 03:00 UTC via Celery beat.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, select, update

from app.core.config import settings
from app.core.database import SessionLocal
from app.workers._async_runner import run_async
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


# Retention policy is environment-driven and deletion is disabled by default.
AUDIT_LOG_RETENTION_DAYS = settings.AUDIT_LOG_RETENTION_DAYS
AUDIT_LOG_ARCHIVE_DAYS = settings.AUDIT_LOG_ARCHIVE_DAYS
INACTIVE_ASSET_DAYS = settings.INACTIVE_ASSET_DAYS
INACTIVE_USER_FLAG_DAYS = settings.INACTIVE_USER_FLAG_DAYS


@celery_app.task(name="app.workers.retention_tasks.enforce_all_retention")
def enforce_all_retention():
    """Run all retention enforcement passes. Schedule daily."""
    return run_async(_enforce_all())


async def _enforce_all():
    results = {}
    results["audit_archived"] = await _archive_old_audit_logs()
    results["audit_deleted"] = await _delete_expired_audit_logs()
    results["assets_deleted"] = await _delete_stale_assets()
    results["users_flagged"] = await _flag_inactive_users()
    logger.info(f"Retention enforcement complete: {results}")
    return results


async def _archive_old_audit_logs() -> int:
    """Mark old audit rows for an operator-managed archival/export process."""
    from app.models import AuditLog

    cutoff = datetime.now(UTC) - timedelta(days=AUDIT_LOG_ARCHIVE_DAYS)
    async with SessionLocal() as db:
        # Count for logging
        result = await db.execute(
            select(AuditLog)
            .where(and_(AuditLog.timestamp < cutoff, AuditLog.archived.is_(False)))
            .limit(10000)
        )
        old_logs = result.scalars().all()
        if not old_logs:
            return 0

        # Mark as archived (a real implementation copies to cold storage first)
        ids = [a.id for a in old_logs]
        await db.execute(update(AuditLog).where(AuditLog.id.in_(ids)).values(archived=True))
        await db.commit()
        logger.info(
            f"Archived {len(old_logs)} audit log entries older than {AUDIT_LOG_ARCHIVE_DAYS}d"
        )
        return len(old_logs)


async def _delete_expired_audit_logs() -> int:
    """Permanently delete audit logs past full retention period."""
    if not settings.RETENTION_DELETE_ENABLED:
        return 0

    from app.models import AuditLog

    cutoff = datetime.now(UTC) - timedelta(days=AUDIT_LOG_RETENTION_DAYS)
    async with SessionLocal() as db:
        result = await db.execute(delete(AuditLog).where(AuditLog.timestamp < cutoff))
        await db.commit()
        if result.rowcount:
            logger.warning(
                f"Permanently deleted {result.rowcount} audit log entries past {AUDIT_LOG_RETENTION_DAYS}d retention"
            )
        return result.rowcount


async def _delete_stale_assets() -> int:
    """Delete assets not seen in INACTIVE_ASSET_DAYS, except tier-1 / critical."""
    if not settings.RETENTION_DELETE_ENABLED:
        return 0

    from app.models import Asset

    cutoff = datetime.now(UTC) - timedelta(days=INACTIVE_ASSET_DAYS)
    async with SessionLocal() as db:
        # Build query: stale AND not tier-1/critical
        result = await db.execute(
            delete(Asset).where(
                and_(
                    Asset.last_seen < cutoff,
                    Asset.criticality.notin_(["tier-1", "critical"]),
                )
            )
        )
        await db.commit()
        if result.rowcount:
            logger.info(
                f"Deleted {result.rowcount} stale assets (last seen >{INACTIVE_ASSET_DAYS}d ago)"
            )
        return result.rowcount


async def _flag_inactive_users() -> int:
    """Flag users who haven't logged in for INACTIVE_USER_FLAG_DAYS."""
    from app.models import Alert, User

    cutoff = datetime.now(UTC) - timedelta(days=INACTIVE_USER_FLAG_DAYS)
    async with SessionLocal() as db:
        result = await db.execute(
            select(User).where(
                and_(
                    User.is_active.is_(True),
                    User.last_login < cutoff,
                    User.username.notlike("deleted_user_%"),
                )
            )
        )
        inactive = result.scalars().all()
        for user in inactive:
            # Check if we already have an open alert for this user
            existing = await db.execute(
                select(Alert).where(
                    and_(
                        Alert.alert_type == "inactive_user",
                        Alert.status == "open",
                        Alert.details["user_id"].astext == str(user.id),
                    )
                )
            )
            if existing.scalar_one_or_none():
                continue

            db.add(
                Alert(
                    alert_type="inactive_user",
                    severity="medium",
                    title=f"Inactive user account: {user.username}",
                    description=(
                        f"User {user.username} has not logged in for "
                        f">{INACTIVE_USER_FLAG_DAYS} days. Consider disabling per "
                        f"NIST 800-53 AC-2 (Account Management)."
                    ),
                    details={
                        "user_id": str(user.id),
                        "username": user.username,
                        "last_login": user.last_login.isoformat() if user.last_login else None,
                    },
                )
            )
        await db.commit()
        if inactive:
            logger.info(f"Flagged {len(inactive)} inactive users for admin review")
        return len(inactive)
