"""Alert management endpoints."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_scope
from app.core.database import get_db
from app.models import Alert
from app.services.webhook_dispatcher import fire_event_sync

router = APIRouter()


@router.get("", dependencies=[Depends(require_scope("alerts:read", "viewer", "analyst"))])
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    alert_type: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    q = select(Alert)
    if status_filter:
        q = q.where(Alert.status == status_filter)
    if severity:
        q = q.where(Alert.severity == severity)
    if alert_type:
        q = q.where(Alert.alert_type == alert_type)
    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    q = q.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    items = [
        {
            "id": str(a.id),
            "type": a.alert_type,
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "asset_id": str(a.asset_id) if a.asset_id else None,
            "details": a.details,
            "status": a.status,
            "notified": a.notified,
            "channels": a.notification_channels,
            "created_at": a.created_at.isoformat(),
            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        }
        for a in result.scalars().all()
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.patch("/{alert_id:uuid}/resolve")
async def resolve_alert(
    alert_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("alerts:resolve", "analyst")),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    alert.status = "resolved"
    alert.resolved_at = datetime.now(UTC)
    alert.resolved_by = user.username
    await audit(
        request, "alert_resolved", user, db, resource_type="alert", resource_id=str(alert_id)
    )
    await db.commit()
    # Schedule delivery after the state change is committed. The dispatcher
    # performs its own DNS/SSRF checks and does not block this API response.
    fire_event_sync(
        "alert.resolved",
        alert.severity,
        {
            "id": str(alert.id),
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "asset_id": str(alert.asset_id) if alert.asset_id else None,
            "details": alert.details,
            "resolved_by": user.username,
        },
    )
    return {"ok": True}
