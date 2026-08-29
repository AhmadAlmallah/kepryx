"""Integration management — register/test connectors."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_admin, require_scope
from app.connectors import get_connector, list_connectors
from app.core.connector_secrets import (
    protect_connector_config,
    resolve_connector_config,
    validate_schedule,
)
from app.core.database import get_db
from app.models import Integration

router = APIRouter()


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=3, max_length=64)
    connector_type: str
    config: dict
    schedule_cron: str = "0 */6 * * *"
    priority: int = Field(default=5, ge=1, le=10)


class IntegrationUpdate(BaseModel):
    config: dict | None = None
    schedule_cron: str | None = None
    priority: int | None = Field(default=None, ge=1, le=10)
    enabled: bool | None = None


@router.get("/types", dependencies=[Depends(require_scope("integrations:read", "admin"))])
async def types():
    return {"connectors": list_connectors()}


@router.get("", dependencies=[Depends(require_scope("integrations:read", "admin"))])
async def list_integrations(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Integration))
    return {
        "items": [
            {
                "id": str(i.id),
                "name": i.name,
                "connector_type": i.connector_type,
                "enabled": i.enabled,
                "priority": i.priority,
                "schedule_cron": i.schedule_cron,
                "last_run": i.last_run.isoformat() if i.last_run else None,
                "last_status": i.last_status,
                "assets_reported": i.assets_reported,
            }
            for i in result.scalars().all()
        ]
    }


@router.post("", status_code=201)
async def create_integration(
    body: IntegrationCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    if not get_connector(body.connector_type):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Unknown connector: {body.connector_type}"
        )
    existing = await db.scalar(select(Integration.id).where(Integration.name == body.name))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Integration name already exists")
    try:
        encrypted_config = protect_connector_config(body.connector_type, body.config)
        schedule = validate_schedule(body.schedule_cron)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    integ = Integration(
        name=body.name,
        connector_type=body.connector_type,
        config=encrypted_config,
        schedule_cron=schedule,
        priority=body.priority,
    )
    db.add(integ)
    await audit(
        request,
        "integration_created",
        user,
        db,
        resource_type="integration",
        details={"name": body.name},
    )
    await db.commit()
    return {"id": str(integ.id)}


@router.patch("/{integration_id}")
async def update_integration(
    integration_id: UUID,
    body: IntegrationUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    integration = await db.scalar(select(Integration).where(Integration.id == integration_id))
    if not integration:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    try:
        if body.config is not None:
            integration.config = protect_connector_config(integration.connector_type, body.config)
        if body.schedule_cron is not None:
            integration.schedule_cron = validate_schedule(body.schedule_cron)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if body.priority is not None:
        integration.priority = body.priority
    if body.enabled is not None:
        integration.enabled = body.enabled
    await audit(
        request,
        "integration_updated",
        user,
        db,
        resource_type="integration",
        resource_id=str(integration_id),
        details={"fields": sorted(body.model_fields_set)},
    )
    await db.commit()
    return {"updated": True}


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integ = result.scalar_one_or_none()
    if not integ:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    connector_class = get_connector(integ.connector_type)
    try:
        connector = connector_class(resolve_connector_config(integ.connector_type, integ.config))
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    ok = await connector.test_connection()
    await audit(
        request,
        "integration_tested",
        user,
        db,
        resource_type="integration",
        resource_id=str(integration_id),
        details={"success": ok},
    )
    await db.commit()
    return {"connected": ok}


@router.post("/{integration_id}/run")
async def run_integration_now(
    integration_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Trigger an immediate sync."""
    from app.workers.reconcile_tasks import sync_all_integrations

    sync_all_integrations.delay(str(integration_id))
    await audit(request, "integration_manual_run", user, db, resource_id=str(integration_id))
    await db.commit()
    return {"queued": True}
