"""Software inventory and software-composition analysis endpoints."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_scope
from app.core.database import get_db
from app.core.rate_limit import per_user_rate_limit
from app.models import Asset
from app.models.software import (
    SoftwareComponent,
    SoftwareFinding,
    SoftwareScanRun,
    SoftwareSolution,
)
from app.services.software_inventory import MAX_ROWS, MAX_UPLOAD_BYTES, parse_software_inventory

router = APIRouter()


class SoftwareFindingUpdate(BaseModel):
    status: Literal["open", "acknowledged", "mitigated", "accepted", "resolved"]
    resolution_note: str | None = Field(default=None, max_length=2000)


def _iso(value):
    return value.isoformat() if value else None


def _environment_for_records(records) -> str:
    environments = {record.environment for record in records if record.environment}
    if len(environments) == 1:
        return next(iter(environments))
    return "mixed" if environments else "production"


async def _refresh_solution_counts(db: AsyncSession, solution_id: UUID) -> None:
    solution = await db.get(SoftwareSolution, solution_id)
    if not solution:
        return
    components_result = await db.execute(
        select(SoftwareComponent).where(SoftwareComponent.solution_id == solution_id)
    )
    components = components_result.scalars().all()
    solution.component_count = len(components)
    solution.vulnerable_component_count = sum(item.status == "vulnerable" for item in components)
    solution.finding_count = (
        await db.scalar(
            select(func.count(SoftwareFinding.id))
            .join(SoftwareComponent, SoftwareComponent.id == SoftwareFinding.component_id)
            .where(
                SoftwareComponent.solution_id == solution_id,
                SoftwareFinding.status == "open",
            )
        )
        or 0
    )


def _solution_json(item: SoftwareSolution) -> dict:
    return {
        "id": str(item.id),
        "name": item.name,
        "description": item.description,
        "environment": item.environment,
        "source": item.source,
        "status": item.last_scan_status,
        "last_scan_error": item.last_scan_error,
        "last_scan_at": _iso(item.last_scan_at),
        "last_successful_scan_at": _iso(item.last_successful_scan_at),
        "component_count": item.component_count,
        "vulnerable_component_count": item.vulnerable_component_count,
        "finding_count": item.finding_count,
        "created_at": _iso(item.created_at),
        "updated_at": _iso(item.updated_at),
    }


def _component_json(
    item: SoftwareComponent, solution_name: str | None = None, asset_name: str | None = None
) -> dict:
    return {
        "id": str(item.id),
        "solution_id": str(item.solution_id),
        "solution": solution_name,
        "asset_id": str(item.asset_id) if item.asset_id else None,
        "asset": asset_name,
        "ecosystem": item.ecosystem,
        "package": item.package_name,
        "version": item.version,
        "latest_version": item.latest_version,
        "component_type": item.component_type,
        "purl": item.purl,
        "cpe": item.cpe,
        "direct": item.direct,
        "environment": item.environment,
        "source": item.source,
        "status": item.status,
        "scan_error": item.scan_error,
        "last_seen": _iso(item.last_seen),
        "last_checked": _iso(item.last_checked),
        "cve_count": item.cve_count,
        "kev_count": item.kev_count,
        "max_cvss": item.max_cvss,
        "update_available": item.update_available,
    }


def _finding_json(
    item: SoftwareFinding,
    component: SoftwareComponent | None = None,
    solution_name: str | None = None,
) -> dict:
    return {
        "id": str(item.id),
        "component_id": str(item.component_id),
        "solution_id": str(component.solution_id) if component else None,
        "solution": solution_name,
        "package": component.package_name if component else None,
        "version": component.version if component else None,
        "ecosystem": component.ecosystem if component else None,
        "advisory_id": item.advisory_id,
        "cve_id": item.cve_id,
        "source": item.source,
        "cvss": item.cvss,
        "epss": item.epss,
        "kev": item.kev,
        "severity": item.severity,
        "summary": item.summary,
        "fixed_version": item.fixed_version,
        "status": item.status,
        "resolution_note": item.resolution_note,
        "resolved_at": _iso(item.resolved_at),
        "resolved_by": item.resolved_by,
        "first_seen": _iso(item.first_seen),
        "last_seen": _iso(item.last_seen),
        "details": item.details or {},
    }


@router.get("/summary", dependencies=[Depends(require_scope("software:read", "viewer", "analyst"))])
async def summary(db: AsyncSession = Depends(get_db)):
    total_solutions = await db.scalar(select(func.count(SoftwareSolution.id))) or 0
    total_components = await db.scalar(select(func.count(SoftwareComponent.id))) or 0
    vulnerable_components = (
        await db.scalar(
            select(func.count(SoftwareComponent.id)).where(SoftwareComponent.status == "vulnerable")
        )
        or 0
    )
    open_findings = (
        await db.scalar(
            select(func.count(SoftwareFinding.id)).where(SoftwareFinding.status == "open")
        )
        or 0
    )
    kev_findings = (
        await db.scalar(
            select(func.count(SoftwareFinding.id)).where(
                SoftwareFinding.status == "open", SoftwareFinding.kev.is_(True)
            )
        )
        or 0
    )
    scan_errors = (
        await db.scalar(
            select(func.count(SoftwareComponent.id)).where(
                SoftwareComponent.scan_error.is_not(None)
            )
        )
        or 0
    )
    latest = await db.scalar(
        select(SoftwareScanRun).order_by(SoftwareScanRun.created_at.desc()).limit(1)
    )
    return {
        "solutions": total_solutions,
        "components": total_components,
        "vulnerable_components": vulnerable_components,
        "open_findings": open_findings,
        "kev_findings": kev_findings,
        "scan_errors": scan_errors,
        "last_scan": {
            "id": str(latest.id),
            "status": latest.status,
            "mode": latest.mode,
            "completed_at": _iso(latest.completed_at),
            "findings_count": latest.findings_count,
        }
        if latest
        else None,
    }


@router.get(
    "/solutions", dependencies=[Depends(require_scope("software:read", "viewer", "analyst"))]
)
async def list_solutions(
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(SoftwareSolution.id))) or 0
    result = await db.execute(
        select(SoftwareSolution).order_by(SoftwareSolution.name).offset(offset).limit(limit)
    )
    return {
        "items": [_solution_json(item) for item in result.scalars().all()],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get(
    "/solutions/{solution_id}",
    dependencies=[Depends(require_scope("software:read", "viewer", "analyst"))],
)
async def get_solution(solution_id: UUID, db: AsyncSession = Depends(get_db)):
    solution = await db.get(SoftwareSolution, solution_id)
    if not solution:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Software solution not found")
    components_result = await db.execute(
        select(SoftwareComponent, Asset.name)
        .outerjoin(Asset, Asset.id == SoftwareComponent.asset_id)
        .where(SoftwareComponent.solution_id == solution_id)
        .order_by(SoftwareComponent.package_name)
    )
    findings_result = await db.execute(
        select(SoftwareFinding, SoftwareComponent)
        .join(SoftwareComponent, SoftwareComponent.id == SoftwareFinding.component_id)
        .where(SoftwareComponent.solution_id == solution_id, SoftwareFinding.status == "open")
        .order_by(SoftwareFinding.kev.desc(), SoftwareFinding.severity.desc())
    )
    return {
        **_solution_json(solution),
        "components": [
            _component_json(item, solution.name, asset_name)
            for item, asset_name in components_result.all()
        ],
        "findings": [
            _finding_json(item, component, solution.name)
            for item, component in findings_result.all()
        ],
    }


@router.get(
    "/components", dependencies=[Depends(require_scope("software:read", "viewer", "analyst"))]
)
async def list_components(
    solution_id: UUID | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = None,
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(SoftwareComponent, SoftwareSolution.name, Asset.name)
        .join(SoftwareSolution, SoftwareSolution.id == SoftwareComponent.solution_id)
        .outerjoin(Asset, Asset.id == SoftwareComponent.asset_id)
    )
    if solution_id:
        query = query.where(SoftwareComponent.solution_id == solution_id)
    if status_filter:
        query = query.where(SoftwareComponent.status == status_filter)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            or_(SoftwareComponent.package_name.ilike(pattern), SoftwareSolution.name.ilike(pattern))
        )
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    result = await db.execute(
        query.order_by(SoftwareComponent.package_name).offset(offset).limit(limit)
    )
    items = [
        _component_json(item, solution_name, asset_name)
        for item, solution_name, asset_name in result.all()
    ]
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get(
    "/components/{component_id}/findings",
    dependencies=[Depends(require_scope("software:read", "viewer", "analyst"))],
)
async def component_findings(component_id: UUID, db: AsyncSession = Depends(get_db)):
    component = await db.get(SoftwareComponent, component_id)
    if not component:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Software component not found")
    solution = await db.get(SoftwareSolution, component.solution_id)
    result = await db.execute(
        select(SoftwareFinding)
        .where(SoftwareFinding.component_id == component_id)
        .order_by(SoftwareFinding.status, SoftwareFinding.severity)
    )
    return {
        "component": _component_json(component, solution.name if solution else None),
        "items": [
            _finding_json(item, component, solution.name if solution else None)
            for item in result.scalars().all()
        ],
    }


@router.get(
    "/findings", dependencies=[Depends(require_scope("software:read", "viewer", "analyst"))]
)
async def list_findings(
    status_filter: str = Query("open", alias="status"),
    severity: str | None = None,
    kev: bool | None = None,
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(SoftwareFinding, SoftwareComponent, SoftwareSolution.name)
        .join(SoftwareComponent, SoftwareComponent.id == SoftwareFinding.component_id)
        .join(SoftwareSolution, SoftwareSolution.id == SoftwareComponent.solution_id)
    )
    if status_filter:
        query = query.where(SoftwareFinding.status == status_filter)
    if severity:
        query = query.where(SoftwareFinding.severity == severity)
    if kev is not None:
        query = query.where(SoftwareFinding.kev.is_(kev))
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    result = await db.execute(
        query.order_by(
            SoftwareFinding.kev.desc(),
            SoftwareFinding.severity.desc(),
            SoftwareFinding.last_seen.desc(),
        )
        .offset(offset)
        .limit(limit)
    )
    items = [
        _finding_json(item, component, solution_name)
        for item, component, solution_name in result.all()
    ]
    return {"items": items, "total": total, "offset": offset, "limit": limit}


@router.get("/runs", dependencies=[Depends(require_scope("software:read", "viewer", "analyst"))])
async def list_runs(
    offset: int = Query(0, ge=0, le=1_000_000),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    total = await db.scalar(select(func.count(SoftwareScanRun.id))) or 0
    result = await db.execute(
        select(SoftwareScanRun)
        .order_by(SoftwareScanRun.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return {
        "items": [
            {
                "id": str(item.id),
                "solution_id": str(item.solution_id) if item.solution_id else None,
                "mode": item.mode,
                "source": item.source,
                "filename": item.filename,
                "status": item.status,
                "rows_seen": item.rows_seen,
                "components_upserted": item.components_upserted,
                "findings_count": item.findings_count,
                "errors": item.errors or [],
                "warnings": item.warnings or [],
                "provider_status": item.provider_status or {},
                "error": item.error,
                "started_at": _iso(item.started_at),
                "completed_at": _iso(item.completed_at),
                "created_at": _iso(item.created_at),
            }
            for item in result.scalars().all()
        ],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.post(
    "/import",
    dependencies=[
        Depends(require_scope("software:write", "analyst")),
        Depends(per_user_rate_limit("software_import", 3, 60)),
    ],
)
async def import_software(
    request: Request,
    file: UploadFile = File(...),
    dry_run: bool = Query(False),
    strict_assets: bool = Query(
        False,
        description="Reject the import when any referenced asset is not already in Kepryx",
    ),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("software:write", "analyst")),
):
    filename = Path(file.filename or "software_inventory.csv").name
    payload = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Software inventory file exceeds 20 MB"
        )
    parsed = parse_software_inventory(payload, filename)
    response = {
        "filename": filename,
        "sha256": parsed.sha256,
        "rows": len(parsed.records),
        "errors": parsed.errors[:100],
        "preview": [record.__dict__ for record in parsed.records[:100]],
    }
    if dry_run:
        asset_names = {record.asset for record in parsed.records if record.asset}
        asset_result = (
            await db.execute(select(Asset).where(Asset.name.in_(asset_names)))
            if asset_names
            else None
        )
        known_asset_names = (
            {item.name for item in asset_result.scalars().all()} if asset_result else set()
        )
        unresolved_assets = sorted(name for name in asset_names if name not in known_asset_names)
        return {
            **response,
            "dry_run": True,
            "accepted": len(parsed.records),
            "rejected": len(parsed.errors),
            "unresolved_assets": unresolved_assets[:100],
        }
    if not parsed.records:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            {"message": "No valid software rows", "errors": parsed.errors[:20]},
        )
    if len(parsed.records) > MAX_ROWS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Maximum of 10,000 software rows exceeded")

    solution_names = {record.solution for record in parsed.records}
    asset_names = {record.asset for record in parsed.records if record.asset}
    solution_result = await db.execute(
        select(SoftwareSolution).where(SoftwareSolution.name.in_(solution_names))
    )
    solutions = {item.name: item for item in solution_result.scalars().all()}
    asset_result = (
        await db.execute(select(Asset).where(Asset.name.in_(asset_names))) if asset_names else None
    )
    assets = {item.name: item for item in asset_result.scalars().all()} if asset_result else {}
    unresolved_assets = sorted(name for name in asset_names if name not in assets)
    if strict_assets and unresolved_assets:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {
                "message": "One or more referenced assets were not found",
                "unresolved_assets": unresolved_assets[:100],
            },
        )
    environments_by_solution = {
        name: _environment_for_records(
            [record for record in parsed.records if record.solution == name]
        )
        for name in solution_names
    }
    for name in sorted(solution_names):
        if name not in solutions:
            solutions[name] = SoftwareSolution(
                name=name,
                environment=environments_by_solution[name],
                source="manual_import",
            )
            db.add(solutions[name])
        elif (
            solutions[name].environment != "mixed"
            and solutions[name].environment != environments_by_solution[name]
        ):
            solutions[name].environment = "mixed"
    await db.flush()

    components_upserted = 0
    for record in parsed.records:
        solution = solutions[record.solution]
        asset = assets.get(record.asset) if record.asset else None
        query = select(SoftwareComponent).where(
            SoftwareComponent.solution_id == solution.id,
            SoftwareComponent.ecosystem == record.ecosystem,
            SoftwareComponent.normalized_name == record.normalized_package,
            SoftwareComponent.version == record.version,
        )
        query = (
            query.where(SoftwareComponent.asset_id == asset.id)
            if asset
            else query.where(SoftwareComponent.asset_id.is_(None))
        )
        component = (await db.execute(query)).scalar_one_or_none()
        if component is None:
            component = SoftwareComponent(
                solution_id=solution.id,
                asset_id=asset.id if asset else None,
                ecosystem=record.ecosystem,
                package_name=record.package,
                normalized_name=record.normalized_package,
                version=record.version,
                component_type=record.component_type,
                purl=record.purl,
                cpe=record.cpe,
                direct=record.direct,
                environment=record.environment,
                source=record.source,
            )
            db.add(component)
        else:
            component.last_seen = datetime.now(UTC)
            component.purl, component.cpe = record.purl, record.cpe
            component.source, component.direct = record.source, record.direct
            component.component_type = record.component_type
            component.environment = record.environment
        components_upserted += 1

    run = SoftwareScanRun(
        solution_id=solutions[next(iter(solution_names))].id if len(solution_names) == 1 else None,
        mode="import",
        source="OSV/NVD/registry",
        filename=filename,
        file_sha256=hashlib.sha256(payload).hexdigest(),
        status="queued",
        rows_seen=len(parsed.records),
        components_upserted=components_upserted,
        errors=parsed.errors[:100],
        warnings=[
            {
                "code": "unresolved_asset",
                "assets": unresolved_assets[:100],
                "count": len(unresolved_assets),
            }
        ]
        if unresolved_assets
        else [],
        created_by=getattr(user, "username", "system"),
    )
    db.add(run)
    await db.flush()
    await audit(
        request,
        "software_inventory_import",
        user,
        db,
        resource_type="software_scan_run",
        resource_id=str(run.id),
        details={
            "filename": filename,
            "sha256": run.file_sha256,
            "rows": len(parsed.records),
            "errors": len(parsed.errors),
            "unresolved_assets": len(unresolved_assets),
            "strict_assets": strict_assets,
        },
    )
    await db.commit()
    from app.workers.software_tasks import scan_software

    scan_software.apply_async(kwargs={"run_id": str(run.id), "mode": "import"})
    return {
        **response,
        "dry_run": False,
        "accepted": len(parsed.records),
        "rejected": len(parsed.errors),
        "unresolved_assets": unresolved_assets[:100],
        "run_id": str(run.id),
        "scan_queued": True,
    }


@router.post(
    "/scan",
    dependencies=[
        Depends(require_scope("software:scan", "analyst")),
        Depends(per_user_rate_limit("software_scan", 5, 60)),
    ],
)
async def trigger_scan(
    request: Request,
    solution_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("software:scan", "analyst")),
):
    if solution_id and not await db.get(SoftwareSolution, solution_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Software solution not found")
    run = SoftwareScanRun(
        solution_id=solution_id,
        mode="manual",
        source="OSV/NVD/registry",
        status="queued",
        created_by=getattr(user, "username", "system"),
    )
    db.add(run)
    await db.flush()
    await audit(
        request,
        "software_manual_scan",
        user,
        db,
        resource_type="software_scan_run",
        resource_id=str(run.id),
        details={"solution_id": str(solution_id) if solution_id else None},
    )
    await db.commit()
    from app.workers.software_tasks import scan_software

    scan_software.apply_async(
        kwargs={
            "solution_id": str(solution_id) if solution_id else None,
            "run_id": str(run.id),
            "mode": "manual",
        }
    )
    return {"queued": True, "run_id": str(run.id), "mode": "manual"}


@router.patch(
    "/findings/{finding_id}",
    dependencies=[Depends(require_scope("software:write", "analyst"))],
)
async def update_finding(
    finding_id: UUID,
    payload: SoftwareFindingUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("software:write", "analyst")),
):
    finding = await db.get(SoftwareFinding, finding_id)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Software finding not found")

    finding.status = payload.status
    finding.resolution_note = payload.resolution_note
    if payload.status in {"mitigated", "accepted", "resolved"}:
        finding.resolved_at = datetime.now(UTC)
        finding.resolved_by = getattr(user, "username", "system")
    else:
        finding.resolved_at = None
        finding.resolved_by = None

    component = await db.get(SoftwareComponent, finding.component_id)
    if component:
        await _refresh_solution_counts(db, component.solution_id)
    await audit(
        request,
        "software_finding_status_changed",
        user,
        db,
        resource_type="software_finding",
        resource_id=str(finding.id),
        details={"status": payload.status},
    )
    await db.commit()
    return {
        "status": "updated",
        "finding": _finding_json(finding, component),
    }
