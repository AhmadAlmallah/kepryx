"""Self-security API: platform dep visibility + update workflow."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_admin, require_scope
from app.core.database import get_db
from app.models.self_security import (
    DependencyFinding,
    PlatformDependency,
    SelfSecuritySettings,
    UpdateProposal,
)

router = APIRouter()


# ─── Settings ───
class SettingsUpdate(BaseModel):
    auto_scan_enabled: bool | None = None
    scan_cron: str | None = None
    auto_update_enabled: bool | None = None
    auto_update_severity_threshold: str | None = None
    auto_update_only_patch: bool | None = None
    auto_update_only_kev: bool | None = None
    require_ai_validation: bool | None = None
    require_admin_approval: bool | None = None
    auto_rollback_on_failure: bool | None = None
    maintenance_window_cron: str | None = None
    notify_channels: list[str] | None = None
    ai_model: str | None = None
    excluded_packages: list[str] | None = None


@router.get("/settings", dependencies=[Depends(require_admin)])
async def get_settings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SelfSecuritySettings).where(SelfSecuritySettings.id == 1))
    s = result.scalar_one_or_none()
    if not s:
        s = SelfSecuritySettings(id=1)
        db.add(s)
        await db.commit()
    return {
        "auto_scan_enabled": s.auto_scan_enabled,
        "scan_cron": s.scan_cron,
        "auto_update_enabled": s.auto_update_enabled,
        "auto_update_severity_threshold": s.auto_update_severity_threshold,
        "auto_update_only_patch": s.auto_update_only_patch,
        "auto_update_only_kev": s.auto_update_only_kev,
        "require_ai_validation": s.require_ai_validation,
        "require_admin_approval": s.require_admin_approval,
        "auto_rollback_on_failure": s.auto_rollback_on_failure,
        "maintenance_window_cron": s.maintenance_window_cron,
        "notify_channels": s.notify_channels,
        "ai_model": s.ai_model,
        "excluded_packages": s.excluded_packages,
        "last_scan_status": s.last_scan_status,
        "last_scan_error": s.last_scan_error,
        "last_scan_at": s.last_scan_at.isoformat() if s.last_scan_at else None,
        "last_successful_scan_at": (
            s.last_successful_scan_at.isoformat() if s.last_successful_scan_at else None
        ),
        "packages_scanned": s.packages_scanned,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        "updated_by": s.updated_by,
    }


@router.patch("/settings", dependencies=[Depends(require_admin)])
async def update_settings(
    body: SettingsUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    if body.auto_update_enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "In-place source updates are disabled; use reviewed dependency PRs",
        )
    if body.require_admin_approval is False:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Administrator approval is mandatory for dependency changes",
        )
    result = await db.execute(select(SelfSecuritySettings).where(SelfSecuritySettings.id == 1))
    s = result.scalar_one_or_none()
    if not s:
        s = SelfSecuritySettings(id=1)
        db.add(s)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(s, k, v)
    s.updated_by = user.username
    await audit(
        request,
        "self_security_settings_updated",
        user,
        db,
        resource_type="settings",
        details=changes,
    )
    await db.commit()
    return {"ok": True, "changes": changes}


# ─── Dependencies inventory ───
@router.get(
    "/dependencies",
    dependencies=[Depends(require_scope("self_security:read", "viewer", "analyst"))],
)
async def list_dependencies(db: AsyncSession = Depends(get_db), vulnerable_only: bool = False):
    q = select(PlatformDependency)
    if vulnerable_only:
        q = q.where(PlatformDependency.cve_count > 0)
    q = q.order_by(PlatformDependency.max_cvss.desc().nulls_last())
    result = await db.execute(q)
    return [
        {
            "id": str(p.id),
            "component": p.component,
            "package_type": p.package_type,
            "name": p.name,
            "version": p.version,
            "latest_version": p.latest_version,
            "purl": p.purl,
            "license": p.license,
            "direct": p.direct,
            "last_checked": p.last_checked.isoformat() if p.last_checked else None,
            "cve_count": p.cve_count,
            "kev_count": p.kev_count,
            "max_cvss": p.max_cvss,
            "update_available": p.update_available,
            "update_blocked_reason": p.update_blocked_reason,
        }
        for p in result.scalars().all()
    ]


@router.get(
    "/dependencies/{dep_id:uuid}/findings",
    dependencies=[Depends(require_scope("self_security:read", "viewer", "analyst"))],
)
async def get_dep_findings(dep_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DependencyFinding)
        .where(DependencyFinding.dependency_id == dep_id)
        .order_by(DependencyFinding.cvss.desc().nulls_last())
    )
    return [
        {
            "id": str(f.id),
            "cve_id": f.cve_id,
            "cvss": f.cvss,
            "epss": f.epss,
            "kev": f.kev,
            "severity": f.severity,
            "description": f.description,
            "fixed_version": f.fixed_version,
            "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
            "suppressed": f.suppressed,
            "suppressed_reason": f.suppressed_reason,
        }
        for f in result.scalars().all()
    ]


@router.post("/findings/{finding_id}/suppress", dependencies=[Depends(require_admin)])
async def suppress_finding(
    finding_id: UUID,
    reason: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    result = await db.execute(select(DependencyFinding).where(DependencyFinding.id == finding_id))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    f.suppressed = True
    f.suppressed_reason = reason[:255]
    f.suppressed_by = user.username
    await audit(
        request,
        "finding_suppressed",
        user,
        db,
        resource_type="finding",
        resource_id=str(finding_id),
        details={"reason": reason},
    )
    await db.commit()
    return {"ok": True}


# ─── Update proposals ───
@router.get(
    "/proposals", dependencies=[Depends(require_scope("self_security:read", "viewer", "analyst"))]
)
async def list_proposals(db: AsyncSession = Depends(get_db), status_filter: str | None = None):
    q = select(UpdateProposal)
    if status_filter:
        q = q.where(UpdateProposal.status == status_filter)
    q = q.order_by(UpdateProposal.created_at.desc())
    result = await db.execute(q)
    return [
        {
            "id": str(p.id),
            "component": p.component,
            "package_name": p.package_name,
            "current_version": p.current_version,
            "target_version": p.target_version,
            "reason": p.reason,
            "cves_fixed": p.cves_fixed,
            "ai_recommendation": p.ai_recommendation,
            "ai_risk_score": p.ai_risk_score,
            "breaking_changes_detected": p.breaking_changes_detected,
            "ai_assessment": p.ai_assessment,
            "compatibility_notes": p.compatibility_notes,
            "status": p.status,
            "approved_by": p.approved_by,
            "approved_at": p.approved_at.isoformat() if p.approved_at else None,
            "applied_at": p.applied_at.isoformat() if p.applied_at else None,
            "error_message": p.error_message,
            "created_at": p.created_at.isoformat(),
        }
        for p in result.scalars().all()
    ]


@router.post("/proposals/{proposal_id}/approve", dependencies=[Depends(require_admin)])
async def approve_proposal(
    proposal_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    result = await db.execute(select(UpdateProposal).where(UpdateProposal.id == proposal_id))
    prop = result.scalar_one_or_none()
    if not prop:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    if prop.status not in ("proposed", "ai_validated"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Cannot approve in status: {prop.status}")
    prop.status = "approved"
    prop.approved_by = user.username
    prop.approved_at = datetime.now(UTC)
    await audit(
        request,
        "update_approved",
        user,
        db,
        resource_type="update_proposal",
        resource_id=str(proposal_id),
        details={"package": prop.package_name, "version": prop.target_version},
    )
    await db.commit()
    return {"ok": True, "status": prop.status}


@router.post("/proposals/{proposal_id}/reject", dependencies=[Depends(require_admin)])
async def reject_proposal(
    proposal_id: UUID,
    request: Request,
    reason: str = "",
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    result = await db.execute(select(UpdateProposal).where(UpdateProposal.id == proposal_id))
    prop = result.scalar_one_or_none()
    if not prop:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    prop.status = "rejected"
    prop.error_message = reason[:1000]
    await audit(
        request,
        "update_rejected",
        user,
        db,
        resource_type="update_proposal",
        resource_id=str(proposal_id),
        details={"reason": reason},
    )
    await db.commit()
    return {"ok": True}


@router.post("/proposals/{proposal_id}/apply-now", dependencies=[Depends(require_admin)])
async def apply_now(
    proposal_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Generate a non-mutating patch artifact for an approved proposal."""
    result = await db.execute(select(UpdateProposal).where(UpdateProposal.id == proposal_id))
    prop = result.scalar_one_or_none()
    if not prop:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    if prop.status != "approved":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Proposal must be approved first")

    from app.workers.self_security_tasks import apply_approved_updates

    apply_approved_updates.delay(str(proposal_id))
    await audit(
        request,
        "manual_update_apply",
        user,
        db,
        resource_type="update_proposal",
        resource_id=str(proposal_id),
    )
    await db.commit()
    return {"queued": True, "action": "prepare_patch_for_pr"}


@router.post("/proposals/{proposal_id}/rollback", dependencies=[Depends(require_admin)])
async def rollback(
    proposal_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Cancel a prepared patch; no source file rollback is performed."""
    from app.workers.self_security_tasks import rollback_proposal

    rollback_proposal.delay(str(proposal_id))
    await audit(
        request,
        "update_rollback",
        user,
        db,
        resource_type="update_proposal",
        resource_id=str(proposal_id),
    )
    await db.commit()
    return {"queued": True}


# ─── Manual triggers ───
@router.post("/scan/trigger", dependencies=[Depends(require_admin)])
async def trigger_scan(
    request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)
):
    from app.workers.self_security_tasks import (
        ai_validate_proposals,
        propose_updates,
        scan_platform_deps,
    )

    scan_platform_deps.delay()
    propose_updates.apply_async(countdown=120)
    ai_validate_proposals.apply_async(countdown=240)
    await audit(request, "self_security_manual_scan", user, db)
    await db.commit()
    return {"queued": True, "pipeline": ["scan", "propose", "ai_validate"]}


@router.get(
    "/summary", dependencies=[Depends(require_scope("self_security:read", "viewer", "analyst"))]
)
async def summary(db: AsyncSession = Depends(get_db)):
    settings_result = await db.execute(
        select(SelfSecuritySettings).where(SelfSecuritySettings.id == 1)
    )
    scan_settings = settings_result.scalar_one_or_none()
    total_deps = await db.scalar(select(func.count(PlatformDependency.id)))
    vuln_deps = await db.scalar(
        select(func.count(PlatformDependency.id)).where(PlatformDependency.cve_count > 0)
    )
    total_findings = await db.scalar(
        select(func.count(DependencyFinding.id)).where(DependencyFinding.suppressed.is_(False))
    )
    critical_findings = await db.scalar(
        select(func.count(DependencyFinding.id)).where(
            DependencyFinding.severity == "critical", DependencyFinding.suppressed.is_(False)
        )
    )
    proposals_pending = await db.scalar(
        select(func.count(UpdateProposal.id)).where(
            UpdateProposal.status.in_(["proposed", "ai_validated", "approved"])
        )
    )
    last_success = scan_settings.last_successful_scan_at if scan_settings else None
    scan_stale = not last_success or last_success < datetime.now(UTC) - timedelta(hours=26)
    return {
        "scan_status": scan_settings.last_scan_status if scan_settings else "never",
        "scan_stale": scan_stale,
        "last_successful_scan_at": last_success.isoformat() if last_success else None,
        "total_dependencies": total_deps or 0,
        "vulnerable_dependencies": vuln_deps or 0,
        "total_findings": total_findings or 0,
        "critical_findings": critical_findings or 0,
        "proposals_pending": proposals_pending or 0,
    }
