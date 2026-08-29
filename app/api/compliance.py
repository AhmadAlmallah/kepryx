"""Compliance catalogs, auditable assessment runs, and evidence lineage endpoints."""

from collections import defaultdict
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_admin, require_scope
from app.core.database import get_db
from app.models import (
    AssessmentEvidence,
    AssessmentResult,
    AssessmentRun,
    Asset,
    ComplianceMapping,
    EvidenceItem,
    FrameworkCatalog,
    FrameworkControl,
)

router = APIRouter()
read_scope = require_scope("compliance:read", "viewer", "analyst")
READ_SCOPE = Depends(read_scope)

SummaryValue = int | float | str | None
Summary = dict[str, SummaryValue]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _empty_counts() -> Summary:
    return {
        "compliant": 0,
        "partial": 0,
        "gap": 0,
        "exception": 0,
        "not_assessed": 0,
        "not_applicable": 0,
        "na": 0,
        "unknown": 0,
    }


def _numeric_count(target: Summary, key: str) -> int:
    value = target.get(key, 0)
    return int(value) if isinstance(value, (int, float)) else 0


def _add_count(target: Summary, status: str, count: int, last_status: str | None = None) -> None:
    key = "not_applicable" if status == "na" else status
    target[key] = _numeric_count(target, key) + count
    if status == "na":
        target["na"] = _numeric_count(target, "na") + count
    if last_status:
        target["last_assessed_at"] = last_status


def _finalize_counts(target: Summary) -> Summary:
    total = sum(
        _numeric_count(target, key)
        for key in (
            "compliant",
            "partial",
            "gap",
            "exception",
            "not_assessed",
            "not_applicable",
            "unknown",
        )
    )
    applicable = total - _numeric_count(target, "not_applicable")
    target["total"] = total
    target["assessed"] = applicable - _numeric_count(target, "not_assessed")
    target["compliance_pct"] = (
        round(_numeric_count(target, "compliant") / applicable * 100, 2) if applicable else 0
    )
    return target


async def _latest_completed_run(db: AsyncSession) -> AssessmentRun | None:
    result = await db.execute(
        select(AssessmentRun)
        .where(AssessmentRun.status == "completed")
        .order_by(AssessmentRun.completed_at.desc().nulls_last(), AssessmentRun.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _new_summary(db: AsyncSession, run: AssessmentRun) -> dict[str, dict]:
    result = await db.execute(
        select(
            FrameworkCatalog.code,
            FrameworkCatalog.name,
            FrameworkCatalog.version,
            AssessmentResult.status,
            func.count(AssessmentResult.id),
        )
        .join(FrameworkControl, FrameworkControl.catalog_id == FrameworkCatalog.id)
        .join(AssessmentResult, AssessmentResult.control_id == FrameworkControl.id)
        .where(AssessmentResult.run_id == run.id)
        .group_by(
            FrameworkCatalog.code,
            FrameworkCatalog.name,
            FrameworkCatalog.version,
            AssessmentResult.status,
        )
    )
    summary: dict[str, dict] = {}
    for framework, name, version, result_status, count in result.all():
        values = summary.setdefault(
            framework,
            {
                **_empty_counts(),
                "name": name,
                "version": version,
                "last_assessed_at": _iso(run.completed_at or run.created_at),
            },
        )
        _add_count(values, result_status, count)
    for values in summary.values():
        _finalize_counts(values)
    return summary


async def _legacy_summary(db: AsyncSession) -> dict[str, dict]:
    result = await db.execute(
        select(
            ComplianceMapping.framework,
            ComplianceMapping.status,
            func.count(ComplianceMapping.id),
        ).group_by(ComplianceMapping.framework, ComplianceMapping.status)
    )
    summary: dict[str, dict] = {}
    for framework, result_status, count in result.all():
        values = summary.setdefault(framework, _empty_counts())
        _add_count(values, result_status, count)
    for values in summary.values():
        _finalize_counts(values)
    return summary


@router.get("", dependencies=[READ_SCOPE])
async def list_compliance(
    db: AsyncSession = Depends(get_db),
    framework: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
):
    """Return the compatibility mapping plus the newest evidence-backed result metadata."""
    query = select(ComplianceMapping, Asset.name).join(
        Asset, Asset.id == ComplianceMapping.asset_id
    )
    if framework:
        query = query.where(ComplianceMapping.framework == framework)
    if status_filter:
        query = query.where(ComplianceMapping.status == status_filter)
    mapping_result = await db.execute(query.limit(1000))

    latest_result = await db.execute(
        select(
            AssessmentResult,
            FrameworkControl.control_id,
            FrameworkCatalog.code,
            FrameworkCatalog.version,
            AssessmentEvidence.evidence_id,
        )
        .join(FrameworkControl, FrameworkControl.id == AssessmentResult.control_id)
        .join(FrameworkCatalog, FrameworkCatalog.id == FrameworkControl.catalog_id)
        .outerjoin(AssessmentEvidence, AssessmentEvidence.result_id == AssessmentResult.id)
        .order_by(AssessmentResult.assessed_at.desc())
        .limit(10000)
    )
    latest_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result, control_id, catalog_code, version, evidence_id in latest_result.all():
        key = (str(result.asset_id), catalog_code, control_id)
        record = latest_by_key.setdefault(
            key,
            {
                "result_id": str(result.id),
                "run_id": str(result.run_id),
                "framework_version": version,
                "status": result.status,
                "score": result.score,
                "confidence": result.confidence,
                "rationale": result.rationale,
                "evidence_ids": [],
            },
        )
        if evidence_id and str(evidence_id) not in record["evidence_ids"]:
            record["evidence_ids"].append(str(evidence_id))

    items = []
    for mapping, asset_name in mapping_result.all():
        lineage = latest_by_key.get(
            (str(mapping.asset_id), mapping.framework, mapping.control_id), {}
        )
        items.append(
            {
                "id": str(mapping.id),
                "framework": mapping.framework,
                "framework_version": lineage.get(
                    "framework_version", mapping.evidence.get("framework_version")
                ),
                "control_id": mapping.control_id,
                "asset_id": str(mapping.asset_id),
                "asset_name": asset_name,
                "status": mapping.status,
                "score": lineage.get("score"),
                "confidence": lineage.get("confidence"),
                "rationale": lineage.get("rationale"),
                "run_id": lineage.get("run_id", mapping.evidence.get("assessment_run_id")),
                "result_id": lineage.get("result_id", mapping.evidence.get("assessment_result_id")),
                "evidence_ids": lineage.get("evidence_ids", [mapping.evidence.get("evidence_id")]),
                "evidence": mapping.evidence,
                "assessed_at": mapping.assessed_at.isoformat(),
            }
        )
    return {"items": items}


@router.get("/summary", dependencies=[READ_SCOPE])
async def compliance_summary(db: AsyncSession = Depends(get_db)):
    """Return the latest evidence-backed per-framework posture summary."""
    run = await _latest_completed_run(db)
    return await _new_summary(db, run) if run else await _legacy_summary(db)


@router.get("/frameworks", dependencies=[READ_SCOPE])
async def list_frameworks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(FrameworkCatalog).order_by(FrameworkCatalog.code, FrameworkCatalog.version)
    )
    catalogs = result.scalars().all()
    control_result = await db.execute(
        select(FrameworkControl).order_by(FrameworkControl.catalog_id, FrameworkControl.sort_order)
    )
    controls_by_catalog: dict[UUID, list[dict]] = defaultdict(list)
    for control in control_result.scalars().all():
        controls_by_catalog[control.catalog_id].append(
            {
                "id": str(control.id),
                "control_id": control.control_id,
                "title": control.title,
                "objective": control.objective,
                "family": control.family,
                "rule_key": control.rule_key,
                "assessment_method": control.assessment_method,
                "evidence_requirements": control.evidence_requirements,
            }
        )
    return {
        "items": [
            {
                "id": str(catalog.id),
                "code": catalog.code,
                "version": catalog.version,
                "name": catalog.name,
                "source_url": catalog.source_url,
                "active": catalog.active,
                "controls": controls_by_catalog.get(catalog.id, []),
            }
            for catalog in catalogs
        ]
    }


@router.get("/runs", dependencies=[READ_SCOPE])
async def list_assessment_runs(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
):
    result = await db.execute(
        select(AssessmentRun).order_by(AssessmentRun.created_at.desc()).limit(limit)
    )
    runs = result.scalars().all()
    return {
        "items": [
            {
                "id": str(run.id),
                "framework_code": run.framework_code,
                "framework_version": run.framework_version,
                "status": run.status,
                "scope": run.scope,
                "methodology": run.methodology,
                "summary": run.summary,
                "started_at": _iso(run.started_at),
                "completed_at": _iso(run.completed_at),
                "initiated_by": run.initiated_by,
                "created_at": _iso(run.created_at),
            }
            for run in runs
        ],
        "total": len(runs),
    }


@router.get("/runs/{run_id}", dependencies=[READ_SCOPE])
async def assessment_run_detail(
    run_id: UUID,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=2000, ge=1, le=10000),
):
    run = await db.get(AssessmentRun, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Assessment run not found")
    result = await db.execute(
        select(
            AssessmentResult,
            FrameworkControl,
            FrameworkCatalog,
            Asset.name,
        )
        .join(FrameworkControl, FrameworkControl.id == AssessmentResult.control_id)
        .join(FrameworkCatalog, FrameworkCatalog.id == FrameworkControl.catalog_id)
        .outerjoin(Asset, Asset.id == AssessmentResult.asset_id)
        .where(AssessmentResult.run_id == run_id)
        .order_by(FrameworkCatalog.code, FrameworkControl.sort_order, Asset.name)
        .limit(limit)
    )
    evidence_counts = await db.execute(
        select(AssessmentEvidence.result_id, func.count(AssessmentEvidence.evidence_id))
        .join(AssessmentResult, AssessmentResult.id == AssessmentEvidence.result_id)
        .where(AssessmentResult.run_id == run_id)
        .group_by(AssessmentEvidence.result_id)
    )
    counts = {str(result_id): count for result_id, count in evidence_counts.all()}
    return {
        "run": {
            "id": str(run.id),
            "framework_code": run.framework_code,
            "framework_version": run.framework_version,
            "status": run.status,
            "scope": run.scope,
            "methodology": run.methodology,
            "summary": run.summary,
            "started_at": _iso(run.started_at),
            "completed_at": _iso(run.completed_at),
            "initiated_by": run.initiated_by,
            "created_at": _iso(run.created_at),
        },
        "results": [
            {
                "id": str(assessment.id),
                "framework": catalog.code,
                "framework_version": catalog.version,
                "control_id": control.control_id,
                "control_title": control.title,
                "asset_id": str(assessment.asset_id) if assessment.asset_id else None,
                "asset_name": asset_name,
                "status": assessment.status,
                "score": assessment.score,
                "confidence": assessment.confidence,
                "rationale": assessment.rationale,
                "rule_key": assessment.rule_key,
                "evidence_count": counts.get(str(assessment.id), 0),
                "assessed_at": _iso(assessment.assessed_at),
            }
            for assessment, control, catalog, asset_name in result.all()
        ],
    }


@router.get("/results/{result_id}/lineage", dependencies=[READ_SCOPE])
async def assessment_result_lineage(result_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(
            AssessmentResult,
            FrameworkControl,
            FrameworkCatalog,
            AssessmentRun,
            Asset.name,
        )
        .join(FrameworkControl, FrameworkControl.id == AssessmentResult.control_id)
        .join(FrameworkCatalog, FrameworkCatalog.id == FrameworkControl.catalog_id)
        .join(AssessmentRun, AssessmentRun.id == AssessmentResult.run_id)
        .outerjoin(Asset, Asset.id == AssessmentResult.asset_id)
        .where(AssessmentResult.id == result_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Assessment result not found")
    assessment, control, catalog, run, asset_name = row
    evidence_result = await db.execute(
        select(AssessmentEvidence, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == AssessmentEvidence.evidence_id)
        .where(AssessmentEvidence.result_id == result_id)
        .order_by(EvidenceItem.observed_at.desc().nulls_last(), EvidenceItem.created_at.desc())
    )
    return {
        "result": {
            "id": str(assessment.id),
            "framework": catalog.code,
            "framework_version": catalog.version,
            "control_id": control.control_id,
            "control_title": control.title,
            "control_objective": control.objective,
            "asset_id": str(assessment.asset_id) if assessment.asset_id else None,
            "asset_name": asset_name,
            "status": assessment.status,
            "score": assessment.score,
            "confidence": assessment.confidence,
            "rationale": assessment.rationale,
            "rule_key": assessment.rule_key,
            "assessed_at": _iso(assessment.assessed_at),
        },
        "run": {
            "id": str(run.id),
            "status": run.status,
            "started_at": _iso(run.started_at),
            "completed_at": _iso(run.completed_at),
            "initiated_by": run.initiated_by,
            "methodology": run.methodology,
        },
        "evidence": [
            {
                "id": str(evidence.id),
                "relation": link.relation,
                "role": link.role,
                "extracted_by": link.extracted_by,
                "source_type": evidence.source_type,
                "source_ref": evidence.source_ref,
                "title": evidence.title,
                "description": evidence.description,
                "observed": evidence.observed,
                "observed_at": _iso(evidence.observed_at),
                "captured_at": _iso(evidence.captured_at),
                "integrity_sha256": evidence.integrity_sha256,
                "collector": evidence.collector,
                "classification": evidence.classification,
            }
            for link, evidence in evidence_result.all()
        ],
    }


@router.post("/audit/run", dependencies=[Depends(require_admin)])
async def trigger_audit(user: Any = Depends(require_admin)):
    from app.workers.compliance_tasks import run_compliance_audit

    task = run_compliance_audit.delay(user.username)
    return {"queued": True, "task_id": task.id}


@router.post("/results/{result_id}/ai-review", dependencies=[READ_SCOPE])
async def ai_review_result(
    result_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: Any = Depends(read_scope),
):
    from app.services.compliance_ai import ComplianceAIError, review_assessment_result

    try:
        review = await review_assessment_result(db, result_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ComplianceAIError as exc:
        await audit(
            request,
            "compliance_ai_review_failed",
            user,
            db,
            resource_type="assessment_result",
            resource_id=str(result_id),
            severity="warning",
            details={"reason": str(exc)},
        )
        await db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    await audit(
        request,
        "compliance_ai_review",
        user,
        db,
        resource_type="assessment_result",
        resource_id=str(result_id),
        details={"read_only": True, "authoritative": False},
    )
    await db.commit()
    return review
