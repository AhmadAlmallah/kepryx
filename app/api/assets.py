"""Asset endpoints — list, get, update, ingest, enrich."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_scope
from app.core.database import get_db
from app.core.rate_limit import per_user_rate_limit
from app.models import CVE, Asset, AssetCVE
from app.services.risk_engine import compute_risk
from app.workers.enrichment_tasks import enrich_asset as enrich_task

router = APIRouter()


class AssetResponse(BaseModel):
    id: UUID
    name: str
    type: str
    os: str | None
    ip: str | None
    mac: str | None
    segment: str | None
    edr_status: str | None
    control_coverage: str
    network_exposure: str
    auth_method: str
    criticality: str
    risk_score: float
    risk_tier: str
    risk_breakdown: dict
    cve_count: int = 0
    kev_count: int = 0
    is_shadow: bool
    is_stale: bool
    sources: list
    last_seen: str | None

    class Config:
        from_attributes = True


class AssetUpdate(BaseModel):
    criticality: str | None = None
    data_classification: str | None = None
    control_coverage: str | None = None
    auth_method: str | None = None
    tags: list[str] | None = None


@router.get("", dependencies=[Depends(require_scope("assets:read", "viewer", "analyst"))])
async def list_assets(
    db: AsyncSession = Depends(get_db),
    risk_tier: str | None = None,
    segment: str | None = None,
    is_shadow: bool | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    q = select(Asset)
    if risk_tier:
        q = q.where(Asset.risk_tier == risk_tier)
    if segment:
        q = q.where(Asset.segment == segment)
    if is_shadow is not None:
        q = q.where(Asset.is_shadow == is_shadow)
    if search:
        like = f"%{search}%"
        q = q.where(or_(Asset.name.ilike(like), Asset.os.ilike(like)))

    total = await db.scalar(select(func.count()).select_from(q.subquery()))
    q = q.order_by(Asset.risk_score.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    assets = result.scalars().all()

    # Keep CVE counts bounded to one aggregate query instead of issuing two
    # queries per asset row. The dashboard is intentionally allowed to request
    # larger pages, so this is part of the API's functional performance
    # contract rather than a cosmetic optimization.
    cve_counts: dict[UUID, tuple[int, int]] = {}
    if assets:
        count_result = await db.execute(
            select(
                AssetCVE.asset_id,
                func.count(AssetCVE.cve_id),
                func.count(AssetCVE.cve_id).filter(CVE.kev.is_(True)),
            )
            .join(CVE, CVE.id == AssetCVE.cve_id)
            .where(AssetCVE.asset_id.in_([asset.id for asset in assets]))
            .group_by(AssetCVE.asset_id)
        )
        cve_counts = {
            asset_id: (int(cve_count), int(kev_count))
            for asset_id, cve_count, kev_count in count_result.all()
        }

    items = []
    for a in assets:
        cve_count, kev_count = cve_counts.get(a.id, (0, 0))
        items.append(
            {
                "id": str(a.id),
                "name": a.name,
                "type": a.type,
                "os": a.os,
                "ip": str(a.ip) if a.ip else None,
                "mac": str(a.mac) if a.mac else None,
                "segment": a.segment,
                "edr_status": a.edr_status,
                "control_coverage": a.control_coverage,
                "network_exposure": a.network_exposure,
                "auth_method": a.auth_method,
                "criticality": a.criticality,
                "risk_score": a.risk_score,
                "risk_tier": a.risk_tier,
                "risk_breakdown": a.risk_breakdown,
                "cve_count": cve_count or 0,
                "kev_count": kev_count or 0,
                "is_shadow": a.is_shadow,
                "is_stale": a.is_stale,
                "sources": a.sources,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
        )

    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get(
    "/{asset_id:uuid}", dependencies=[Depends(require_scope("assets:read", "viewer", "analyst"))]
)
async def get_asset(asset_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    cves_result = await db.execute(
        select(AssetCVE, CVE).join(CVE).where(AssetCVE.asset_id == asset_id)
    )
    cves = [
        {
            "id": cve.id,
            "cvss_v3": cve.cvss_v3,
            "cvss_vector": cve.cvss_vector,
            "epss_score": cve.epss_score,
            "epss_percentile": cve.epss_percentile,
            "kev": cve.kev,
            "kev_date_added": cve.kev_date_added.isoformat() if cve.kev_date_added else None,
            "description": cve.description,
            "matched_cpe": ac.matched_cpe,
            "suppressed": ac.suppressed,
            "remediated": ac.remediated,
        }
        for ac, cve in cves_result.all()
    ]

    return {
        "id": str(asset.id),
        "name": asset.name,
        "type": asset.type,
        "os": asset.os,
        "ip": str(asset.ip) if asset.ip else None,
        "mac": str(asset.mac) if asset.mac else None,
        "segment": asset.segment,
        "edr_status": asset.edr_status,
        "control_coverage": asset.control_coverage,
        "network_exposure": asset.network_exposure,
        "auth_method": asset.auth_method,
        "criticality": asset.criticality,
        "data_classification": asset.data_classification,
        "dependencies": asset.dependencies,
        "software_stack": asset.software_stack,
        "cpe": asset.cpe,
        "last_patch": asset.last_patch,
        "eol_status": asset.eol_status,
        "risk_score": asset.risk_score,
        "risk_tier": asset.risk_tier,
        "risk_breakdown": asset.risk_breakdown,
        "is_shadow": asset.is_shadow,
        "is_stale": asset.is_stale,
        "sources": asset.sources,
        "first_seen": asset.first_seen.isoformat(),
        "last_seen": asset.last_seen.isoformat(),
        "cves": cves,
        "tags": asset.tags,
        "attrs": asset.attrs,
    }


@router.patch("/{asset_id:uuid}")
async def update_asset(
    asset_id: UUID,
    body: AssetUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("assets:write", "analyst")),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(asset, k, v)
    cve_result = await db.execute(
        select(CVE).join(AssetCVE, AssetCVE.cve_id == CVE.id).where(AssetCVE.asset_id == asset_id)
    )
    risk = compute_risk(
        {
            "control_coverage": asset.control_coverage,
            "network_exposure": asset.network_exposure,
            "auth_method": asset.auth_method,
            "criticality": asset.criticality,
            "data_classification": asset.data_classification,
            "eol_status": asset.eol_status,
            "cves": [
                {"cvss_v3": cve.cvss_v3, "epss_score": cve.epss_score, "kev": cve.kev}
                for cve in cve_result.scalars().all()
            ],
        }
    )
    asset.risk_score = risk.score
    asset.risk_tier = risk.tier
    asset.risk_breakdown = risk.breakdown
    await audit(
        request,
        "asset_updated",
        user,
        db,
        resource_type="asset",
        resource_id=str(asset_id),
        details=changes,
    )
    await db.commit()
    return {"ok": True, "changes": changes}


@router.post("/{asset_id:uuid}/enrich")
async def trigger_enrichment(
    asset_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("assets:write", "analyst")),
):
    enrich_task.delay(str(asset_id))
    await audit(
        request, "enrich_triggered", user, db, resource_type="asset", resource_id=str(asset_id)
    )
    await db.commit()
    return {"ok": True, "queued": True}


class IngestRequest(BaseModel):
    raw_text: str = Field(min_length=1, max_length=200000)


@router.post("/ingest/ai")
async def ai_ingest(
    body: IngestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("assets:write", "analyst")),
    _rate_check: None = Depends(per_user_rate_limit("ai_ingest", 5, 60)),
):
    """Parse arbitrary input via Claude, then enrich via NVD/EPSS/KEV."""
    from app.services.ai_parser import AIParserError, parse_assets_from_text

    try:
        parsed = await parse_assets_from_text(body.raw_text)
    except AIParserError as exc:
        # A missing or unavailable external model is an expected dependency
        # failure, not an unhandled API exception. Keep the UI actionable and
        # avoid returning an opaque 500 response.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    created_ids = []
    from app.services.reconciler import Reconciler

    reconciler = Reconciler(db)
    for asset_data in parsed:
        asset = await reconciler.create_from_source("manual", asset_data)
        created_ids.append(str(asset.id))
        # Queue enrichment
        enrich_task.delay(str(asset.id))

    await audit(request, "ai_ingest", user, db, details={"count": len(parsed)})
    await db.commit()
    return {"parsed": len(parsed), "asset_ids": created_ids, "enrichment_queued": True}


@router.get(
    "/stats/summary", dependencies=[Depends(require_scope("assets:read", "viewer", "analyst"))]
)
async def stats_summary(db: AsyncSession = Depends(get_db)):
    total = await db.scalar(select(func.count(Asset.id)))
    critical = await db.scalar(select(func.count(Asset.id)).where(Asset.risk_tier == "Critical"))
    high = await db.scalar(select(func.count(Asset.id)).where(Asset.risk_tier == "High"))
    shadow = await db.scalar(select(func.count(Asset.id)).where(Asset.is_shadow.is_(True)))
    stale = await db.scalar(select(func.count(Asset.id)).where(Asset.is_stale.is_(True)))
    no_edr = await db.scalar(
        select(func.count(Asset.id)).where(
            or_(Asset.edr_status == "None", Asset.edr_status.is_(None))
        )
    )
    eol = await db.scalar(select(func.count(Asset.id)).where(Asset.eol_status.is_(True)))
    kev_total = await db.scalar(select(func.count(CVE.id)).where(CVE.kev.is_(True)))

    return {
        "total_assets": total or 0,
        "critical_risk": critical or 0,
        "high_risk": high or 0,
        "shadow_assets": shadow or 0,
        "stale_assets": stale or 0,
        "no_edr_coverage": no_edr or 0,
        "eol_assets": eol or 0,
        "total_kev_cves": kev_total or 0,
    }


# â”€â”€â”€ Manual asset CRUD endpoints (added by deploy v2) â”€â”€â”€


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(default="Unknown", max_length=64)
    os: str | None = Field(default=None, max_length=255)
    ip: str | None = Field(default=None, max_length=64)
    mac: str | None = Field(default=None, max_length=64)
    segment: str | None = Field(default="Internal", max_length=64)
    edr_status: str | None = Field(default="None", max_length=128)
    control_coverage: str = Field(default="none")
    network_exposure: str = Field(default="internal")
    auth_method: str = Field(default="password")
    criticality: str = Field(default="medium")
    data_classification: str = Field(default="Internal")
    last_patch: str | None = None
    eol_status: bool = False
    software_stack: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("assets:write", "analyst")),
):
    """Create a manually observed asset through the supported API contract."""
    values = body.model_dump()
    risk = compute_risk(values)
    asset = Asset(
        **values,
        sources=["manual"],
        attrs={},
        is_shadow=False,
        is_stale=False,
        risk_score=risk.score,
        risk_tier=risk.tier,
        risk_breakdown=risk.breakdown,
    )
    db.add(asset)
    await db.flush()
    await audit(
        request,
        "asset_created",
        user,
        db,
        resource_type="asset",
        resource_id=str(asset.id),
        details={"source": "manual"},
    )
    await db.commit()
    return {"id": str(asset.id), "risk_score": risk.score, "risk_tier": risk.tier}
