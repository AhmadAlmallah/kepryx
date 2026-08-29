"""Dashboard read models and evidence-backed inventory graph endpoints."""

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_scope
from app.core.database import get_db
from app.models import (
    CVE,
    Alert,
    Asset,
    AssetCVE,
    AuditLog,
    ComplianceMapping,
    Integration,
    Scan,
)
from app.models.self_security import DependencyFinding, PlatformDependency, SelfSecuritySettings

router = APIRouter()


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


async def _activity(db: AsyncSession, limit: int = 12) -> list[dict]:
    """Return intentionally redacted activity suitable for the shared dashboard."""
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.archived.is_(False))
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
    )
    return [
        {
            "id": str(item.id),
            "timestamp": _iso(item.timestamp),
            "action": item.action,
            "resource_type": item.resource_type,
            "resource_id": item.resource_id,
            "severity": item.severity,
        }
        for item in result.scalars().all()
    ]


@router.get("/overview", dependencies=[Depends(require_scope("assets:read", "viewer", "analyst"))])
async def dashboard_overview(db: AsyncSession = Depends(get_db)):
    """Return a stable, normalized read model for the operator dashboard."""
    total_assets = await db.scalar(select(func.count(Asset.id))) or 0
    critical_assets = (
        await db.scalar(select(func.count(Asset.id)).where(Asset.risk_tier == "Critical")) or 0
    )
    high_assets = (
        await db.scalar(select(func.count(Asset.id)).where(Asset.risk_tier == "High")) or 0
    )
    shadow_assets = (
        await db.scalar(select(func.count(Asset.id)).where(Asset.is_shadow.is_(True))) or 0
    )
    open_alerts = await db.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
    kev_cves = await db.scalar(select(func.count(CVE.id)).where(CVE.kev.is_(True))) or 0
    enabled_integrations = (
        await db.scalar(select(func.count(Integration.id)).where(Integration.enabled.is_(True)))
        or 0
    )

    latest_scan = (
        (await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(1))).scalars().first()
    )
    scan = {
        "id": str(latest_scan.id) if latest_scan else None,
        "type": latest_scan.scan_type if latest_scan else None,
        "target": latest_scan.target if latest_scan else None,
        "status": latest_scan.status if latest_scan else "never",
        "hosts_found": latest_scan.hosts_found if latest_scan else 0,
        "started_at": _iso(latest_scan.started_at) if latest_scan else None,
        "completed_at": _iso(latest_scan.completed_at) if latest_scan else None,
        "error": latest_scan.error if latest_scan else None,
    }

    self_settings = (
        await db.execute(select(SelfSecuritySettings).where(SelfSecuritySettings.id == 1))
    ).scalar_one_or_none()
    dependency_count = await db.scalar(select(func.count(PlatformDependency.id))) or 0
    dependency_findings = (
        await db.scalar(
            select(func.count(DependencyFinding.id)).where(DependencyFinding.suppressed.is_(False))
        )
        or 0
    )

    compliance_result = await db.execute(
        select(
            ComplianceMapping.framework,
            ComplianceMapping.status,
            func.count(ComplianceMapping.id),
        ).group_by(ComplianceMapping.framework, ComplianceMapping.status)
    )
    compliance: dict[str, dict[str, int | float]] = {}
    for framework, status, count in compliance_result.all():
        values = compliance.setdefault(
            framework,
            {"compliant": 0, "gap": 0, "na": 0, "unknown": 0},
        )
        values[status] = count
    for values in compliance.values():
        total = sum(values.values())
        values["total"] = total
        values["compliance_pct"] = (
            round((values.get("compliant", 0) / total) * 100, 2) if total else 0
        )

    alert_result = await db.execute(
        select(Alert).where(Alert.status == "open").order_by(Alert.created_at.desc()).limit(8)
    )
    alerts = [
        {
            "id": str(item.id),
            "type": item.alert_type,
            "severity": item.severity,
            "title": item.title,
            "asset_id": str(item.asset_id) if item.asset_id else None,
            "status": item.status,
            "created_at": _iso(item.created_at),
        }
        for item in alert_result.scalars().all()
    ]

    stale_cutoff = datetime.now(UTC) - timedelta(days=30)
    stale_assets = (
        await db.scalar(select(func.count(Asset.id)).where(Asset.last_seen < stale_cutoff)) or 0
    )
    eol_assets = (
        await db.scalar(select(func.count(Asset.id)).where(Asset.eol_status.is_(True))) or 0
    )

    return {
        "summary": {
            "total_assets": total_assets,
            "critical_assets": critical_assets,
            "high_assets": high_assets,
            "shadow_assets": shadow_assets,
            "open_alerts": open_alerts,
            "kev_cves": kev_cves,
            "enabled_integrations": enabled_integrations,
            "stale_assets": stale_assets,
            "eol_assets": eol_assets,
        },
        "scan": scan,
        "self_security": {
            "status": self_settings.last_scan_status if self_settings else "never",
            "last_successful_scan_at": _iso(self_settings.last_successful_scan_at)
            if self_settings
            else None,
            "packages_scanned": self_settings.packages_scanned if self_settings else 0,
            "findings": dependency_findings,
            "dependencies": dependency_count,
        },
        "compliance": compliance,
        "alerts": alerts,
        "activity": await _activity(db),
    }


@router.get(
    "/graph/inventory",
    dependencies=[Depends(require_scope("assets:read", "viewer", "analyst"))],
)
async def inventory_graph(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(250, ge=1, le=500),
    include_vulnerabilities: bool = True,
):
    """Return bounded, source-labelled relationships for the inventory graph."""
    asset_result = await db.execute(
        select(Asset).order_by(Asset.risk_score.desc(), Asset.last_seen.desc()).limit(limit)
    )
    assets = asset_result.scalars().all()
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()
    edge_ids: set[tuple[str, str, str]] = set()
    truncated = False

    def add_node(node_id: str, node_type: str, label: str, **extra: object) -> bool:
        nonlocal truncated
        if node_id in node_ids:
            return True
        if len(nodes) >= limit:
            truncated = True
            return False
        node_ids.add(node_id)
        nodes.append({"id": node_id, "type": node_type, "label": label, **extra})
        return True

    def add_edge(source: str, target: str, relation: str, **extra: object) -> None:
        if source not in node_ids or target not in node_ids:
            return
        key = (source, target, relation)
        if key in edge_ids:
            return
        edge_ids.add(key)
        edges.append({"source": source, "target": target, "relation": relation, **extra})

    asset_ids = [asset.id for asset in assets]
    for asset in assets:
        asset_id = f"asset:{asset.id}"
        if not add_node(
            asset_id,
            "asset",
            asset.name,
            risk_tier=asset.risk_tier,
            risk_score=asset.risk_score,
            status="shadow" if asset.is_shadow else "managed",
            segment=asset.segment,
            source_count=len(_as_list(asset.sources)),
            updated_at=_iso(asset.last_seen),
        ):
            break

        segment = asset.segment or "Unassigned"
        segment_id = f"segment:{segment}"
        if add_node(segment_id, "segment", segment):
            add_edge(
                asset_id,
                segment_id,
                "member_of",
                evidence_source="asset.segment",
                observed_at=_iso(asset.last_seen),
            )

        for source in _as_list(asset.sources)[:5]:
            source_label = str(source)[:96]
            source_id = f"source:{source_label}"
            if add_node(source_id, "source", source_label):
                add_edge(
                    asset_id,
                    source_id,
                    "reported_by",
                    evidence_source="asset.sources",
                    observed_at=_iso(asset.last_seen),
                )

        for dependency in _as_list(asset.dependencies)[:3]:
            dependency_label = str(dependency)[:128]
            dependency_id = f"dependency:{asset.id}:{dependency_label}"
            if add_node(dependency_id, "dependency", dependency_label):
                add_edge(
                    asset_id,
                    dependency_id,
                    "declares",
                    evidence_source="asset.dependencies",
                    observed_at=_iso(asset.last_seen),
                )

    if asset_ids and nodes:
        alert_result = await db.execute(
            select(Alert)
            .where(Alert.asset_id.in_(asset_ids), Alert.status == "open")
            .order_by(Alert.created_at.desc())
            .limit(limit * 2)
        )
        per_asset_alerts: defaultdict[object, int] = defaultdict(int)
        for alert in alert_result.scalars().all():
            if not alert.asset_id or per_asset_alerts[alert.asset_id] >= 2:
                continue
            alert_id = f"alert:{alert.id}"
            if add_node(
                alert_id,
                "alert",
                alert.title,
                severity=alert.severity,
                status=alert.status,
                updated_at=_iso(alert.created_at),
            ):
                add_edge(
                    f"asset:{alert.asset_id}",
                    alert_id,
                    "has_alert",
                    evidence_source="alerts",
                    observed_at=_iso(alert.created_at),
                )
                per_asset_alerts[alert.asset_id] += 1

        if include_vulnerabilities:
            cve_result = await db.execute(
                select(AssetCVE, CVE)
                .join(CVE, CVE.id == AssetCVE.cve_id)
                .where(AssetCVE.asset_id.in_(asset_ids))
                .order_by(
                    CVE.kev.desc(),
                    CVE.cvss_v3.desc().nulls_last(),
                    CVE.epss_score.desc().nulls_last(),
                )
                .limit(limit * 4)
            )
            per_asset_cves: defaultdict[object, int] = defaultdict(int)
            for asset_cve, cve in cve_result.all():
                if per_asset_cves[asset_cve.asset_id] >= 4:
                    continue
                cve_id = f"cve:{cve.id}"
                if add_node(
                    cve_id,
                    "cve",
                    cve.id,
                    cvss=cve.cvss_v3,
                    epss=cve.epss_score,
                    kev=cve.kev,
                    evidence_source="NVD/EPSS/KEV",
                    updated_at=_iso(cve.last_synced),
                ):
                    add_edge(
                        f"asset:{asset_cve.asset_id}",
                        cve_id,
                        "affected_by",
                        matched_cpe=asset_cve.matched_cpe,
                        evidence_source="NVD/EPSS/KEV",
                        observed_at=_iso(asset_cve.discovered_at),
                    )
                    per_asset_cves[asset_cve.asset_id] += 1

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "generated_at": datetime.now(UTC).isoformat(),
            "asset_count": len(assets),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "limit": limit,
            "truncated": truncated,
            "authoritative_sources": ["NVD", "EPSS", "CISA KEV", "OSV"],
        },
    }
