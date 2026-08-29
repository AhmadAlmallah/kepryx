"""Export endpoints: CSV for inventory/CVEs/audit, PDF for compliance reports."""

import csv
import io
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_scope
from app.core.database import get_db
from app.models import Alert, Asset, AssetCVE, AuditLog

router = APIRouter()


def _csv_safe(value):
    """Prevent spreadsheet formula execution when exported CSV is opened."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def _stream_csv(headers: list, rows) -> StreamingResponse:
    """Generate CSV streaming response with proper headers."""

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
        for row in rows:
            writer.writerow([_csv_safe(value) for value in row])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()

    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="kepryx_export_{ts}.csv"'},
    )


@router.get(
    "/inventory.csv", dependencies=[Depends(require_scope("assets:read", "viewer", "analyst"))]
)
async def export_inventory(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=10000, ge=1, le=50000),
):
    """Export asset inventory as CSV."""
    result = await db.execute(
        select(Asset).options(selectinload(Asset.cves).selectinload(AssetCVE.cve)).limit(limit)
    )
    assets = result.scalars().all()

    headers = [
        "ID",
        "Name",
        "Type",
        "OS",
        "IP",
        "MAC",
        "Segment",
        "EDR Status",
        "Control Coverage",
        "Network Exposure",
        "Auth Method",
        "Criticality",
        "Data Classification",
        "Risk Score",
        "Risk Tier",
        "CVE Count",
        "KEV Count",
        "EOL",
        "Shadow IT",
        "Last Seen",
        "Sources",
    ]

    rows = []
    for a in assets:
        rows.append(
            [
                str(a.id),
                a.name,
                a.type,
                a.os or "",
                str(a.ip or ""),
                str(a.mac or ""),
                a.segment or "",
                a.edr_status or "",
                a.control_coverage,
                a.network_exposure,
                a.auth_method,
                a.criticality,
                a.data_classification,
                a.risk_score,
                a.risk_tier,
                sum(1 for link in a.cves if not link.suppressed and not link.remediated),
                sum(
                    1
                    for link in a.cves
                    if not link.suppressed and not link.remediated and link.cve.kev
                ),
                "YES" if a.eol_status else "no",
                "YES" if a.is_shadow else "no",
                a.last_seen.isoformat() if a.last_seen else "",
                ", ".join(a.sources or []),
            ]
        )
    return _stream_csv(headers, rows)


@router.get(
    "/alerts.csv", dependencies=[Depends(require_scope("alerts:read", "viewer", "analyst"))]
)
async def export_alerts(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=10000, ge=1, le=50000),
):
    """Export all alerts as CSV."""
    result = await db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(limit))
    alerts = result.scalars().all()
    headers = [
        "ID",
        "Created",
        "Severity",
        "Type",
        "Title",
        "Status",
        "Asset ID",
        "Resolved At",
        "Resolved By",
    ]
    rows = [
        [
            str(a.id),
            a.created_at.isoformat() if a.created_at else "",
            a.severity,
            a.alert_type,
            a.title,
            a.status,
            str(a.asset_id) if a.asset_id else "",
            a.resolved_at.isoformat() if a.resolved_at else "",
            a.resolved_by or "",
        ]
        for a in alerts
    ]
    return _stream_csv(headers, rows)


@router.get("/audit.csv", dependencies=[Depends(require_scope("audit:read", "analyst"))])
async def export_audit(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=10000, ge=1, le=50000),
):
    """Export audit log as CSV (last N entries)."""
    result = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit))
    entries = result.scalars().all()
    headers = [
        "Timestamp",
        "Username",
        "Action",
        "Resource Type",
        "Resource ID",
        "IP Address",
        "Severity",
        "User Agent",
    ]
    rows = [
        [
            a.timestamp.isoformat() if a.timestamp else "",
            a.username or "system",
            a.action,
            a.resource_type or "",
            a.resource_id or "",
            str(a.ip_address or ""),
            a.severity,
            (a.user_agent or "")[:200],
        ]
        for a in entries
    ]
    return _stream_csv(headers, rows)


@router.get(
    "/compliance.pdf", dependencies=[Depends(require_scope("compliance:read", "viewer", "analyst"))]
)
async def export_compliance_pdf(db: AsyncSession = Depends(get_db)):
    """Generate compliance audit PDF report.

    Uses reportlab for PDF generation. Includes per-framework compliance
    percentages, asset breakdown, control gap details.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return Response(
            content="reportlab not installed. Run: pip install reportlab==4.2.5",
            status_code=503,
            media_type="text/plain",
        )

    from sqlalchemy import func

    from app.models import (
        AssessmentEvidence,
        AssessmentResult,
        AssessmentRun,
        ComplianceMapping,
        EvidenceItem,
        FrameworkCatalog,
        FrameworkControl,
    )

    # Prefer the evidence-backed assessment run; retain the old mapping projection as a
    # fallback for installations that have not run the new audit worker yet.
    latest_run = (
        await db.execute(
            select(AssessmentRun)
            .where(AssessmentRun.status == "completed")
            .order_by(AssessmentRun.completed_at.desc().nulls_last())
            .limit(1)
        )
    ).scalar_one_or_none()
    summary: dict = {}
    trace_rows: Sequence[Any] = []
    evidence_linked = 0
    if latest_run:
        result = await db.execute(
            select(
                FrameworkCatalog.code,
                FrameworkCatalog.version,
                AssessmentResult.status,
                func.count(AssessmentResult.id).label("count"),
            )
            .join(FrameworkControl, FrameworkControl.catalog_id == FrameworkCatalog.id)
            .join(AssessmentResult, AssessmentResult.control_id == FrameworkControl.id)
            .where(AssessmentResult.run_id == latest_run.id)
            .group_by(FrameworkCatalog.code, FrameworkCatalog.version, AssessmentResult.status)
        )
        for row in result:
            values = summary.setdefault(
                row.code,
                {
                    "version": row.version,
                    "compliant": 0,
                    "partial": 0,
                    "gap": 0,
                    "exception": 0,
                    "not_applicable": 0,
                    "not_assessed": 0,
                },
            )
            values[row.status] = row.count
        evidence_linked = (
            await db.scalar(
                select(func.count(func.distinct(AssessmentEvidence.result_id)))
                .join(AssessmentResult, AssessmentResult.id == AssessmentEvidence.result_id)
                .where(AssessmentResult.run_id == latest_run.id)
            )
            or 0
        )
        trace_result = await db.execute(
            select(
                FrameworkCatalog.code,
                FrameworkControl.control_id,
                Asset.name,
                AssessmentResult.status,
                EvidenceItem.source_type,
                EvidenceItem.integrity_sha256,
            )
            .join(FrameworkControl, FrameworkControl.catalog_id == FrameworkCatalog.id)
            .join(AssessmentResult, AssessmentResult.control_id == FrameworkControl.id)
            .outerjoin(Asset, Asset.id == AssessmentResult.asset_id)
            .outerjoin(AssessmentEvidence, AssessmentEvidence.result_id == AssessmentResult.id)
            .outerjoin(EvidenceItem, EvidenceItem.id == AssessmentEvidence.evidence_id)
            .where(AssessmentResult.run_id == latest_run.id)
            .order_by(FrameworkCatalog.code, FrameworkControl.control_id, Asset.name)
            .limit(100)
        )
        trace_rows = trace_result.all()
    else:
        result = await db.execute(
            select(
                ComplianceMapping.framework,
                ComplianceMapping.status,
                func.count(ComplianceMapping.id).label("count"),
            ).group_by(ComplianceMapping.framework, ComplianceMapping.status)
        )
        for row in result:
            summary.setdefault(row.framework, {})[row.status] = row.count

    # Get asset count
    asset_result = await db.execute(select(func.count(Asset.id)))
    total_assets = asset_result.scalar() or 0

    # Build PDF
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=22,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=8,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=20,
    )
    elements = []

    # Header
    elements.append(Paragraph("Kepryx Compliance Audit Report", title_style))
    elements.append(
        Paragraph(
            f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} | "
            f"Total assets audited: {total_assets} | "
            f"Assessment run: {str(latest_run.id)[:12] if latest_run else 'legacy mapping'} | "
            f"Evidence linked: {evidence_linked}",
            subtitle_style,
        )
    )

    # Framework summary table
    elements.append(Paragraph("<b>Framework Compliance Summary</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.15 * inch))

    table_data = [["Framework", "Compliant", "Partial", "Gaps", "N/A", "Total", "Compliance %"]]
    for fw in sorted(summary.keys()):
        s = summary[fw]
        compliant = s.get("compliant", 0)
        partial = s.get("partial", 0)
        gap = s.get("gap", 0)
        na = s.get("not_applicable", s.get("na", 0))
        total = compliant + partial + gap + na + s.get("exception", 0) + s.get("not_assessed", 0)
        applicable = total - na
        pct = round(compliant / applicable * 100, 1) if applicable > 0 else 0
        table_data.append(
            [
                f"{fw.upper().replace('-', ' ')} v{s.get('version', 'legacy')}",
                str(compliant),
                str(partial),
                str(gap),
                str(na),
                str(total),
                f"{pct}%",
            ]
        )

    table = Table(
        table_data,
        colWidths=[
            1.8 * inch,
            0.75 * inch,
            0.75 * inch,
            0.65 * inch,
            0.65 * inch,
            0.65 * inch,
            1.0 * inch,
        ],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ]
        )
    )
    elements.append(table)
    elements.append(Spacer(1, 0.3 * inch))

    if latest_run:
        elements.append(Paragraph("Evidence Traceability (first 100 results)", styles["Heading2"]))
        elements.append(Spacer(1, 0.1 * inch))
        trace_data = [["Framework", "Control", "Asset", "Result", "Source", "SHA-256"]]
        for row in trace_rows:
            trace_data.append(
                [
                    f"{row.code} v{summary.get(row.code, {}).get('version', 'n/a')}",
                    row.control_id,
                    row.name or "organization scope",
                    row.status,
                    row.source_type or "unlinked",
                    (row.integrity_sha256 or "unavailable")[:16],
                ]
            )
        trace_table = Table(
            trace_data,
            repeatRows=1,
            colWidths=[1.05 * inch, 0.7 * inch, 1.55 * inch, 0.75 * inch, 0.95 * inch, 1.2 * inch],
        )
        trace_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ]
            )
        )
        elements.append(trace_table)
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(
            Paragraph(
                "Lineage: framework/version → control → assessment result → evidence observation. "
                "Hashes identify the exact observed JSON snapshot stored by Kepryx.",
                subtitle_style,
            )
        )

    # Per-framework asset detail
    elements.append(PageBreak())
    elements.append(Paragraph("<b>Risk Distribution</b>", styles["Heading2"]))
    elements.append(Spacer(1, 0.15 * inch))

    risk_result = await db.execute(
        select(Asset.risk_tier, func.count(Asset.id).label("count")).group_by(Asset.risk_tier)
    )
    risk_data = [["Risk Tier", "Asset Count", "Recommended SLA"]]
    sla_map = {
        "Critical": "7 days",
        "High": "30 days",
        "Medium": "90 days",
        "Low": "180 days",
        "Informational": "monitor only",
    }
    for risk_row in risk_result:
        risk_data.append(
            [
                risk_row.risk_tier or "Unknown",
                str(risk_row.count),
                sla_map.get(risk_row.risk_tier, "n/a"),
            ]
        )
    risk_table = Table(risk_data, colWidths=[2.0 * inch, 1.5 * inch, 2.0 * inch])
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ]
        )
    )
    elements.append(risk_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Footer
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#94a3b8"),
        alignment=1,
    )
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(
        Paragraph(
            "Generated by Kepryx - Asset Intelligence & Risk Platform | Apache 2.0",
            footer_style,
        )
    )

    doc.build(elements)
    buf.seek(0)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="kepryx_compliance_{ts}.pdf"'},
    )
