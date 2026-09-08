"""Software inventory models.

These tables describe software observed in a customer environment.  They are
intentionally separate from ``self_security`` which describes Kepryx's own
runtime dependencies.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base

if TYPE_CHECKING:
    from app.models import Asset


class SoftwareSolution(Base):
    __tablename__ = "software_solutions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str] = mapped_column(String(64), default="production")
    source: Mapped[str] = mapped_column(String(64), default="manual_import")
    last_scan_status: Mapped[str] = mapped_column(String(32), default="never")
    last_scan_error: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_successful_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_component_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    components: Mapped[list["SoftwareComponent"]] = relationship(
        back_populates="solution", cascade="all, delete-orphan"
    )


class SoftwareComponent(Base):
    __tablename__ = "software_components"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    solution_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("software_solutions.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    component_type: Mapped[str] = mapped_column(String(32), default="library")
    latest_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)
    direct: Mapped[bool] = mapped_column(default=True)
    environment: Mapped[str] = mapped_column(String(64), default="production")
    source: Mapped[str] = mapped_column(String(64), default="manual_import")
    status: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    scan_error: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    kev_count: Mapped[int] = mapped_column(Integer, default=0)
    max_cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    update_available: Mapped[bool] = mapped_column(default=False)
    attrs: Mapped[dict] = mapped_column(JSONB, default=dict)

    solution: Mapped["SoftwareSolution"] = relationship(back_populates="components")
    asset: Mapped["Asset | None"] = relationship()
    findings: Mapped[list["SoftwareFinding"]] = relationship(
        back_populates="component", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "solution_id",
            "ecosystem",
            "normalized_name",
            "version",
            "asset_id",
            name="uq_software_component_identity",
        ),
        Index("ix_software_components_solution_status", "solution_id", "status"),
        Index("ix_software_components_package", "ecosystem", "normalized_name"),
    )


class SoftwareFinding(Base):
    __tablename__ = "software_findings"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    component_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("software_components.id", ondelete="CASCADE"),
        nullable=False,
    )
    advisory_id: Mapped[str] = mapped_column(String(128), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(32), default="OSV")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(default=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    details: Mapped[dict] = mapped_column(JSONB, default=dict)

    component: Mapped["SoftwareComponent"] = relationship(back_populates="findings")

    __table_args__ = (
        UniqueConstraint("component_id", "advisory_id", name="uq_software_finding_advisory"),
        Index("ix_software_findings_component_status", "component_id", "status"),
    )


class SoftwareScanRun(Base):
    __tablename__ = "software_scan_runs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    solution_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("software_solutions.id", ondelete="SET NULL"),
        nullable=True,
    )
    mode: Mapped[str] = mapped_column(String(32), default="scheduled")
    source: Mapped[str] = mapped_column(String(64), default="OSV")
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    rows_seen: Mapped[int] = mapped_column(Integer, default=0)
    components_upserted: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSONB, default=list)
    warnings: Mapped[list] = mapped_column(JSONB, default=list)
    provider_status: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_software_scan_runs_solution_created", "solution_id", "created_at"),)
