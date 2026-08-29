"""Self-security models — platform dep tracking, CVE findings, update proposals."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class PlatformDependency(Base):
    """A package the platform itself depends on (Python lib or container image)."""

    __tablename__ = "platform_dependencies"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    component: Mapped[str] = mapped_column(String(64))  # api, worker, postgres-image, etc.
    package_type: Mapped[str] = mapped_column(String(16))  # pip, container, system
    name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(64))
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True)  # Package URL spec
    license: Mapped[str | None] = mapped_column(String(64), nullable=True)
    direct: Mapped[bool] = mapped_column(Boolean, default=True)  # vs transitive
    last_checked: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    cve_count: Mapped[int] = mapped_column(Integer, default=0)
    kev_count: Mapped[int] = mapped_column(Integer, default=0)
    max_cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    update_available: Mapped[bool] = mapped_column(Boolean, default=False)
    update_blocked_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    findings: Mapped[list["DependencyFinding"]] = relationship(
        back_populates="dependency", cascade="all, delete-orphan"
    )
    __table_args__ = (
        Index("ix_pdep_component", "component"),
        Index("ix_pdep_name", "name"),
        Index("ix_pdep_name_version", "name", "version"),
    )


class DependencyFinding(Base):
    """CVE matched to a platform dependency."""

    __tablename__ = "dependency_findings"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    dependency_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("platform_dependencies.id", ondelete="CASCADE")
    )
    cve_id: Mapped[str] = mapped_column(String(32))
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    suppressed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    suppressed_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    dependency: Mapped["PlatformDependency"] = relationship(back_populates="findings")
    __table_args__ = (
        Index("ix_dependency_findings_severity", "severity"),
        Index("ix_dfind_cve", "cve_id"),
        UniqueConstraint("dependency_id", "cve_id", name="uq_dependency_findings_dep_cve"),
    )


class UpdateProposal(Base):
    """A proposed dependency update awaiting AI validation + admin approval."""

    __tablename__ = "update_proposals"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    dependency_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("platform_dependencies.id", ondelete="CASCADE")
    )
    component: Mapped[str] = mapped_column(String(64))
    package_name: Mapped[str] = mapped_column(String(128))
    current_version: Mapped[str] = mapped_column(String(64))
    target_version: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(64))  # cve_fix, kev_fix, eol, manual
    cves_fixed: Mapped[list] = mapped_column(JSONB, default=list)

    # AI safety assessment
    ai_assessment: Mapped[dict] = mapped_column(JSONB, default=dict)
    ai_recommendation: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )  # approve|reject|manual_review
    ai_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0-10
    breaking_changes_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    compatibility_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Workflow state
    status: Mapped[str] = mapped_column(String(32), default="proposed")
    # proposed | ai_validated | approved | ready_for_pr | rejected | failed

    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_snapshot: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_uprop_status", "status"),)


class SelfSecuritySettings(Base):
    """Admin-tunable knobs for self-update behavior."""

    __tablename__ = "self_security_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    auto_scan_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_cron: Mapped[str] = mapped_column(String(64), default="0 1 * * *")
    auto_update_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_update_severity_threshold: Mapped[str] = mapped_column(String(16), default="critical")
    auto_update_only_patch: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_update_only_kev: Mapped[bool] = mapped_column(Boolean, default=True)
    require_ai_validation: Mapped[bool] = mapped_column(Boolean, default=True)
    require_admin_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_rollback_on_failure: Mapped[bool] = mapped_column(Boolean, default=True)
    maintenance_window_cron: Mapped[str | None] = mapped_column(String(64), default="0 2 * * 0")
    notify_channels: Mapped[list] = mapped_column(JSONB, default=lambda: ["slack", "email"])
    ai_model: Mapped[str] = mapped_column(String(64), default="claude-sonnet-4-20250514")
    excluded_packages: Mapped[list] = mapped_column(JSONB, default=list)
    last_scan_status: Mapped[str] = mapped_column(String(16), default="never")
    last_scan_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_successful_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    packages_scanned: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
