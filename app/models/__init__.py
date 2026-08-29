"""SQLAlchemy ORM models."""

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
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(32), default="viewer")  # admin, analyst, viewer
    mfa_secret: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_users_username", "username"),
        Index("ix_users_email", "email"),
    )


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True, index=True)
    mac: Mapped[str | None] = mapped_column(MACADDR, nullable=True, index=True)
    segment: Mapped[str | None] = mapped_column(String(64), index=True)
    edr_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    control_coverage: Mapped[str] = mapped_column(String(16), default="none")
    network_exposure: Mapped[str] = mapped_column(String(32), default="internal")
    auth_method: Mapped[str] = mapped_column(String(32), default="password")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    data_classification: Mapped[str] = mapped_column(String(32), default="Internal")
    dependencies: Mapped[list] = mapped_column(JSONB, default=list)
    software_stack: Mapped[list] = mapped_column(JSONB, default=list)
    cpe: Mapped[list] = mapped_column(JSONB, default=list)
    last_patch: Mapped[str | None] = mapped_column(String(32), nullable=True)
    eol_status: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_tier: Mapped[str] = mapped_column(String(16), default="Informational", index=True)
    risk_breakdown: Mapped[dict] = mapped_column(JSONB, default=dict)
    sources: Mapped[list] = mapped_column(JSONB, default=list)  # which feeds reported this asset
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    is_shadow: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_stale: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    attrs: Mapped[dict] = mapped_column("attrs", JSONB, default=dict)

    cves: Mapped[list["AssetCVE"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_assets_risk_tier_score", "risk_tier", "risk_score"),
        Index("ix_assets_segment_criticality", "segment", "criticality"),
    )


class CVE(Base):
    """Master CVE record — synced daily from NVD."""

    __tablename__ = "cves"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # CVE-YYYY-NNNNN
    cvss_v3: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_cpes: Mapped[list] = mapped_column(JSONB, default=list)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_synced: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (Index("ix_cves_epss", "epss_score"),)


class AssetCVE(Base):
    """Junction: asset ↔ cve."""

    __tablename__ = "asset_cves"
    asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), ForeignKey("cves.id"), primary_key=True)
    matched_cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    remediated: Mapped[bool] = mapped_column(Boolean, default=False)
    asset: Mapped["Asset"] = relationship(back_populates="cves")
    cve: Mapped["CVE"] = relationship()

    __table_args__ = (Index("ix_asset_cves_cve_id", "cve_id"),)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_type: Mapped[str] = mapped_column(String(32))  # discovery, port, vuln
    target: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(64), default="scheduler")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    alert_type: Mapped[str] = mapped_column(
        String(64)
    )  # shadow_it, kev_exposed, edr_dropped, drift, eol
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    asset_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)
    notification_channels: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (Index("ix_alerts_type", "alert_type"),)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    user_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        Index("ix_audit_timestamp", "timestamp"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_log_archived_timestamp", "archived", "timestamp"),
    )


class APIToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    scopes: Mapped[list] = mapped_column(JSONB, default=list)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (Index("ix_api_tokens_prefix", "token_prefix"),)


class Webhook(Base):
    __tablename__ = "webhooks"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    secret_prefix: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    secret_encrypted: Mapped[str] = mapped_column(String(1024), nullable=False)
    secret_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    event_types: Mapped[list] = mapped_column(JSONB, default=list)
    severity_filter: Mapped[list] = mapped_column(JSONB, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_delivery: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivery_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Integration(Base):
    """Configured data source connector."""

    __tablename__ = "integrations"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    connector_type: Mapped[str] = mapped_column(
        String(32)
    )  # ad, dhcp, edr_crowdstrike, nessus, aws, ...
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)  # endpoints, encrypted secrets
    schedule_cron: Mapped[str] = mapped_column(String(64), default="0 */6 * * *")
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    assets_reported: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=5)  # higher = more authoritative
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanNetwork(Base):
    """Networks to scan."""

    __tablename__ = "scan_networks"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    scan_type: Mapped[str] = mapped_column(String(32), default="discovery")
    excluded_ips: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ComplianceMapping(Base):
    """Asset → compliance control mappings."""

    __tablename__ = "compliance_mappings"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    framework: Mapped[str] = mapped_column(String(32))  # nist-800-53, cis-v8, iso-27001
    control_id: Mapped[str] = mapped_column(String(32))
    asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(
        String(16), default="unknown"
    )  # compliant, partial, gap, exception, not_assessed, not_applicable
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (Index("ix_compliance_framework_control", "framework", "control_id"),)


class FrameworkCatalog(Base):
    """Versioned metadata for a supported security/compliance framework."""

    __tablename__ = "framework_catalogs"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[dict] = mapped_column("metadata_json", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    controls: Mapped[list["FrameworkControl"]] = relationship(
        back_populates="catalog", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("code", "version", name="uq_framework_catalog_code_version"),
        Index("ix_framework_catalog_active", "active"),
    )


class FrameworkControl(Base):
    """Short, licensed-safe control metadata and the deterministic rule key."""

    __tablename__ = "framework_controls"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    catalog_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("framework_catalogs.id", ondelete="CASCADE")
    )
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False)
    assessment_method: Mapped[str] = mapped_column(String(64), default="asset_observation")
    evidence_requirements: Mapped[list] = mapped_column(JSONB, default=list)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    metadata_json: Mapped[dict] = mapped_column("metadata_json", JSONB, default=dict)

    catalog: Mapped["FrameworkCatalog"] = relationship(back_populates="controls")
    results: Mapped[list["AssessmentResult"]] = relationship(back_populates="control")

    __table_args__ = (
        UniqueConstraint("catalog_id", "control_id", name="uq_framework_control_catalog_id"),
        Index("ix_framework_controls_rule_key", "rule_key"),
    )


class AssessmentRun(Base):
    """Immutable-in-practice execution envelope for a compliance assessment."""

    __tablename__ = "assessment_runs"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    framework_code: Mapped[str] = mapped_column(String(64), nullable=False)
    framework_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    scope: Mapped[dict] = mapped_column(JSONB, default=dict)
    methodology: Mapped[dict] = mapped_column(JSONB, default=dict)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(64), default="scheduler")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    results: Mapped[list["AssessmentResult"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_assessment_runs_created_at", "created_at"),
        Index("ix_assessment_runs_framework", "framework_code", "framework_version"),
    )


class AssessmentResult(Base):
    """Deterministic control result tied to one run, control, and optional asset."""

    __tablename__ = "assessment_results"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="CASCADE")
    )
    control_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("framework_controls.id", ondelete="CASCADE")
    )
    asset_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(24), default="not_assessed", index=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    rationale: Mapped[str] = mapped_column(Text, default="")
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    run: Mapped["AssessmentRun"] = relationship(back_populates="results")
    control: Mapped["FrameworkControl"] = relationship(back_populates="results")
    asset: Mapped["Asset | None"] = relationship()
    evidence_links: Mapped[list["AssessmentEvidence"]] = relationship(
        back_populates="result", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_assessment_results_run_status", "run_id", "status"),
        Index("ix_assessment_results_asset_control", "asset_id", "control_id"),
        Index("ix_assessment_results_assessed_at", "assessed_at"),
    )


class EvidenceItem(Base):
    """A bounded evidence observation with a reproducible content hash."""

    __tablename__ = "evidence_items"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    observed: Mapped[dict] = mapped_column(JSONB, default=dict)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    integrity_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    collector: Mapped[str] = mapped_column(String(128), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), default="internal")
    metadata_json: Mapped[dict] = mapped_column("metadata_json", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    result_links: Mapped[list["AssessmentEvidence"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_evidence_source_ref", "source_type", "source_ref"),
        Index("ix_evidence_observed_at", "observed_at"),
    )


class AssessmentEvidence(Base):
    """Many-to-many lineage edge between an assessment result and evidence."""

    __tablename__ = "assessment_evidence"
    result_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("assessment_results.id", ondelete="CASCADE"),
        primary_key=True,
    )
    evidence_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("evidence_items.id", ondelete="CASCADE"), primary_key=True
    )
    relation: Mapped[str] = mapped_column(String(32), default="supports")
    role: Mapped[str] = mapped_column(String(32), default="primary")
    extracted_by: Mapped[str] = mapped_column(String(64), default="deterministic_rule")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    result: Mapped["AssessmentResult"] = relationship(back_populates="evidence_links")
    evidence: Mapped["EvidenceItem"] = relationship(back_populates="result_links")

    __table_args__ = (Index("ix_assessment_evidence_evidence_id", "evidence_id"),)


# Re-export self-security models so Alembic discovers them via Base.metadata
from app.models.self_security import (  # noqa: E402, F401
    DependencyFinding,
    PlatformDependency,
    SelfSecuritySettings,
    UpdateProposal,
)
