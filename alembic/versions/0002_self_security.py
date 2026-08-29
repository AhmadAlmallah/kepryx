"""Self-security tables

Revision ID: 0002_self_security
Revises: 0001_initial
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0002_self_security"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("platform_dependencies",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("component", sa.String(64), nullable=False),
        sa.Column("package_type", sa.String(16), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("latest_version", sa.String(64)),
        sa.Column("purl", sa.String(512)),
        sa.Column("license", sa.String(64)),
        sa.Column("direct", sa.Boolean, server_default=sa.text("true")),
        sa.Column("last_checked", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("cve_count", sa.Integer, server_default="0"),
        sa.Column("kev_count", sa.Integer, server_default="0"),
        sa.Column("max_cvss", sa.Float),
        sa.Column("update_available", sa.Boolean, server_default=sa.text("false")),
        sa.Column("update_blocked_reason", sa.String(255)),
    )
    op.create_index("ix_pdep_component", "platform_dependencies", ["component"])
    op.create_index("ix_pdep_name", "platform_dependencies", ["name"])
    op.create_index("ix_pdep_name_version", "platform_dependencies", ["name", "version"])

    op.create_table("dependency_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("dependency_id", UUID(as_uuid=True),
                  sa.ForeignKey("platform_dependencies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("cvss", sa.Float),
        sa.Column("epss", sa.Float),
        sa.Column("kev", sa.Boolean, server_default=sa.text("false")),
        sa.Column("description", sa.Text),
        sa.Column("fixed_version", sa.String(64)),
        sa.Column("severity", sa.String(16), server_default="medium"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("suppressed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("suppressed_reason", sa.String(255)),
        sa.Column("suppressed_by", sa.String(64)),
        sa.Column("suppressed_until", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("dependency_id", "cve_id", name="uq_dependency_findings_dep_cve"),
    )
    op.create_index("ix_dfind_cve", "dependency_findings", ["cve_id"])

    op.create_table("update_proposals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("dependency_id", UUID(as_uuid=True),
                  sa.ForeignKey("platform_dependencies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("component", sa.String(64), nullable=False),
        sa.Column("package_name", sa.String(128), nullable=False),
        sa.Column("current_version", sa.String(64), nullable=False),
        sa.Column("target_version", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("cves_fixed", JSONB, server_default="[]"),
        sa.Column("ai_assessment", JSONB, server_default="{}"),
        sa.Column("ai_recommendation", sa.String(32)),
        sa.Column("ai_risk_score", sa.Float),
        sa.Column("breaking_changes_detected", sa.Boolean, server_default=sa.text("false")),
        sa.Column("compatibility_notes", sa.Text),
        sa.Column("status", sa.String(32), server_default="proposed"),
        sa.Column("approved_by", sa.String(64)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.Column("rollback_snapshot", JSONB, server_default="{}"),
        sa.Column("error_message", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_uprop_status", "update_proposals", ["status"])

    op.create_table("self_security_settings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("auto_scan_enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("scan_cron", sa.String(64), server_default="0 1 * * *"),
        sa.Column("auto_update_enabled", sa.Boolean, server_default=sa.text("false")),
        sa.Column("auto_update_severity_threshold", sa.String(16), server_default="critical"),
        sa.Column("auto_update_only_patch", sa.Boolean, server_default=sa.text("true")),
        sa.Column("auto_update_only_kev", sa.Boolean, server_default=sa.text("true")),
        sa.Column("require_ai_validation", sa.Boolean, server_default=sa.text("true")),
        sa.Column("require_admin_approval", sa.Boolean, server_default=sa.text("true")),
        sa.Column("auto_rollback_on_failure", sa.Boolean, server_default=sa.text("true")),
        sa.Column("maintenance_window_cron", sa.String(64), server_default="0 2 * * 0"),
        sa.Column("notify_channels", JSONB, server_default='["slack", "email"]'),
        sa.Column("ai_model", sa.String(64), server_default="claude-sonnet-4-20250514"),
        sa.Column("excluded_packages", JSONB, server_default="[]"),
        sa.Column("last_scan_status", sa.String(16), server_default="never"),
        sa.Column("last_scan_error", sa.Text),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column("last_successful_scan_at", sa.DateTime(timezone=True)),
        sa.Column("packages_scanned", sa.Integer, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_by", sa.String(64)),
    )

    # Insert default settings row
    op.execute("INSERT INTO self_security_settings (id) VALUES (1) ON CONFLICT DO NOTHING")


def downgrade():
    op.drop_table("self_security_settings")
    op.drop_table("update_proposals")
    op.drop_table("dependency_findings")
    op.drop_table("platform_dependencies")
