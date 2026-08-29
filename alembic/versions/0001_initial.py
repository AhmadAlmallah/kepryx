"""Initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, MACADDR

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(64), unique=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="viewer"),
        sa.Column("mfa_secret", sa.String(1024)),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("failed_attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("last_login", sa.DateTime(timezone=True)),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table("assets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("os", sa.String(255)),
        sa.Column("ip", INET),
        sa.Column("mac", MACADDR),
        sa.Column("segment", sa.String(64)),
        sa.Column("edr_status", sa.String(128)),
        sa.Column("control_coverage", sa.String(16), server_default="none"),
        sa.Column("network_exposure", sa.String(32), server_default="internal"),
        sa.Column("auth_method", sa.String(32), server_default="password"),
        sa.Column("criticality", sa.String(16), server_default="medium"),
        sa.Column("data_classification", sa.String(32), server_default="Internal"),
        sa.Column("dependencies", JSONB, server_default="[]"),
        sa.Column("software_stack", JSONB, server_default="[]"),
        sa.Column("cpe", JSONB, server_default="[]"),
        sa.Column("last_patch", sa.String(32)),
        sa.Column("eol_status", sa.Boolean, server_default=sa.text("false")),
        sa.Column("risk_score", sa.Float, server_default="0"),
        sa.Column("risk_tier", sa.String(16), server_default="Informational"),
        sa.Column("risk_breakdown", JSONB, server_default="{}"),
        sa.Column("sources", JSONB, server_default="[]"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("is_shadow", sa.Boolean, server_default=sa.text("false")),
        sa.Column("is_stale", sa.Boolean, server_default=sa.text("false")),
        sa.Column("tags", JSONB, server_default="[]"),
        sa.Column("attrs", JSONB, server_default="{}"),
    )
    op.create_index("ix_assets_name", "assets", ["name"])
    op.create_index("ix_assets_ip", "assets", ["ip"])
    op.create_index("ix_assets_mac", "assets", ["mac"])
    op.create_index("ix_assets_segment", "assets", ["segment"])
    op.create_index("ix_assets_type", "assets", ["type"])
    op.create_index("ix_assets_risk_tier_score", "assets", ["risk_tier", "risk_score"])
    op.create_index("ix_assets_segment_criticality", "assets", ["segment", "criticality"])
    op.create_index("ix_assets_is_shadow", "assets", ["is_shadow"])
    op.create_index("ix_assets_is_stale", "assets", ["is_stale"])

    op.create_table("cves",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("cvss_v3", sa.Float),
        sa.Column("cvss_vector", sa.String(128)),
        sa.Column("epss_score", sa.Float),
        sa.Column("epss_percentile", sa.Float),
        sa.Column("kev", sa.Boolean, server_default=sa.text("false")),
        sa.Column("kev_date_added", sa.DateTime(timezone=True)),
        sa.Column("description", sa.Text),
        sa.Column("affected_cpes", JSONB, server_default="[]"),
        sa.Column("published", sa.DateTime(timezone=True)),
        sa.Column("modified", sa.DateTime(timezone=True)),
        sa.Column("last_synced", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_cves_kev", "cves", ["kev"])
    op.create_index("ix_cves_epss", "cves", ["epss_score"])

    op.create_table("asset_cves",
        sa.Column("asset_id", UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("cve_id", sa.String(32), sa.ForeignKey("cves.id"), primary_key=True),
        sa.Column("matched_cpe", sa.String(512)),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("suppressed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("remediated", sa.Boolean, server_default=sa.text("false")),
    )

    op.create_table("scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_type", sa.String(32), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("hosts_found", sa.Integer, server_default="0"),
        sa.Column("raw_output", sa.Text),
        sa.Column("error", sa.Text),
        sa.Column("triggered_by", sa.String(64), server_default="scheduler"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("alerts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("asset_id", UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL")),
        sa.Column("details", JSONB, server_default="{}"),
        sa.Column("status", sa.String(16), server_default="open"),
        sa.Column("notified", sa.Boolean, server_default=sa.text("false")),
        sa.Column("notification_channels", JSONB, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_by", sa.String(64)),
    )
    op.create_index("ix_alerts_type", "alerts", ["alert_type"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    op.create_table("audit_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("user_id", UUID(as_uuid=True)),
        sa.Column("username", sa.String(64)),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64)),
        sa.Column("resource_id", sa.String(64)),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("user_agent", sa.String(512)),
        sa.Column("severity", sa.String(16), server_default="info"),
        sa.Column("details", JSONB, server_default="{}"),
    )
    op.create_index("ix_audit_timestamp", "audit_log", ["timestamp"])
    op.create_index("ix_audit_action", "audit_log", ["action"])

    op.create_table("integrations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(64), unique=True, nullable=False),
        sa.Column("connector_type", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("config", JSONB, server_default="{}"),
        sa.Column("schedule_cron", sa.String(64), server_default="0 */6 * * *"),
        sa.Column("last_run", sa.DateTime(timezone=True)),
        sa.Column("last_status", sa.String(32)),
        sa.Column("assets_reported", sa.Integer, server_default="0"),
        sa.Column("priority", sa.Integer, server_default="5"),
        sa.Column("failure_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("scan_networks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("cidr", sa.String(64), unique=True, nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("scan_type", sa.String(32), server_default="discovery"),
        sa.Column("excluded_ips", JSONB, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("compliance_mappings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("framework", sa.String(32), nullable=False),
        sa.Column("control_id", sa.String(32), nullable=False),
        sa.Column("asset_id", UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(16), server_default="unknown"),
        sa.Column("evidence", JSONB, server_default="{}"),
        sa.Column("assessed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_compliance_framework_control", "compliance_mappings", ["framework", "control_id"])

    # Partition audit log monthly (skip for SQLite/dev; manual partition setup for prod)


def downgrade():
    op.drop_table("compliance_mappings")
    op.drop_table("scan_networks")
    op.drop_table("integrations")
    op.drop_table("audit_log")
    op.drop_table("alerts")
    op.drop_table("scans")
    op.drop_table("asset_cves")
    op.drop_table("cves")
    op.drop_table("assets")
    op.drop_table("users")
