"""Align ORM nullability and indexes with the deployed PostgreSQL schema.

Revision ID: 0006_schema_alignment
Revises: 0005_foundation_remediation
"""

from collections.abc import Mapping, Sequence

from alembic import op

revision: str = "0006_schema_alignment"
down_revision: str | Sequence[str] | None = "0005_foundation_remediation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Values are trusted SQL literals, not user input. Existing NULLs are repaired before
# constraints are tightened so upgrades remain safe for installations created by v0.9.
REQUIRED_COLUMNS: Mapping[str, Mapping[str, str]] = {
    "alerts": {
        "details": "'{}'::jsonb",
        "status": "'open'",
        "notified": "false",
        "notification_channels": "'[]'::jsonb",
        "created_at": "now()",
    },
    "api_tokens": {
        "scopes": "'[]'::jsonb",
        "created_by": "'legacy_migration'",
        "created_at": "now()",
        "revoked": "false",
        "usage_count": "0",
    },
    "asset_cves": {
        "discovered_at": "now()",
        "suppressed": "false",
        "remediated": "false",
    },
    "assets": {
        "control_coverage": "'none'",
        "network_exposure": "'internal'",
        "auth_method": "'password'",
        "criticality": "'medium'",
        "data_classification": "'Internal'",
        "dependencies": "'[]'::jsonb",
        "software_stack": "'[]'::jsonb",
        "cpe": "'[]'::jsonb",
        "eol_status": "false",
        "risk_score": "0",
        "risk_tier": "'Informational'",
        "risk_breakdown": "'{}'::jsonb",
        "sources": "'[]'::jsonb",
        "first_seen": "now()",
        "last_seen": "now()",
        "is_shadow": "false",
        "is_stale": "false",
        "tags": "'[]'::jsonb",
        "attrs": "'{}'::jsonb",
    },
    "audit_log": {
        "timestamp": "now()",
        "severity": "'info'",
        "details": "'{}'::jsonb",
    },
    "compliance_mappings": {
        "status": "'unknown'",
        "evidence": "'{}'::jsonb",
        "assessed_at": "now()",
    },
    "cves": {
        "kev": "false",
        "affected_cpes": "'[]'::jsonb",
        "last_synced": "now()",
    },
    "dependency_findings": {
        "kev": "false",
        "severity": "'medium'",
        "discovered_at": "now()",
        "suppressed": "false",
    },
    "integrations": {
        "enabled": "false",
        "config": "'{}'::jsonb",
        "schedule_cron": "'0 */6 * * *'",
        "assets_reported": "0",
        "priority": "5",
        "failure_count": "0",
        "created_at": "now()",
    },
    "platform_dependencies": {
        "direct": "true",
        "last_checked": "now()",
        "cve_count": "0",
        "kev_count": "0",
        "update_available": "false",
    },
    "scan_networks": {
        "enabled": "true",
        "scan_type": "'discovery'",
        "excluded_ips": "'[]'::jsonb",
        "created_at": "now()",
    },
    "scans": {
        "status": "'pending'",
        "hosts_found": "0",
        "triggered_by": "'scheduler'",
        "created_at": "now()",
    },
    "self_security_settings": {
        "auto_scan_enabled": "true",
        "scan_cron": "'0 1 * * *'",
        "auto_update_enabled": "false",
        "auto_update_severity_threshold": "'critical'",
        "auto_update_only_patch": "true",
        "auto_update_only_kev": "true",
        "require_ai_validation": "true",
        "require_admin_approval": "true",
        "auto_rollback_on_failure": "true",
        "notify_channels": "'[\"slack\", \"email\"]'::jsonb",
        "ai_model": "'claude-sonnet-4-20250514'",
        "excluded_packages": "'[]'::jsonb",
        "last_scan_status": "'never'",
        "packages_scanned": "0",
        "updated_at": "now()",
    },
    "update_proposals": {
        "cves_fixed": "'[]'::jsonb",
        "ai_assessment": "'{}'::jsonb",
        "breaking_changes_detected": "false",
        "status": "'proposed'",
        "rollback_snapshot": "'{}'::jsonb",
        "created_at": "now()",
    },
    "users": {"created_at": "now()"},
    "webhooks": {
        "event_types": "'[]'::jsonb",
        "severity_filter": "'[]'::jsonb",
        "enabled": "false",
        "created_at": "now()",
        "delivery_count": "0",
        "failure_count": "0",
    },
}


def upgrade() -> None:
    for table, columns in REQUIRED_COLUMNS.items():
        for column, fallback in columns.items():
            op.execute(
                f'UPDATE "{table}" SET "{column}" = {fallback} WHERE "{column}" IS NULL'  # noqa: S608 - table, column, and fallback are trusted migration constants
            )
            op.alter_column(table, column, nullable=False)

    op.create_index("ix_assets_risk_score", "assets", ["risk_score"], if_not_exists=True)
    op.create_index("ix_assets_risk_tier", "assets", ["risk_tier"], if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_assets_risk_tier", table_name="assets", if_exists=True)
    op.drop_index("ix_assets_risk_score", table_name="assets", if_exists=True)
    for table, columns in reversed(REQUIRED_COLUMNS.items()):
        for column in columns:
            op.alter_column(table, column, nullable=True)
