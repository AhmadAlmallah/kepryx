"""Add archived column to audit_log for retention

Revision ID: 0004_retention
Revises: 0003_tokens_webhooks
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_retention"
down_revision = "0003_tokens_webhooks"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("audit_log",
        sa.Column("archived", sa.Boolean, server_default=sa.text("false"), nullable=False)
    )
    op.create_index("ix_audit_log_archived_timestamp", "audit_log", ["archived", "timestamp"])

    # M-10, M-11: Add missing indexes
    op.create_index("ix_asset_cves_cve_id", "asset_cves", ["cve_id"], if_not_exists=True)
    op.create_index("ix_dependency_findings_severity", "dependency_findings", ["severity"], if_not_exists=True)


def downgrade():
    op.drop_index("ix_audit_log_archived_timestamp")
    op.drop_column("audit_log", "archived")
    op.drop_index("ix_asset_cves_cve_id")
    op.drop_index("ix_dependency_findings_severity")
