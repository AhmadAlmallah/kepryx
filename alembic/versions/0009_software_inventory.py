"""Add end-user software inventory, findings, and scan-run evidence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_software_inventory"
down_revision: str | Sequence[str] | None = "0008_integration_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid():
    return postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "software_solutions",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("environment", sa.String(64), nullable=False, server_default="production"),
        sa.Column("source", sa.String(64), nullable=False, server_default="manual_import"),
        sa.Column("last_scan_status", sa.String(32), nullable=False, server_default="never"),
        sa.Column("last_scan_error", sa.String(128), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_successful_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("vulnerable_component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_software_solutions_name", "software_solutions", ["name"], unique=True)

    op.create_table(
        "software_components",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("solution_id", _uuid(), sa.ForeignKey("software_solutions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", _uuid(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ecosystem", sa.String(64), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("normalized_name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("component_type", sa.String(32), nullable=False, server_default="library"),
        sa.Column("latest_version", sa.String(128), nullable=True),
        sa.Column("purl", sa.String(512), nullable=True),
        sa.Column("cpe", sa.String(512), nullable=True),
        sa.Column("direct", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("environment", sa.String(64), nullable=False, server_default="production"),
        sa.Column("source", sa.String(64), nullable=False, server_default="manual_import"),
        sa.Column("status", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_checked", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cve_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kev_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_cvss", sa.Float(), nullable=True),
        sa.Column("update_available", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("attrs", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_unique_constraint(
        "uq_software_component_identity",
        "software_components",
        ["solution_id", "ecosystem", "normalized_name", "version", "asset_id"],
    )
    op.create_index("ix_software_components_solution_status", "software_components", ["solution_id", "status"])
    op.create_index("ix_software_components_package", "software_components", ["ecosystem", "normalized_name"])

    op.create_table(
        "software_findings",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("component_id", _uuid(), sa.ForeignKey("software_components.id", ondelete="CASCADE"), nullable=False),
        sa.Column("advisory_id", sa.String(128), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("source", sa.String(32), nullable=False, server_default="OSV"),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("severity", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("fixed_version", sa.String(128), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("details", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_unique_constraint("uq_software_finding_advisory", "software_findings", ["component_id", "advisory_id"])
    op.create_index("ix_software_findings_component_status", "software_findings", ["component_id", "status"])
    op.create_index("ix_software_findings_cve_id", "software_findings", ["cve_id"])
    op.create_index("ix_software_findings_kev", "software_findings", ["kev"])
    op.create_index("ix_software_findings_severity", "software_findings", ["severity"])

    op.create_table(
        "software_scan_runs",
        sa.Column("id", _uuid(), primary_key=True),
        sa.Column("solution_id", _uuid(), sa.ForeignKey("software_solutions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("mode", sa.String(32), nullable=False, server_default="scheduled"),
        sa.Column("source", sa.String(64), nullable=False, server_default="OSV"),
        sa.Column("filename", sa.String(255), nullable=True),
        sa.Column("file_sha256", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("rows_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("components_upserted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("error", sa.String(128), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_software_scan_runs_solution_created", "software_scan_runs", ["solution_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_software_scan_runs_solution_created", table_name="software_scan_runs")
    op.drop_table("software_scan_runs")
    op.drop_index("ix_software_findings_severity", table_name="software_findings")
    op.drop_index("ix_software_findings_kev", table_name="software_findings")
    op.drop_index("ix_software_findings_cve_id", table_name="software_findings")
    op.drop_index("ix_software_findings_component_status", table_name="software_findings")
    op.drop_constraint("uq_software_finding_advisory", "software_findings", type_="unique")
    op.drop_table("software_findings")
    op.drop_index("ix_software_components_package", table_name="software_components")
    op.drop_index("ix_software_components_solution_status", table_name="software_components")
    op.drop_constraint("uq_software_component_identity", "software_components", type_="unique")
    op.drop_table("software_components")
    op.drop_index("ix_software_solutions_name", table_name="software_solutions")
    op.drop_table("software_solutions")
