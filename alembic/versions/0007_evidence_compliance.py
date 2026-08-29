"""Add versioned compliance catalogs, assessment runs, and evidence lineage.

The seed data contains identifiers and short engineering objectives only. Normative
framework text remains with the respective publishers and is not redistributed here.
"""

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0007_evidence_compliance"
down_revision: str | Sequence[str] | None = "0006_schema_alignment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


CATALOGS = (
    {
        "code": "cis-v8",
        "version": "8.1",
        "name": "CIS Controls",
        "source_url": "https://www.cisecurity.org/controls",
        "controls": (
            (
                "1.1",
                "Enterprise asset inventory",
                "Maintain a current record of enterprise assets.",
                "Inventory",
                "asset_inventory",
                ["name", "ip", "os"],
            ),
            (
                "2.1",
                "Software inventory",
                "Track software installed on enterprise assets.",
                "Inventory",
                "software_inventory",
                ["software_stack"],
            ),
            (
                "4.1",
                "Secure configuration",
                "Apply secure configuration and hardening controls.",
                "Configuration",
                "secure_configuration",
                ["control_coverage"],
            ),
            (
                "6.1",
                "Access control",
                "Use strong authentication for asset access.",
                "Access",
                "strong_authentication",
                ["auth_method"],
            ),
            (
                "7.1",
                "Vulnerability management",
                "Maintain evidence of vulnerability scanning and patching.",
                "Vulnerability",
                "vulnerability_management",
                ["last_patch"],
            ),
            (
                "10.1",
                "Malware defenses",
                "Deploy and monitor endpoint malware defenses.",
                "Defense",
                "endpoint_defense",
                ["edr_status"],
            ),
        ),
    },
    {
        "code": "nist-800-53",
        "version": "Rev. 5",
        "name": "NIST SP 800-53 Security and Privacy Controls",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "controls": (
            (
                "CM-8",
                "System component inventory",
                "Maintain an inventory of system components.",
                "Configuration Management",
                "system_component_inventory",
                ["name", "type", "os"],
            ),
            (
                "AC-2",
                "Account management",
                "Use strong authentication controls for accounts.",
                "Access Control",
                "account_management",
                ["auth_method"],
            ),
            (
                "SI-2",
                "Flaw remediation",
                "Track timely remediation and avoid end-of-life assets.",
                "System and Information Integrity",
                "flaw_remediation",
                ["last_patch", "eol_status"],
            ),
            (
                "SI-4",
                "System monitoring",
                "Deploy continuous monitoring on system components.",
                "System and Information Integrity",
                "system_monitoring",
                ["edr_status"],
            ),
        ),
    },
    {
        "code": "iso-27001",
        "version": "2022",
        "name": "ISO/IEC 27001 Information Security Management Systems",
        "source_url": "https://www.iso.org/standard/27001",
        "controls": (
            (
                "A.8.1",
                "Asset inventory",
                "Maintain an inventory of information assets.",
                "Technological controls",
                "asset_inventory",
                ["name", "type"],
            ),
            (
                "A.8.9",
                "Configuration management",
                "Manage and document secure configuration baselines.",
                "Technological controls",
                "configuration_management",
                ["control_coverage"],
            ),
            (
                "A.12.6",
                "Technical vulnerability management",
                "Identify and manage technical vulnerabilities.",
                "Operations security",
                "technical_vulnerability_management",
                ["last_patch"],
            ),
        ),
    },
)


def upgrade() -> None:
    op.create_table(
        "framework_catalogs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("source_url", sa.String(512), nullable=True),
        sa.Column("active", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("metadata_json", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("code", "version", name="uq_framework_catalog_code_version"),
    )
    op.create_index("ix_framework_catalog_active", "framework_catalogs", ["active"])

    op.create_table(
        "framework_controls",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "catalog_id",
            UUID(as_uuid=True),
            sa.ForeignKey("framework_catalogs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("objective", sa.Text, nullable=False),
        sa.Column("family", sa.String(128), nullable=True),
        sa.Column("rule_key", sa.String(64), nullable=False),
        sa.Column(
            "assessment_method", sa.String(64), server_default="asset_observation", nullable=False
        ),
        sa.Column(
            "evidence_requirements", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False
        ),
        sa.Column("sort_order", sa.Integer, server_default="0", nullable=False),
        sa.Column("metadata_json", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.UniqueConstraint("catalog_id", "control_id", name="uq_framework_control_catalog_id"),
    )
    op.create_index("ix_framework_controls_rule_key", "framework_controls", ["rule_key"])

    op.create_table(
        "assessment_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("framework_code", sa.String(64), nullable=False),
        sa.Column("framework_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), server_default="queued", nullable=False),
        sa.Column("scope", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("methodology", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("summary", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("initiated_by", sa.String(64), server_default="scheduler", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_assessment_runs_created_at", "assessment_runs", ["created_at"])
    op.create_index(
        "ix_assessment_runs_framework", "assessment_runs", ["framework_code", "framework_version"]
    )
    op.create_index("ix_assessment_runs_status", "assessment_runs", ["status"])

    op.create_table(
        "assessment_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "run_id",
            UUID(as_uuid=True),
            sa.ForeignKey("assessment_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "control_id",
            UUID(as_uuid=True),
            sa.ForeignKey("framework_controls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("status", sa.String(24), server_default="not_assessed", nullable=False),
        sa.Column("score", sa.Float, nullable=True),
        sa.Column("confidence", sa.Float, server_default="1", nullable=False),
        sa.Column("rationale", sa.Text, server_default="", nullable=False),
        sa.Column("rule_key", sa.String(64), nullable=False),
        sa.Column(
            "assessed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_assessment_results_run_status", "assessment_results", ["run_id", "status"])
    op.create_index("ix_assessment_results_status", "assessment_results", ["status"])
    op.create_index(
        "ix_assessment_results_asset_control", "assessment_results", ["asset_id", "control_id"]
    )
    op.create_index("ix_assessment_results_assessed_at", "assessment_results", ["assessed_at"])

    op.create_table(
        "evidence_items",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("source_ref", sa.String(255), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, server_default="", nullable=False),
        sa.Column("observed", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column(
            "captured_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("integrity_sha256", sa.String(64), nullable=False),
        sa.Column("collector", sa.String(128), nullable=False),
        sa.Column("classification", sa.String(32), server_default="internal", nullable=False),
        sa.Column("metadata_json", JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_evidence_source_ref", "evidence_items", ["source_type", "source_ref"])
    op.create_index("ix_evidence_observed_at", "evidence_items", ["observed_at"])

    op.create_table(
        "assessment_evidence",
        sa.Column(
            "result_id",
            UUID(as_uuid=True),
            sa.ForeignKey("assessment_results.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "evidence_id",
            UUID(as_uuid=True),
            sa.ForeignKey("evidence_items.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("relation", sa.String(32), server_default="supports", nullable=False),
        sa.Column("role", sa.String(32), server_default="primary", nullable=False),
        sa.Column(
            "extracted_by", sa.String(64), server_default="deterministic_rule", nullable=False
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_assessment_evidence_evidence_id", "assessment_evidence", ["evidence_id"])

    catalog_table = sa.table(
        "framework_catalogs",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("code", sa.String(64)),
        sa.column("version", sa.String(32)),
        sa.column("name", sa.String(128)),
        sa.column("source_url", sa.String(512)),
        sa.column("active", sa.Boolean),
        sa.column("metadata_json", JSONB),
    )
    control_table = sa.table(
        "framework_controls",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("catalog_id", UUID(as_uuid=True)),
        sa.column("control_id", sa.String(64)),
        sa.column("title", sa.String(255)),
        sa.column("objective", sa.Text),
        sa.column("family", sa.String(128)),
        sa.column("rule_key", sa.String(64)),
        sa.column("assessment_method", sa.String(64)),
        sa.column("evidence_requirements", JSONB),
        sa.column("sort_order", sa.Integer),
        sa.column("metadata_json", JSONB),
    )
    catalog_ids: dict[str, object] = {}
    catalog_rows = []
    control_rows = []
    for catalog in CATALOGS:
        catalog_id = uuid4()
        catalog_ids[catalog["code"]] = catalog_id
        catalog_rows.append(
            {
                "id": catalog_id,
                "code": catalog["code"],
                "version": catalog["version"],
                "name": catalog["name"],
                "source_url": catalog["source_url"],
                "active": True,
                "metadata_json": {"content_scope": "identifiers_and_engineering_objectives"},
            }
        )
        for sort_order, control in enumerate(catalog["controls"], start=1):
            control_rows.append(
                {
                    "id": uuid4(),
                    "catalog_id": catalog_id,
                    "control_id": control[0],
                    "title": control[1],
                    "objective": control[2],
                    "family": control[3],
                    "rule_key": control[4],
                    "assessment_method": "asset_observation",
                    "evidence_requirements": control[5],
                    "sort_order": sort_order,
                    "metadata_json": {},
                }
            )
    op.bulk_insert(catalog_table, catalog_rows)
    op.bulk_insert(control_table, control_rows)


def downgrade() -> None:
    op.drop_index("ix_assessment_evidence_evidence_id", table_name="assessment_evidence")
    op.drop_table("assessment_evidence")
    op.drop_index("ix_evidence_observed_at", table_name="evidence_items")
    op.drop_index("ix_evidence_source_ref", table_name="evidence_items")
    op.drop_table("evidence_items")
    op.drop_index("ix_assessment_results_assessed_at", table_name="assessment_results")
    op.drop_index("ix_assessment_results_asset_control", table_name="assessment_results")
    op.drop_index("ix_assessment_results_status", table_name="assessment_results")
    op.drop_index("ix_assessment_results_run_status", table_name="assessment_results")
    op.drop_table("assessment_results")
    op.drop_index("ix_assessment_runs_status", table_name="assessment_runs")
    op.drop_index("ix_assessment_runs_framework", table_name="assessment_runs")
    op.drop_index("ix_assessment_runs_created_at", table_name="assessment_runs")
    op.drop_table("assessment_runs")
    op.drop_index("ix_framework_controls_rule_key", table_name="framework_controls")
    op.drop_table("framework_controls")
    op.drop_index("ix_framework_catalog_active", table_name="framework_catalogs")
    op.drop_table("framework_catalogs")
