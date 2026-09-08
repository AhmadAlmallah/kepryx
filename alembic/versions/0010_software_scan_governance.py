"""Add software scan provenance, partial-failure, and finding resolution state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010_software_governance"
down_revision: str | Sequence[str] | None = "0009_software_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("software_components", sa.Column("scan_error", sa.String(128), nullable=True))

    op.add_column("software_findings", sa.Column("resolution_note", sa.Text(), nullable=True))
    op.add_column(
        "software_findings", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("software_findings", sa.Column("resolved_by", sa.String(64), nullable=True))

    op.add_column(
        "software_scan_runs",
        sa.Column(
            "warnings", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
    )
    op.add_column(
        "software_scan_runs",
        sa.Column(
            "provider_status",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("software_scan_runs", "provider_status")
    op.drop_column("software_scan_runs", "warnings")
    op.drop_column("software_findings", "resolved_by")
    op.drop_column("software_findings", "resolved_at")
    op.drop_column("software_findings", "resolution_note")
    op.drop_column("software_components", "scan_error")
