"""Align software status indexes with the deployed ORM query paths."""

from collections.abc import Sequence

from alembic import op

revision: str = "0011_software_status_indexes"
down_revision: str | Sequence[str] | None = "0010_software_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_software_components_status", "software_components", ["status"])
    op.create_index("ix_software_findings_status", "software_findings", ["status"])
    op.create_index("ix_software_scan_runs_status", "software_scan_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_software_scan_runs_status", table_name="software_scan_runs")
    op.drop_index("ix_software_findings_status", table_name="software_findings")
    op.drop_index("ix_software_components_status", table_name="software_components")
