"""Record redacted integration run timing and error classification."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_integration_runs"
down_revision: str | Sequence[str] | None = "0007_evidence_compliance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("integrations", sa.Column("last_error_code", sa.String(64), nullable=True))
    op.add_column("integrations", sa.Column("last_duration_ms", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("integrations", "last_duration_ms")
    op.drop_column("integrations", "last_error_code")
