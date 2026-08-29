"""Add api_tokens and webhooks tables

Revision ID: 0003_tokens_webhooks
Revises: 0002_self_security
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0003_tokens_webhooks"
down_revision = "0002_self_security"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("api_tokens",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("token_hash", sa.String(256), nullable=False),
        sa.Column("token_prefix", sa.String(16), nullable=False),
        sa.Column("scopes", JSONB, server_default="[]"),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used", sa.DateTime(timezone=True)),
        sa.Column("revoked", sa.Boolean, server_default=sa.text("false")),
        sa.Column("usage_count", sa.Integer, server_default="0"),
    )
    op.create_index("ix_api_tokens_prefix", "api_tokens", ["token_prefix"])

    op.create_table("webhooks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("url", sa.String(512), nullable=False),
        sa.Column("secret_hash", sa.String(256), nullable=False),
        sa.Column("secret_prefix", sa.String(16), nullable=False),
        sa.Column("secret_encrypted", sa.String(1024), nullable=False),
        sa.Column("secret_salt", sa.String(64), nullable=False),
        sa.Column("event_types", JSONB, server_default="[]"),
        sa.Column("severity_filter", JSONB, server_default="[]"),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_delivery", sa.DateTime(timezone=True)),
        sa.Column("delivery_count", sa.Integer, server_default="0"),
        sa.Column("failure_count", sa.Integer, server_default="0"),
        sa.Column("last_status", sa.String(32)),
    )
    op.create_index("ix_webhooks_secret_prefix", "webhooks", ["secret_prefix"])


def downgrade():
    op.drop_index("ix_webhooks_secret_prefix", table_name="webhooks")
    op.drop_table("webhooks")
    op.drop_table("api_tokens")
