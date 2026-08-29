"""Reconcile security-sensitive schema drift.

Revision ID: 0005_foundation_remediation
Revises: 0004_retention
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_foundation_remediation"
down_revision = "0004_retention"
branch_labels = None
depends_on = None


def _column_names(inspector, table: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table)}


def _index_names(inspector, table: str) -> set[str]:
    return {index["name"] for index in inspector.get_indexes(table)}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    op.alter_column(
        "users",
        "mfa_secret",
        existing_type=sa.String(64),
        type_=sa.String(1024),
        existing_nullable=True,
    )
    from app.core.security import protect_mfa_secret

    legacy_mfa_rows = bind.execute(
        sa.text(
            "SELECT id, mfa_secret FROM users "
            "WHERE mfa_secret IS NOT NULL AND mfa_secret NOT LIKE 'v1:%'"
        )
    ).fetchall()
    for user_id, mfa_secret in legacy_mfa_rows:
        bind.execute(
            sa.text("UPDATE users SET mfa_secret = :secret WHERE id = :user_id"),
            {"secret": protect_mfa_secret(mfa_secret), "user_id": user_id},
        )

    settings_columns = _column_names(inspector, "self_security_settings")
    settings_additions = {
        "last_scan_status": sa.Column(
            "last_scan_status", sa.String(16), server_default="never", nullable=False
        ),
        "last_scan_error": sa.Column("last_scan_error", sa.Text(), nullable=True),
        "last_scan_at": sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        "last_successful_scan_at": sa.Column(
            "last_successful_scan_at", sa.DateTime(timezone=True), nullable=True
        ),
        "packages_scanned": sa.Column(
            "packages_scanned", sa.Integer(), server_default="0", nullable=False
        ),
    }
    for name, column in settings_additions.items():
        if name not in settings_columns:
            op.add_column("self_security_settings", column)

    audit_columns = _column_names(inspector, "audit_log")
    if "archived" not in audit_columns:
        op.add_column(
            "audit_log",
            sa.Column("archived", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        )
    # Pseudonymized values are not valid PostgreSQL INET literals.
    op.execute(
        "ALTER TABLE audit_log ALTER COLUMN ip_address TYPE VARCHAR(64) "
        "USING ip_address::text"
    )

    webhook_columns = _column_names(inspector, "webhooks")
    secure_columns = {
        "secret_hash": sa.Column("secret_hash", sa.String(256), nullable=True),
        "secret_prefix": sa.Column("secret_prefix", sa.String(16), nullable=True),
        "secret_encrypted": sa.Column("secret_encrypted", sa.String(1024), nullable=True),
        "secret_salt": sa.Column("secret_salt", sa.String(64), nullable=True),
    }
    for name, column in secure_columns.items():
        if name not in webhook_columns:
            op.add_column("webhooks", column)

    # Legacy plaintext secrets cannot be safely transformed inside a schema
    # migration. Disable affected webhooks and require explicit secret rotation.
    op.execute(
        "UPDATE webhooks SET "
        "secret_hash = COALESCE(secret_hash, 'rotation_required'), "
        "secret_prefix = COALESCE(secret_prefix, 'rotate'), "
        "secret_encrypted = COALESCE(secret_encrypted, 'rotation_required'), "
        "secret_salt = COALESCE(secret_salt, 'rotation_required'), "
        "enabled = false "
        "WHERE secret_hash IS NULL OR secret_encrypted IS NULL OR secret_salt IS NULL"
    )
    for name in secure_columns:
        op.alter_column("webhooks", name, nullable=False)

    if "secret" in webhook_columns:
        op.drop_column("webhooks", "secret")

    # Remove legacy plaintext connector credentials. Integrations are disabled
    # until an administrator rotates credentials through the encrypted API.
    op.execute(
        "UPDATE integrations SET enabled = false, last_status = 'rotation_required', "
        "config = config - ARRAY['client_secret','access_key','secret_key',"
        "'bind_password','access_key_id','secret_access_key','username','password'] "
        "WHERE "
        "(config ? 'client_secret' AND jsonb_typeof(config->'client_secret') <> 'object') OR "
        "(config ? 'access_key' AND jsonb_typeof(config->'access_key') <> 'object') OR "
        "(config ? 'secret_key' AND jsonb_typeof(config->'secret_key') <> 'object') OR "
        "(config ? 'bind_password' AND jsonb_typeof(config->'bind_password') <> 'object') OR "
        "(config ? 'access_key_id' AND jsonb_typeof(config->'access_key_id') <> 'object') OR "
        "(config ? 'secret_access_key' AND jsonb_typeof(config->'secret_access_key') <> 'object') OR "
        "(config ? 'username' AND jsonb_typeof(config->'username') <> 'object') OR "
        "(config ? 'password' AND jsonb_typeof(config->'password') <> 'object')"
    )

    inspector = sa.inspect(bind)
    if "ix_webhooks_secret_prefix" not in _index_names(inspector, "webhooks"):
        op.create_index("ix_webhooks_secret_prefix", "webhooks", ["secret_prefix"])
    if "ix_asset_cves_cve_id" not in _index_names(inspector, "asset_cves"):
        op.create_index("ix_asset_cves_cve_id", "asset_cves", ["cve_id"])
    if "ix_dependency_findings_severity" not in _index_names(
        inspector, "dependency_findings"
    ):
        op.create_index(
            "ix_dependency_findings_severity", "dependency_findings", ["severity"]
        )
    unique_names = {
        item["name"] for item in inspector.get_unique_constraints("dependency_findings")
    }
    if "uq_dependency_findings_dep_cve" not in unique_names:
        op.execute(
            "DELETE FROM dependency_findings duplicate USING dependency_findings keeper "
            "WHERE duplicate.dependency_id = keeper.dependency_id "
            "AND duplicate.cve_id = keeper.cve_id AND duplicate.ctid > keeper.ctid"
        )
        op.create_unique_constraint(
            "uq_dependency_findings_dep_cve",
            "dependency_findings",
            ["dependency_id", "cve_id"],
        )


def downgrade():
    raise RuntimeError(
        "0005 removes legacy plaintext webhook secrets and cannot be safely downgraded"
    )
