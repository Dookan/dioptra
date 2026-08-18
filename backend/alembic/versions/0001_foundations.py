"""Phase 0 baseline: users, refresh tokens, append-only audit log.

Revision ID: 0001_foundations
Revises:
Create Date: 2026-08-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0001_foundations"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("username", sa.String(length=32), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=True),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column(
            "role",
            sa.Enum("ADMIN", "ANALYST", "DEVELOPER", name="role", native_enum=False, length=16),
            nullable=False,
        ),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # `email` is unique but NOT indexed in the ORM, so it stays a constraint.
        # `username` is unique AND indexed, which SQLAlchemy renders as a single
        # UNIQUE INDEX — declaring a separate constraint here would drift from
        # Base.metadata (caught by `alembic check` in CI).
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_refresh_tokens_user_id", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_username", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_role", sa.String(length=16), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=True),
        sa.Column(
            "outcome",
            sa.Enum("OK", "DENIED", "ERROR", name="auditoutcome", native_enum=False, length=8),
            nullable=False,
        ),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
    )
    op.create_index("ix_audit_log_occurred_at", "audit_log", ["occurred_at"])
    op.create_index("ix_audit_log_actor_username", "audit_log", ["actor_username"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_actor_action", "audit_log", ["actor_username", "action"])

    # Append-only is a database guarantee, not a convention: an ORM mistake or a
    # future script must not be able to rewrite the trail (ASVS V7.1).
    op.execute(
        """
        CREATE OR REPLACE FUNCTION dioptra_audit_log_append_only() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_append_only
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION dioptra_audit_log_append_only();
        """
    )
    op.execute(
        # TRUNCATE is statement-level and fires no row trigger, so the rule above
        # never sees it: `TRUNCATE audit_log` would erase the whole trail under
        # the application's own role. Same function, statement-level timing.
        """
        CREATE TRIGGER audit_log_no_truncate
            BEFORE TRUNCATE ON audit_log
            FOR EACH STATEMENT EXECUTE FUNCTION dioptra_audit_log_append_only();
        """
    )


def downgrade() -> None:
    # BOTH triggers share one function, so both must go before it: PostgreSQL
    # refuses a non-CASCADE DROP FUNCTION while any trigger still depends on it,
    # which would abort the rollback the `migrations` CI job exists to prove.
    op.execute("DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS dioptra_audit_log_append_only();")
    op.drop_table("audit_log")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
