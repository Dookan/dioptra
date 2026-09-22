"""Phase 2 findings UI: triage verdicts on findings, versioned report snapshots.

Revision ID: 0003_findings_ui
Revises: 0002_audit_mvp
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003_findings_ui"
down_revision = "0002_audit_mvp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "verdict",
            sa.Enum("CONFIRMED", "FALSE_POSITIVE", name="verdict", native_enum=False, length=16),
            nullable=True,
        ),
    )
    op.add_column("findings", sa.Column("verdict_justification", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("verdict_by_username", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("verdict_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "report_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("sections", sa.JSON(), nullable=False),
        sa.Column("change_summary", sa.String(length=500), nullable=False),
        sa.Column("areas", sa.String(length=200), nullable=False),
        sa.Column("created_by_username", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signed_by_username", sa.String(length=64), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("excluded_findings", sa.JSON(), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id", "number", name="uq_report_version_number"),
    )
    op.create_index(
        op.f("ix_report_versions_analysis_id"), "report_versions", ["analysis_id"], unique=False
    )

    # A signed version is immutable at the database level, like the audit log:
    # signing is the analyst's attestation and nothing may rewrite it afterwards.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION dioptra_report_version_signed_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'a signed report version is immutable';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER report_version_signed_immutable
            BEFORE UPDATE OR DELETE ON report_versions
            FOR EACH ROW WHEN (OLD.signed_at IS NOT NULL)
            EXECUTE FUNCTION dioptra_report_version_signed_immutable();
        """
    )
    op.execute(
        # TRUNCATE fires no row trigger; the table may hold signed rows, so it
        # is refused outright, the same rule audit_log applies.
        """
        CREATE TRIGGER report_version_no_truncate
            BEFORE TRUNCATE ON report_versions
            FOR EACH STATEMENT EXECUTE FUNCTION dioptra_report_version_signed_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS report_version_no_truncate ON report_versions")
    op.execute("DROP TRIGGER IF EXISTS report_version_signed_immutable ON report_versions")
    op.execute("DROP FUNCTION IF EXISTS dioptra_report_version_signed_immutable()")
    op.drop_index(op.f("ix_report_versions_analysis_id"), table_name="report_versions")
    op.drop_table("report_versions")
    op.drop_column("findings", "verdict_at")
    op.drop_column("findings", "verdict_by_username")
    op.drop_column("findings", "verdict_justification")
    op.drop_column("findings", "verdict")
