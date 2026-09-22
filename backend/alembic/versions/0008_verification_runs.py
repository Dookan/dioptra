"""Phase 4 day 17: the E7 verification runs.

Revision ID: 0008_verification_runs
Revises: 0007_test_files
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0008_verification_runs"
down_revision = "0007_test_files"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Uuid(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("function", sa.String(length=200), nullable=False),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("coverage", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("uncovered_items", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("surviving_mutants", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("assertion_free_cases", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("failed_cases", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by_username", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_verification_runs_analysis_id", "verification_runs", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_verification_runs_analysis_id", table_name="verification_runs")
    op.drop_table("verification_runs")
