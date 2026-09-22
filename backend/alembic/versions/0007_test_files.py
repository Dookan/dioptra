"""Phase 4 day 16: the E6 test file, and the E7 → E5 reopen flag.

Revision ID: 0007_test_files
Revises: 0006_case_briefs
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0007_test_files"
down_revision = "0006_case_briefs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "case_designs", sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_table(
        "test_files",
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
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_by_username", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_test_files_analysis_id", "test_files", ["analysis_id"])
    # NULLS NOT DISTINCT on PostgreSQL, like uq_case_design_function: a row
    # whose Lizard line was missing still gets exactly one test file.
    kwargs = {}
    if op.get_bind().dialect.name == "postgresql":
        kwargs["postgresql_nulls_not_distinct"] = True
    op.create_unique_constraint(
        "uq_test_file_function",
        "test_files",
        ["analysis_id", "path", "function", "line"],
        **kwargs,
    )


def downgrade() -> None:
    op.drop_constraint("uq_test_file_function", "test_files", type_="unique")
    op.drop_index("ix_test_files_analysis_id", table_name="test_files")
    op.drop_table("test_files")
    op.drop_column("case_designs", "reopened_at")
