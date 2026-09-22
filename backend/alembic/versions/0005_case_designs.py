"""Phase 3 day 14: E5 case designs (the developer's diagram text per planned function).

Revision ID: 0005_case_designs
Revises: 0004_workflow_stages
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0005_case_designs"
down_revision = "0004_workflow_stages"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "case_designs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("function", sa.String(length=200), nullable=False),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("diagram_text", sa.Text(), nullable=True),
        sa.Column("created_by_username", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "analysis_id",
            "path",
            "function",
            "line",
            name="uq_case_design_function",
            postgresql_nulls_not_distinct=True,
        ),
    )
    op.create_index(
        op.f("ix_case_designs_analysis_id"), "case_designs", ["analysis_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_case_designs_analysis_id"), table_name="case_designs")
    op.drop_table("case_designs")
