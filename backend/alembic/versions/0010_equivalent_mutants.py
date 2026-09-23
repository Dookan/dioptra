"""Phase 5 day 20: surviving mutants the developer marks as equivalent.

Revision ID: 0010_equivalent_mutants
Revises: 0009_inventory
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0010_equivalent_mutants"
down_revision = "0009_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "equivalent_mutants",
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
        sa.Column("mutant_id", sa.String(length=200), nullable=False),
        sa.Column("mutant", sa.String(length=400), nullable=False, server_default=""),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("created_by_username", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "analysis_id",
            "path",
            "function",
            "line",
            "mutant_id",
            name="uq_equivalent_mutant",
            postgresql_nulls_not_distinct=True,
        ),
    )
    op.create_index("ix_equivalent_mutants_analysis_id", "equivalent_mutants", ["analysis_id"])
    op.add_column(
        "verification_runs",
        sa.Column("equivalent_mutants", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("verification_runs", "equivalent_mutants")
    op.drop_index("ix_equivalent_mutants_analysis_id", table_name="equivalent_mutants")
    op.drop_table("equivalent_mutants")
