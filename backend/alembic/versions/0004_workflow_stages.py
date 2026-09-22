"""Phase 3 workflow: analysis stage, E4 test plans.

Revision ID: 0004_workflow_stages
Revises: 0003_findings_ui
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004_workflow_stages"
down_revision = "0003_findings_ui"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analyses",
        sa.Column(
            "stage",
            sa.Enum(
                "REGISTER",
                "CODE",
                "ANALYSIS",
                "PLAN",
                "DESIGN",
                "TESTS",
                "VERIFICATION",
                "REPORT",
                name="stage",
                native_enum=False,
                length=12,
            ),
            nullable=False,
            server_default="CODE",
        ),
    )
    op.create_index(op.f("ix_analyses_stage"), "analyses", ["stage"], unique=False)
    op.create_table(
        "test_plans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column(
            "criterion",
            sa.Enum(
                "STATEMENTS",
                "DECISIONS",
                "PATHS",
                name="coveragecriterion",
                native_enum=False,
                length=12,
            ),
            nullable=False,
        ),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("functions", sa.JSON(), nullable=False),
        sa.Column("created_by_username", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id"),
    )


def downgrade() -> None:
    op.drop_table("test_plans")
    op.drop_index(op.f("ix_analyses_stage"), table_name="analyses")
    op.drop_column("analyses", "stage")
