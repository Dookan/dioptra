"""Phase 3 day 15: E5 cases and approval on the case design row.

Revision ID: 0006_case_briefs
Revises: 0005_case_designs
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0006_case_briefs"
down_revision = "0005_case_designs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "case_designs", sa.Column("cases", sa.JSON(), nullable=False, server_default="[]")
    )
    op.add_column("case_designs", sa.Column("brief", sa.JSON(), nullable=True))
    op.add_column(
        "case_designs", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "case_designs", sa.Column("approved_by_username", sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("case_designs", "approved_by_username")
    op.drop_column("case_designs", "approved_at")
    op.drop_column("case_designs", "brief")
    op.drop_column("case_designs", "cases")
