"""analyses: a CANCELLED status and the request the worker polls (phase 12).

``status`` is stored as the member NAME in ``VARCHAR(8)`` and ``CANCELLED`` is
nine characters: PostgreSQL would refuse it with a ``DataError`` while SQLite,
which the test suite runs on, would not notice (`tasks/phase12-survey.md`
§2.2). The column is widened to 16 — no CHECK constraint exists on it
(``native_enum=False`` without ``create_constraint``). ``cancel_requested_at``
is what a running pipeline polls to stop within seconds; NULL otherwise.

Downgrade: a cancelled analysis becomes FAILED ``analysis_cancelled`` before
the column narrows back, so no stored value is cut.

Revision ID: 0017_analysis_cancel
Revises: 0016_sca_third_party_correction
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0017_analysis_cancel"
down_revision = "0016_sca_third_party_correction"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analyses") as batch:
        batch.alter_column(
            "status",
            existing_type=sa.String(length=8),
            type_=sa.String(length=16),
            existing_nullable=False,
        )
        batch.add_column(
            sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    op.execute(
        "UPDATE analyses SET status = 'FAILED', failure_code = 'analysis_cancelled' "
        "WHERE status = 'CANCELLED'"
    )
    with op.batch_alter_table("analyses") as batch:
        batch.drop_column("cancel_requested_at")
        batch.alter_column(
            "status",
            existing_type=sa.String(length=16),
            type_=sa.String(length=8),
            existing_nullable=False,
        )
