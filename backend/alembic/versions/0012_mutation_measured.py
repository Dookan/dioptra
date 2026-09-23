"""verification_runs.mutation_measured — the declared mutation gap (phase 7a).

Wave 2 brought a function the mutation tool can never touch: Infection only
mutates code declared INSIDE A CLASS, so a free PHP function yields no mutant
however good or bad the developer's tests are (measured 2026-09-23,
tasks/phase7a-php.md). "No survivor" must not read as "nothing survived", so
the run now records whether mutation could be measured at all.

Existing rows are backfilled to TRUE: every run before this migration was
JS/TS or Python, whose tools mutate free functions too.

Revision ID: 0012_mutation_measured
Revises: 0011_installed_at_date
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0012_mutation_measured"
down_revision = "0011_installed_at_date"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "verification_runs",
        sa.Column(
            "mutation_measured",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("verification_runs", "mutation_measured")
