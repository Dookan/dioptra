"""analyses.current_step — what the worker is doing right now (phase 10).

A 1 GiB archive makes the pipeline minutes long (8 min 19 s on the phase-10
walk), and the screen could only say "en curso". The worker now writes the step
it is on — the acquisition, each tool, the normalisation — and commits each
tool's row as soon as it finishes, so the project screen can say "paso 3 de 8,
Semgrep". NULL whenever nothing runs. No backfill: a finished analysis has no
current step.

Revision ID: 0015_analysis_progress
Revises: 0014_report_jobs
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0015_analysis_progress"
down_revision = "0014_report_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analyses", sa.Column("current_step", sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("analyses") as batch:
        batch.drop_column("current_step")
