"""report_jobs — the PDF export becomes asynchronous (phase 8).

A 516-page institutional PDF takes ~50 s to render, all of it WeasyPrint
(`tasks/phase8-survey.md` §1–§2). The render moves to the worker; this table
is the job a person watches from any screen.

The partial unique index is the "one PDF in flight per person" rule of
survey §7.1, held by the database so two concurrent requests cannot both pass
a read-then-insert check. PostgreSQL and SQLite both support the WHERE clause.

Revision ID: 0014_report_jobs
Revises: 0013_third_party_findings
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0014_report_jobs"
down_revision = "0013_third_party_findings"
branch_labels = None
depends_on = None

_IN_FLIGHT = sa.text("status IN ('queued', 'running')")


def upgrade() -> None:
    op.create_table(
        "report_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Uuid(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=True),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("requested_by_username", sa.String(length=64), nullable=False),
        sa.Column("requested_by_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("downloaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=True),
        sa.Column("detail", sa.String(length=200), nullable=True),
    )
    op.create_index("ix_report_jobs_analysis_id", "report_jobs", ["analysis_id"])
    op.create_index("ix_report_jobs_status_created", "report_jobs", ["status", "created_at"])
    op.create_index(
        "uq_report_jobs_one_in_flight",
        "report_jobs",
        ["requested_by_username"],
        unique=True,
        postgresql_where=_IN_FLIGHT,
        sqlite_where=_IN_FLIGHT,
    )


def downgrade() -> None:
    op.drop_index("uq_report_jobs_one_in_flight", table_name="report_jobs")
    op.drop_index("ix_report_jobs_status_created", table_name="report_jobs")
    op.drop_index("ix_report_jobs_analysis_id", table_name="report_jobs")
    op.drop_table("report_jobs")
