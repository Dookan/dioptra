"""Phase 5 day 18: the software inventory — vulnerability mirror, sync log, CBOM rows.

Revision ID: 0009_inventory
Revises: 0008_verification_runs
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0009_inventory"
down_revision = "0008_verification_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("source", sa.String(length=8), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("vector", sa.String(length=120), nullable=True),
        sa.Column("severity", sa.String(length=8), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "vulnerability_packages",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.String(length=64),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ecosystem", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("versions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("ranges", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.create_index(
        "ix_vulnerability_packages_vulnerability_id",
        "vulnerability_packages",
        ["vulnerability_id"],
    )
    op.create_index(
        "ix_vulnerability_packages_ecosystem_name",
        "vulnerability_packages",
        ["ecosystem", "name"],
    )
    op.create_table(
        "vulndb_syncs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("source", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_stored", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_skipped", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detail", sa.String(length=500), nullable=True),
        sa.Column("requested_by_username", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_vulndb_syncs_started_at", "vulndb_syncs", ["started_at"])
    op.create_table(
        "crypto_assets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Uuid(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("primitive", sa.String(length=40), nullable=False),
        sa.Column("algorithm", sa.String(length=80), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("weak", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rule_id", sa.String(length=200), nullable=False),
    )
    op.create_index("ix_crypto_assets_analysis_id", "crypto_assets", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_crypto_assets_analysis_id", table_name="crypto_assets")
    op.drop_table("crypto_assets")
    op.drop_index("ix_vulndb_syncs_started_at", table_name="vulndb_syncs")
    op.drop_table("vulndb_syncs")
    op.drop_index("ix_vulnerability_packages_ecosystem_name", table_name="vulnerability_packages")
    op.drop_index("ix_vulnerability_packages_vulnerability_id", table_name="vulnerability_packages")
    op.drop_table("vulnerability_packages")
    op.drop_table("vulnerabilities")
