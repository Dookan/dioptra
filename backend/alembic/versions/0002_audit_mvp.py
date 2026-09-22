"""Phase 1 audit MVP: projects, systems, analyses, findings, tool runs, raw outputs, SBOM, metrics.

Revision ID: 0002_audit_mvp
Revises: 0001_foundations
Create Date: 2026-09-21
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0002_audit_mvp"
down_revision = "0001_foundations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_projects_name"), "projects", ["name"], unique=True)
    op.create_table(
        "analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column(
            "source_kind",
            sa.Enum("ZIP", "GIT", name="sourcekind", native_enum=False, length=8),
            nullable=False,
        ),
        sa.Column("source_ref", sa.String(length=512), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "RUNNING",
                "DONE",
                "FAILED",
                name="analysisstatus",
                native_enum=False,
                length=8,
            ),
            nullable=False,
        ),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("workspace_path", sa.String(length=512), nullable=True),
        sa.Column("languages", sa.JSON(), nullable=False),
        sa.Column("frameworks", sa.JSON(), nullable=False),
        sa.Column("lockfiles", sa.JSON(), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_analyses_project_id"), "analyses", ["project_id"], unique=False)
    op.create_index(op.f("ix_analyses_status"), "analyses", ["status"], unique=False)
    op.create_table(
        "systems",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("framework", sa.String(length=120), nullable=True),
        sa.Column("database", sa.String(length=120), nullable=True),
        sa.Column("developer", sa.String(length=200), nullable=True),
        sa.Column("installed_at", sa.String(length=40), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id"),
    )
    op.create_table(
        "code_metrics",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("functions", sa.JSON(), nullable=False),
        sa.Column("lines", sa.JSON(), nullable=False),
        sa.Column("commented_code_files", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column(
            "category",
            sa.Enum(
                "SAST",
                "SCA",
                "SECRET",
                "SBOM",
                "METRICS",
                name="toolcategory",
                native_enum=False,
                length=8,
            ),
            nullable=False,
        ),
        sa.Column("tools", sa.JSON(), nullable=False),
        sa.Column("rule_id", sa.String(length=200), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=True),
        sa.Column("owasp", sa.String(length=16), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFO",
                name="severity",
                native_enum=False,
                length=8,
            ),
            nullable=False,
        ),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=120), nullable=True),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("advisory", sa.JSON(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_analysis_id"), "findings", ["analysis_id"], unique=False)
    op.create_index(op.f("ix_findings_fingerprint"), "findings", ["fingerprint"], unique=False)
    op.create_table(
        "raw_tool_outputs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(length=40), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("output", sa.LargeBinary(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_raw_tool_outputs_analysis_id"), "raw_tool_outputs", ["analysis_id"], unique=False
    )
    op.create_table(
        "sboms",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("spec_version", sa.String(length=8), nullable=False),
        sa.Column("generator", sa.String(length=40), nullable=False),
        sa.Column("component_count", sa.Integer(), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id"),
    )
    op.create_table(
        "tool_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(length=40), nullable=False),
        sa.Column(
            "category",
            sa.Enum(
                "SAST",
                "SCA",
                "SECRET",
                "SBOM",
                "METRICS",
                name="toolcategory",
                native_enum=False,
                length=8,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "RAN",
                "FAILED",
                "MISSING",
                "TIMEOUT",
                name="toolstatus",
                native_enum=False,
                length=8,
            ),
            nullable=False,
        ),
        sa.Column("detail", sa.String(length=500), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tool_runs_analysis_id"), "tool_runs", ["analysis_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_tool_runs_analysis_id"), table_name="tool_runs")
    op.drop_table("tool_runs")
    op.drop_table("sboms")
    op.drop_index(op.f("ix_raw_tool_outputs_analysis_id"), table_name="raw_tool_outputs")
    op.drop_table("raw_tool_outputs")
    op.drop_index(op.f("ix_findings_fingerprint"), table_name="findings")
    op.drop_index(op.f("ix_findings_analysis_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_table("code_metrics")
    op.drop_table("systems")
    op.drop_index(op.f("ix_analyses_status"), table_name="analyses")
    op.drop_index(op.f("ix_analyses_project_id"), table_name="analyses")
    op.drop_table("analyses")
    op.drop_index(op.f("ix_projects_name"), table_name="projects")
    op.drop_table("projects")
