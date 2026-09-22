"""Model registry.

Single import point that pulls every mapped class into ``Base.metadata``.
Alembic and the test fixtures import this module and nothing else, so a new
table is never silently missing from a migration.
"""

from __future__ import annotations

from app.analysis.models import Analysis, CodeMetrics, Finding, RawToolOutput, Sbom, ToolRun
from app.audit.models import AuditLogEntry
from app.auth.models import RefreshToken, User
from app.db.base import Base
from app.projects.models import Project, System
from app.reports.models import ReportVersion

__all__ = [
    "Analysis",
    "AuditLogEntry",
    "Base",
    "CodeMetrics",
    "Finding",
    "Project",
    "RawToolOutput",
    "RefreshToken",
    "ReportVersion",
    "Sbom",
    "System",
    "ToolRun",
    "User",
]
