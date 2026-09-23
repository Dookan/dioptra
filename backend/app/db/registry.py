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
from app.inventory.models import CryptoAsset, VulnDbSync, Vulnerability, VulnerabilityPackage
from app.projects.models import Project, System
from app.reports.models import ReportVersion
from app.workflow.models import CaseDesign, EquivalentMutant, TestPlan

__all__ = [
    "Analysis",
    "AuditLogEntry",
    "CaseDesign",
    "Base",
    "CodeMetrics",
    "CryptoAsset",
    "EquivalentMutant",
    "Finding",
    "Project",
    "RawToolOutput",
    "RefreshToken",
    "ReportVersion",
    "Sbom",
    "System",
    "TestPlan",
    "ToolRun",
    "User",
    "VulnDbSync",
    "Vulnerability",
    "VulnerabilityPackage",
]
