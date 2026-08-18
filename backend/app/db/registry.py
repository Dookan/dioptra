"""Model registry.

Single import point that pulls every mapped class into ``Base.metadata``.
Alembic and the test fixtures import this module and nothing else, so a new
table is never silently missing from a migration.
"""

from __future__ import annotations

from app.audit.models import AuditLogEntry
from app.auth.models import RefreshToken, User
from app.db.base import Base

__all__ = ["AuditLogEntry", "Base", "RefreshToken", "User"]
