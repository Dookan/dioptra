"""Audit log table.

Append-only is enforced at the DATABASE level, not only in the repository
layer: an ORM mistake or a future migration script must not be able to rewrite
history (ASVS V7.1, threat model → Audit log / Repudiation).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import DDL, Enum, Index, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utc_now
from app.db.base import Base
from app.db.types import UtcDateTime


class AuditOutcome(StrEnum):
    OK = "ok"
    DENIED = "denied"
    ERROR = "error"


class AuditLogEntry(Base):
    """One recorded action. Rows are inserted and never touched again."""

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, index=True)

    # Stored as text, not a foreign key: the actor may be an unknown username
    # from a failed login, and the trail must survive account deletion.
    actor_username: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(default=None)
    actor_role: Mapped[str | None] = mapped_column(String(16), default=None)

    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(255), default=None)
    outcome: Mapped[AuditOutcome] = mapped_column(
        Enum(AuditOutcome, native_enum=False, length=8, validate_strings=True)
    )
    #: Required by policy for triage verdicts, gate approvals and report signing.
    justification: Mapped[str | None] = mapped_column(Text, default=None)
    source_ip: Mapped[str | None] = mapped_column(String(45), default=None)

    __table_args__ = (Index("ix_audit_log_actor_action", "actor_username", "action"),)


# SQLAlchemy ships DDL untyped; the strings below are static and never templated.
_PG_APPEND_ONLY = DDL(  # type: ignore[no-untyped-call]
    """
    CREATE OR REPLACE FUNCTION dioptra_audit_log_append_only() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'audit_log is append-only';
    END;
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER audit_log_append_only
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION dioptra_audit_log_append_only();

    -- TRUNCATE is statement-level and fires NO row trigger, so the rule above
    -- does not see it: `TRUNCATE audit_log` would erase the entire trail under
    -- the application's own role. Same function, statement-level timing.
    CREATE TRIGGER audit_log_no_truncate
        BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION dioptra_audit_log_append_only();
    """
)

# SQLite (test suite) has no stored procedures; RAISE(ABORT) is the equivalent.
_SQLITE_NO_UPDATE = DDL(  # type: ignore[no-untyped-call]
    "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
)
_SQLITE_NO_DELETE = DDL(  # type: ignore[no-untyped-call]
    "CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
)

event.listen(
    AuditLogEntry.__table__, "after_create", _PG_APPEND_ONLY.execute_if(dialect="postgresql")
)
event.listen(
    AuditLogEntry.__table__, "after_create", _SQLITE_NO_UPDATE.execute_if(dialect="sqlite")
)
event.listen(
    AuditLogEntry.__table__, "after_create", _SQLITE_NO_DELETE.execute_if(dialect="sqlite")
)
