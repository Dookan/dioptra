"""Report versions (stage E8).

Every save of the editor is a snapshot; signing locks one. Immutability of a
signed version is enforced at the DATABASE level, like the audit log: an ORM
mistake or a later migration must not be able to rewrite what an analyst
signed (docs/threat-model.md → Report editing).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DDL, JSON, ForeignKey, Integer, String, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.analysis.models import Analysis
from app.core.clock import utc_now
from app.db.base import Base
from app.db.types import UtcDateTime


class ReportVersion(Base):
    """One snapshot of the editable prose of the report of one analysis."""

    __tablename__ = "report_versions"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    #: 1 is the composed baseline; every human save is the next number.
    number: Mapped[int] = mapped_column(Integer)
    #: ``{section_key: text}`` overrides of the institutional prose. Hostile
    #: until rendered: the editor is a browser, escaping happens at render.
    sections: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: "Descripción del cambio" in the report's version-control table.
    change_summary: Mapped[str] = mapped_column(String(500))
    #: "Áreas Modificadas": the labels of the sections this save changed.
    areas: Mapped[str] = mapped_column(String(200))
    created_by_username: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)

    signed_by_username: Mapped[str | None] = mapped_column(String(64), default=None)
    signed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    #: Ids of the findings triage had excluded ("No aplica") when the version
    #: was signed. NULL on a draft: a draft renders the live triage; a signed
    #: version renders exactly the set it was signed with, whatever the
    #: analyst decides afterwards (later verdicts land in the next version).
    excluded_findings: Mapped[list[str] | None] = mapped_column(JSON, default=None)
    #: SHA-256 of the canonical signed content (number, prose, excluded set).
    content_hash: Mapped[str | None] = mapped_column(String(64), default=None)

    analysis: Mapped[Analysis] = relationship()

    __table_args__ = (UniqueConstraint("analysis_id", "number", name="uq_report_version_number"),)

    @property
    def signed(self) -> bool:
        return self.signed_at is not None


# SQLAlchemy ships DDL untyped; the strings below are static and never templated.
_PG_SIGNED_IMMUTABLE = DDL(  # type: ignore[no-untyped-call]
    """
    CREATE OR REPLACE FUNCTION dioptra_report_version_signed_immutable() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'a signed report version is immutable';
    END;
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER report_version_signed_immutable
        BEFORE UPDATE OR DELETE ON report_versions
        FOR EACH ROW WHEN (OLD.signed_at IS NOT NULL)
        EXECUTE FUNCTION dioptra_report_version_signed_immutable();

    -- TRUNCATE fires no row trigger; the table may hold signed rows, so it is
    -- refused outright (same rule as audit_log). SQLite has no TRUNCATE.
    CREATE TRIGGER report_version_no_truncate
        BEFORE TRUNCATE ON report_versions
        FOR EACH STATEMENT EXECUTE FUNCTION dioptra_report_version_signed_immutable();
    """
)

_SQLITE_SIGNED_NO_UPDATE = DDL(  # type: ignore[no-untyped-call]
    "CREATE TRIGGER report_version_signed_no_update BEFORE UPDATE ON report_versions "
    "WHEN OLD.signed_at IS NOT NULL "
    "BEGIN SELECT RAISE(ABORT, 'a signed report version is immutable'); END;"
)
_SQLITE_SIGNED_NO_DELETE = DDL(  # type: ignore[no-untyped-call]
    "CREATE TRIGGER report_version_signed_no_delete BEFORE DELETE ON report_versions "
    "WHEN OLD.signed_at IS NOT NULL "
    "BEGIN SELECT RAISE(ABORT, 'a signed report version is immutable'); END;"
)

event.listen(
    ReportVersion.__table__,
    "after_create",
    _PG_SIGNED_IMMUTABLE.execute_if(dialect="postgresql"),
)
event.listen(
    ReportVersion.__table__,
    "after_create",
    _SQLITE_SIGNED_NO_UPDATE.execute_if(dialect="sqlite"),
)
event.listen(
    ReportVersion.__table__,
    "after_create",
    _SQLITE_SIGNED_NO_DELETE.execute_if(dialect="sqlite"),
)
