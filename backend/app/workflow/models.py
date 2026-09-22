"""Workflow tables. Phase 3: the E4 test plan and the E5 case designs."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utc_now
from app.db.base import Base
from app.db.types import UtcDateTime


class CoverageCriterion(StrEnum):
    """The exigency chosen at E4 (docs/glossary.md → Coverage criterion)."""

    STATEMENTS = "statements"
    DECISIONS = "decisions"
    PATHS = "paths"


class TestPlan(Base):
    """E4 deliverable: the functions to test, the criterion and the written rationale."""

    __tablename__ = "test_plans"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), unique=True
    )
    criterion: Mapped[CoverageCriterion] = mapped_column(
        Enum(CoverageCriterion, native_enum=False, length=12, validate_strings=True),
        default=CoverageCriterion.DECISIONS,
    )
    #: The developer's own words; also printed in the report (P5, test debt).
    rationale: Mapped[str] = mapped_column(Text)
    #: ``[{path, function, line, ccn}]`` — validated against the metrics rows.
    functions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_by_username: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, onupdate=utc_now)


#: Cases per function; the schema and the service share the one number, and
#: E4 refuses a function whose basis paths exceed it (it could never be approved).
MAX_CASES = 200


class CaseDesign(Base):
    """E5 work on one planned function: diagram text (day 14), cases and approval (day 15).

    The picture the UI draws is always computed from the AST; ``diagram_text``
    is the developer's editable Mermaid — stored and shown as text, never
    rendered as markup (docs/threat-model.md → Flow diagrams). ``cases`` are
    the developer's own words plus the brief items each one declares to
    cover; ``brief`` is the snapshot taken at approval, which P4's scaffold
    names its cases from.
    """

    __tablename__ = "case_designs"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(String(1024))
    function: Mapped[str] = mapped_column(String(200))
    line: Mapped[int | None] = mapped_column(Integer, default=None)
    diagram_text: Mapped[str | None] = mapped_column(Text, default=None)
    #: ``[{title, covers: [item id]}]`` — validated against the live brief on save.
    cases: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    #: The brief as it was when the cases were approved (``brief_as_dict``).
    brief: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    approved_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    approved_by_username: Mapped[str | None] = mapped_column(String(64), default=None)
    created_by_username: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        # NULLS NOT DISTINCT: a function without a line (malformed Lizard row)
        # still gets one row on PostgreSQL; SQLite relies on the service upsert.
        UniqueConstraint(
            "analysis_id",
            "path",
            "function",
            "line",
            name="uq_case_design_function",
            postgresql_nulls_not_distinct=True,
        ),
    )
