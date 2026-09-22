"""Workflow tables. Phase 3: the E4 test plan."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Enum, ForeignKey, String, Text
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
