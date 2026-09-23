"""Workflow tables. Phase 3: the E4 test plan and the E5 case designs.

Phase 4 adds the E6 test file the developer writes over the scaffold, and the
``reopened_at`` flag the E7 → E5 loop sets on the designs that failed.
"""

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
    #: Set by the E7 → E5 loop when this function's verification failed: the
    #: design becomes writable again AT E7 without moving the stage backwards
    #: (the machine stays monotonic). Approving again clears it.
    reopened_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
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


#: A test file the developer stores. Generous, because it is the developer's
#: own work, but bounded: it is text we parse, and the sandbox writes it out.
MAX_TEST_FILE_CHARS = 200_000


class TestFile(Base):
    """E6 deliverable: the test file the developer wrote for one planned function.

    Stored as TEXT and never executed outside the E7 sandbox. The platform
    generated only its scaffold (names, imports, the brief items per case);
    every assertion in here is the developer's — that separation is the whole
    pedagogy (docs/roles-and-permissions.md → Rules).
    """

    __tablename__ = "test_files"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(String(1024))
    function: Mapped[str] = mapped_column(String(200))
    line: Mapped[int | None] = mapped_column(Integer, default=None)
    #: The scaffold's file name; the sandbox writes the content under it.
    filename: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text, default="")
    created_by_username: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        UniqueConstraint(
            "analysis_id",
            "path",
            "function",
            "line",
            name="uq_test_file_function",
            postgresql_nulls_not_distinct=True,
        ),
    )


class VerificationStatus(StrEnum):
    """How one verification attempt on one planned function ended."""

    PASSED = "passed"
    #: It ran and the re-audit rejected it: coverage, a failing test, an
    #: assertion-less case, or a surviving mutant.
    FAILED = "failed"
    #: It could not run at all (no sandbox, a timeout, unreadable results).
    ERRORED = "errored"


#: Reason codes a failed run carries, in `VerificationRun.reasons`. Every one
#: of them has an i18n key the screen resolves; the developer never reads a
#: server-authored sentence.
REASON_TESTS_FAILED = "tests_failed"
REASON_ASSERTION_FREE = "assertion_free"
REASON_COVERAGE_SHORT = "coverage_short"
REASON_BRIEF_UNCOVERED = "brief_uncovered"
REASON_MUTANT_SURVIVED = "mutant_survived"
REASON_SANDBOX_ERROR = "sandbox_error"


class VerificationRun(Base):
    """E7: one sandbox attempt on one planned function.

    Runs are append-only in practice — the gate reads the LATEST per function,
    and the history is what the report's "test debt" section is built from.
    """

    __tablename__ = "verification_runs"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(String(1024))
    function: Mapped[str] = mapped_column(String(200))
    line: Mapped[int | None] = mapped_column(Integer, default=None)
    status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus, native_enum=False, length=8, validate_strings=True)
    )
    #: Reason codes (above); empty on a pass.
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: ``app.sandbox.results.Coverage.as_dict``.
    coverage: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: Brief item ids whose line never ran, or whose branch stayed partial.
    uncovered_items: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: ``[{id, line, mutant}]`` — the exact mutant the developer is shown.
    surviving_mutants: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    #: ``[{id, line, mutant}]`` — survivors excused as equivalent BEFORE this run
    #: (``EquivalentMutant``); shown in the report beside the real survivors.
    equivalent_mutants: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    assertion_free_cases: Mapped[list[str]] = mapped_column(JSON, default=list)
    failed_cases: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: Tail of the sandbox's stderr, bounded; audited output, rendered as text.
    detail: Mapped[str | None] = mapped_column(Text, default=None)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_by_username: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)


class EquivalentMutant(Base):
    """A surviving mutant the developer judged EQUIVALENT, with a written reason (P5).

    Some mutants cannot be killed by any test — ``"ascii"`` → ``"ASCII"`` is
    the same codec, ``ensure_ascii=None`` is ``False`` — and a gate that
    demands zero survivors would then close forever. The developer marks the
    mutant with a justification (audit row ``verification.mutant.equivalent``)
    and the NEXT run excludes it, recording it on the run so the report shows
    what was excused and why. Found by the P5 walk of the platform on itself.
    """

    __tablename__ = "equivalent_mutants"

    id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4, primary_key=True)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    path: Mapped[str] = mapped_column(String(1024))
    function: Mapped[str] = mapped_column(String(200))
    line: Mapped[int | None] = mapped_column(Integer, default=None)
    #: The mutant id as the sandbox reported it (``text.x_slug__mutmut_14``, a Stryker id).
    mutant_id: Mapped[str] = mapped_column(String(200))
    #: The mutant text at the time of the mark, so the report can show it.
    mutant: Mapped[str] = mapped_column(String(400), default="")
    justification: Mapped[str] = mapped_column(Text)
    created_by_username: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)

    __table_args__ = (
        UniqueConstraint(
            "analysis_id",
            "path",
            "function",
            "line",
            "mutant_id",
            name="uq_equivalent_mutant",
            postgresql_nulls_not_distinct=True,
        ),
    )
