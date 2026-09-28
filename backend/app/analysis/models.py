"""Analysis, findings, raw tool outputs, SBOM and metrics tables.

Everything stored here that came out of the audited tree — paths, snippets,
messages, component names — is HOSTILE INPUT. It is persisted raw and escaped
at every render (docs/analysis-pipeline.md → Normalizer invariants).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    Uuid,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.clock import utc_now
from app.db.base import Base
from app.db.types import UtcDateTime

if TYPE_CHECKING:
    from app.workflow.models import CaseDesign, TestFile, TestPlan, VerificationRun


class SourceKind(StrEnum):
    ZIP = "zip"
    GIT = "git"


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class ToolCategory(StrEnum):
    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"  # noqa: S105 — a category label, not a credential
    SBOM = "sbom"
    METRICS = "metrics"


class ToolStatus(StrEnum):
    """Coverage state of one tool. ``missing``/``failed`` are coverage gaps, reported."""

    RAN = "ran"
    FAILED = "failed"
    MISSING = "missing"
    TIMEOUT = "timeout"


class Severity(StrEnum):
    """Report severity. Order matters for sorting: index 0 is the worst."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {level: index for index, level in enumerate(Severity)}


class Stage(StrEnum):
    """Workflow stages E1–E8 (docs/workflow-gates.md), in order. Names, never E-codes."""

    REGISTER = "register"
    CODE = "code"
    ANALYSIS = "analysis"
    PLAN = "plan"
    DESIGN = "design"
    TESTS = "tests"
    VERIFICATION = "verification"
    REPORT = "report"


STAGE_ORDER: tuple[Stage, ...] = tuple(Stage)


class Verdict(StrEnum):
    """The analyst's triage decision (stage E3). ``None`` on the finding = pending."""

    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"


def _text_enum(enum_type: type[StrEnum], length: int) -> Enum:
    # Stored as text: a native PG enum would need a migration per new member.
    return Enum(enum_type, native_enum=False, length=length, validate_strings=True)


class Analysis(Base):
    """One run of the pipeline over one ingested version of the project."""

    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    source_kind: Mapped[SourceKind] = mapped_column(_text_enum(SourceKind, 8))
    #: Original file name for a ZIP, the URL for git. Display only, escaped.
    source_ref: Mapped[str] = mapped_column(String(512))
    status: Mapped[AnalysisStatus] = mapped_column(
        _text_enum(AnalysisStatus, 8), default=AnalysisStatus.QUEUED, index=True
    )
    #: Typed failure code (``IngestError.code``), never a message or a trace.
    failure_code: Mapped[str | None] = mapped_column(String(64), default=None)
    #: The pipeline step the worker is on (``analysis/progress.py``: the
    #: acquisition, each tool by name, the normalisation); NULL when idle.
    current_step: Mapped[str | None] = mapped_column(String(32), default=None)
    #: Workflow stage of this ingested version. E1 (register) is the project's;
    #: an analysis is born at E2 and only ``app.workflow.stages.advance`` moves it.
    stage: Mapped[Stage] = mapped_column(_text_enum(Stage, 12), default=Stage.CODE, index=True)
    #: Absolute path of the jail; only the worker reads it.
    workspace_path: Mapped[str | None] = mapped_column(String(512), default=None)

    languages: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    frameworks: Mapped[list[str]] = mapped_column(JSON, default=list)
    lockfiles: Mapped[list[str]] = mapped_column(JSON, default=list)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)

    findings: Mapped[list[Finding]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", order_by="Finding.ordinal"
    )
    tool_runs: Mapped[list[ToolRun]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", order_by="ToolRun.tool"
    )
    raw_outputs: Mapped[list[RawToolOutput]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    sbom: Mapped[Sbom | None] = relationship(
        back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )
    metrics: Mapped[CodeMetrics | None] = relationship(
        back_populates="analysis", uselist=False, cascade="all, delete-orphan"
    )
    # String target: app.workflow.models imports nothing from here, and the
    # registry maps both before the first query configures the mappers.
    test_plan: Mapped[TestPlan | None] = relationship(
        "TestPlan", uselist=False, cascade="all, delete-orphan"
    )
    case_designs: Mapped[list[CaseDesign]] = relationship(
        "CaseDesign", cascade="all, delete-orphan", order_by="CaseDesign.created_at"
    )
    test_files: Mapped[list[TestFile]] = relationship(
        "TestFile", cascade="all, delete-orphan", order_by="TestFile.created_at"
    )
    verification_runs: Mapped[list[VerificationRun]] = relationship(
        "VerificationRun",
        cascade="all, delete-orphan",
        order_by="VerificationRun.created_at",
    )


class Finding(Base):
    """One normalized, deduplicated issue (docs/analysis-pipeline.md → invariants)."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    #: Stable position inside the report (severity, then path, then line).
    ordinal: Mapped[int] = mapped_column(Integer, default=0)
    category: Mapped[ToolCategory] = mapped_column(_text_enum(ToolCategory, 8))
    #: Tools that reported this finding, first one is the primary source.
    tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    rule_id: Mapped[str] = mapped_column(String(200))
    #: ``None`` is a VALID state: "unknown CWE" reaches triage and the report.
    cwe: Mapped[int | None] = mapped_column(Integer, default=None)
    owasp: Mapped[str | None] = mapped_column(String(16), default=None)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[Severity] = mapped_column(_text_enum(Severity, 8))
    cvss_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), default=None)
    path: Mapped[str] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer, default=None)
    snippet: Mapped[str | None] = mapped_column(Text, default=None)
    message: Mapped[str | None] = mapped_column(Text, default=None)
    #: SCA only: the advisory id (CVE/GHSA), the package, and versions.
    advisory: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: (path, line, rule-or-CWE) key used for cross-tool deduplication.
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    #: The finding sits in a dependency directory, so it is NOT the analyst's
    #: to adjudicate: it never enters the E3 queue and the gate does not wait
    #: for a verdict on it. It is still stored, shown and reported
    #: (`app/analysis/third_party.py`, `tasks/phase9-survey.md`).
    third_party: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), index=True
    )

    # Triage (E3). The latest verdict lives here; every verdict ever given,
    # including revisions, is a row of the append-only audit log — that trail
    # is the history, so no second table can drift from it.
    verdict: Mapped[Verdict | None] = mapped_column(_text_enum(Verdict, 16), default=None)
    verdict_justification: Mapped[str | None] = mapped_column(Text, default=None)
    verdict_by_username: Mapped[str | None] = mapped_column(String(64), default=None)
    verdict_at: Mapped[datetime | None] = mapped_column(UtcDateTime, default=None)

    analysis: Mapped[Analysis] = relationship(back_populates="findings")

    @property
    def in_report(self) -> bool:
        """ "Es real — incluir en el reporte": only a false positive leaves the report."""
        return self.verdict is not Verdict.FALSE_POSITIVE


class ToolRun(Base):
    """Coverage record of one tool. A tool that could not run is a gap, never silence."""

    __tablename__ = "tool_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    tool: Mapped[str] = mapped_column(String(40))
    category: Mapped[ToolCategory] = mapped_column(_text_enum(ToolCategory, 8))
    status: Mapped[ToolStatus] = mapped_column(_text_enum(ToolStatus, 8))
    detail: Mapped[str | None] = mapped_column(String(500), default=None)
    duration_ms: Mapped[int | None] = mapped_column(Integer, default=None)

    analysis: Mapped[Analysis] = relationship(back_populates="tool_runs")


class RawToolOutput(Base):
    """The tool's untouched output, persisted BEFORE normalization (plan day 7)."""

    __tablename__ = "raw_tool_outputs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    tool: Mapped[str] = mapped_column(String(40))
    exit_code: Mapped[int | None] = mapped_column(Integer, default=None)
    stderr: Mapped[str | None] = mapped_column(Text, default=None)
    #: The report file the tool wrote (SARIF / CycloneDX / CSV / JSON), capped.
    output: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)
    truncated: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)

    analysis: Mapped[Analysis] = relationship(back_populates="raw_outputs")


class Sbom(Base):
    """CycloneDX 1.6 SBOM of one ingested version. Generated once, shared with P5."""

    __tablename__ = "sboms"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), unique=True
    )
    spec_version: Mapped[str] = mapped_column(String(8), default="1.6")
    generator: Mapped[str] = mapped_column(String(40))
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)

    analysis: Mapped[Analysis] = relationship(back_populates="sbom")


class CodeMetrics(Base):
    """Lizard + cloc output and the commented-code scan, for the report and E4."""

    __tablename__ = "code_metrics"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), unique=True
    )
    #: ``[{path, function, line, nloc, ccn, params}]`` from Lizard.
    functions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    #: ``{language: {files, blank, comment, code}}`` from cloc.
    lines: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: Files where commented-out code was detected (report section "Errores y prácticas").
    commented_code_files: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utc_now)

    analysis: Mapped[Analysis] = relationship(back_populates="metrics")
