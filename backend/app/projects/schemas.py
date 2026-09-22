"""Request/response models for projects, systems and analyses."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import (
    AnalysisStatus,
    Finding,
    Severity,
    SourceKind,
    Stage,
    ToolCategory,
    ToolStatus,
    Verdict,
)
from app.workflow.models import MAX_CASES, CoverageCriterion


class SystemProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    framework: str | None = Field(default=None, max_length=120)
    database: str | None = Field(default=None, max_length=120)
    developer: str | None = Field(default=None, max_length=200)
    installed_at: str | None = Field(default=None, max_length=40)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=4000)
    system: SystemProfileIn


class SystemProfileOut(SystemProfileIn):
    model_config = ConfigDict(from_attributes=True)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime
    system: SystemProfileOut | None


class GitIngestRequest(BaseModel):
    url: str = Field(min_length=8, max_length=512)


class ToolRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tool: str
    category: ToolCategory
    status: ToolStatus
    detail: str | None
    duration_ms: int | None


class TriageOut(BaseModel):
    """E3 progress; ``complete`` is the gate condition, computed server-side."""

    total: int
    confirmed: int
    false_positive: int
    pending: int
    complete: bool


class AnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    source_kind: SourceKind
    source_ref: str
    status: AnalysisStatus
    failure_code: str | None
    #: Workflow stage (E1–E8 by name); only ``POST …/stage/advance`` moves it.
    stage: Stage
    languages: dict[str, int]
    frameworks: list[str]
    lockfiles: list[str]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    #: Every finding by severity, verdicts ignored.
    finding_counts: dict[str, int] = Field(default_factory=dict)
    #: What the report prints: false positives left out (mirrors `Finding.in_report`).
    report_counts: dict[str, int] = Field(default_factory=dict)
    tool_runs: list[ToolRunOut] = Field(default_factory=list)
    triage: TriageOut = Field(
        default_factory=lambda: TriageOut(
            total=0, confirmed=0, false_positive=0, pending=0, complete=True
        )
    )


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ordinal: int
    category: ToolCategory
    tools: list[str]
    rule_id: str
    cwe: int | None
    owasp: str | None
    title: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    path: str
    line: int | None
    snippet: str | None
    message: str | None
    advisory: dict[str, Any] | None
    references: list[str]
    # Institutional prose for the CWE (report content shown as data: the
    # analyst reviews the very text the PDF will print).
    description: str = ""
    impact: str = ""
    mitigation: list[str] = Field(default_factory=list)
    # Triage state; ``verdict`` None = pending.
    verdict: Verdict | None = None
    verdict_justification: str | None = None
    verdict_by_username: str | None = None
    verdict_at: datetime | None = None


def finding_out(finding: Finding) -> FindingOut:
    """Serialize a finding with the catalog prose the report uses for it."""
    from app.analysis.catalog import describe  # noqa: PLC0415 — keeps schemas import-light

    entry = describe(finding.cwe, fallback_title=finding.title)
    payload = FindingOut.model_validate(finding)
    payload.description = entry.description
    payload.impact = entry.impact
    payload.mitigation = list(entry.mitigation)
    return payload


class JustificationIn(BaseModel):
    """Body of every stage transition: the written reason, validated by the service."""

    justification: str = Field(max_length=8000)


class RiskRowOut(BaseModel):
    path: str
    function: str
    line: int | None
    ccn: int
    nloc: int
    findings: int
    max_severity: Severity | None
    score: int
    level: str


class PlannedFunctionIn(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    function: str = Field(min_length=1, max_length=200)
    line: int | None = None


class TestPlanIn(BaseModel):
    criterion: CoverageCriterion = CoverageCriterion.DECISIONS
    rationale: str = Field(max_length=8000)
    functions: list[PlannedFunctionIn] = Field(max_length=200)


class TestPlanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    analysis_id: uuid.UUID
    criterion: CoverageCriterion
    rationale: str
    functions: list[dict[str, Any]]
    created_by_username: str
    created_at: datetime
    updated_at: datetime


class DiagramTextIn(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    function: str = Field(min_length=1, max_length=200)
    line: int | None = None
    text: str = Field(max_length=40_000)


class CaseIn(BaseModel):
    title: str = Field(max_length=2000)
    #: Brief item ids this case declares to demonstrate (validated server-side).
    covers: list[str] = Field(default_factory=list, max_length=200)


class CasesIn(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    function: str = Field(min_length=1, max_length=200)
    line: int | None = None
    cases: list[CaseIn] = Field(max_length=MAX_CASES)


class DesignStateOut(BaseModel):
    path: str
    function: str
    line: int | None
    cases: int
    approved_at: datetime | None
    approved_by_username: str | None


class BriefOut(BaseModel):
    #: ``app.workflow.brief.brief_as_dict``: signature, complexity, min_cases, items.
    brief: dict[str, Any]
    cases: list[dict[str, Any]]
    approved_at: datetime | None
    approved_by_username: str | None


class DiagramOut(BaseModel):
    path: str
    function: str
    line: int | None
    language: str
    complexity: int
    #: Interchange / editing format; the picture is drawn from ``layout``.
    mermaid: str
    graph: dict[str, Any]
    layout: dict[str, Any]
    edited_text: str | None
    edited_by_username: str | None
    edited_at: datetime | None


class VerdictIn(BaseModel):
    verdict: Verdict
    #: Mandatory. The length floor is enforced by the service after whitespace
    #: normalization, so a padded blank cannot pass the schema.
    justification: str = Field(max_length=8000)
