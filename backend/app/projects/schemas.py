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
    ToolCategory,
    ToolStatus,
    Verdict,
)


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


class VerdictIn(BaseModel):
    verdict: Verdict
    #: Mandatory. The length floor is enforced by the service after whitespace
    #: normalization, so a padded blank cannot pass the schema.
    justification: str = Field(max_length=8000)
