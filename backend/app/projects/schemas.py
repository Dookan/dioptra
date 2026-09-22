"""Request/response models for projects, systems and analyses."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import AnalysisStatus, Severity, SourceKind, ToolCategory, ToolStatus


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
    finding_counts: dict[str, int] = Field(default_factory=dict)
    tool_runs: list[ToolRunOut] = Field(default_factory=list)


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
