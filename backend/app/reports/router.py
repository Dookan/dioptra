"""Report editor endpoints: ``/api/v1/analyses/{id}/report/...`` (stage E8)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.deps import ActiveUser, AnalystUser, client_ip
from app.db.session import get_db
from app.ingest import service
from app.reports import context, versions
from app.reports.models import ReportVersion

router = APIRouter(prefix="/api/v1/analyses/{analysis_id}/report", tags=["report"])

DbSession = Annotated[Session, Depends(get_db)]


class ReportVersionOut(BaseModel):
    number: int
    change_summary: str
    areas: str
    created_by_username: str
    created_at: datetime
    signed_by_username: str | None
    signed_at: datetime | None
    #: Findings frozen out of a signed version (``None`` on a draft).
    excluded_findings: list[str] | None
    content_hash: str | None


class SectionOut(BaseModel):
    key: str
    label: str
    text: str
    edited: bool


class ReportStateOut(BaseModel):
    """What the editor shows: the current version's prose and the history."""

    number: int
    #: False until the first save or signature: version 1 is then virtual.
    persisted: bool
    signed: bool
    sections: list[SectionOut]
    versions: list[ReportVersionOut]


class SectionsIn(BaseModel):
    sections: dict[str, str] = Field(max_length=len(versions.EDITABLE_SECTIONS))
    change_summary: str = Field(max_length=8000)


class SignIn(BaseModel):
    justification: str = Field(max_length=8000)


def _version_out(version: ReportVersion) -> ReportVersionOut:
    return ReportVersionOut(
        number=version.number,
        change_summary=version.change_summary,
        areas=version.areas,
        created_by_username=version.created_by_username,
        created_at=version.created_at,
        signed_by_username=version.signed_by_username,
        signed_at=version.signed_at,
        excluded_findings=version.excluded_findings,
        content_hash=version.content_hash,
    )


def _state(db: Session, analysis_id: uuid.UUID) -> ReportStateOut:
    analysis = service.get_analysis(db, analysis_id)
    project = service.get_project(db, analysis.project_id)
    history = versions.list_versions(db, analysis)
    latest = history[-1] if history else None
    overrides: dict[str, str] = dict(latest.sections) if latest is not None else {}
    # A signed current version previews the set it was signed with, like its export.
    excluded = (
        frozenset(latest.excluded_findings)
        if latest is not None and latest.excluded_findings is not None
        else None
    )
    defaults = context.default_sections(analysis, project, excluded=excluded)
    return ReportStateOut(
        number=latest.number if latest is not None else 1,
        persisted=latest is not None,
        signed=latest is not None and latest.signed,
        sections=[
            SectionOut(
                key=key,
                label=versions.section_label(key),
                text=overrides.get(key, defaults[key]),
                edited=key in overrides,
            )
            for key in versions.EDITABLE_SECTIONS
        ],
        versions=[_version_out(item) for item in history],
    )


@router.get("/current", response_model=ReportStateOut)
def get_current(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> ReportStateOut:
    return _state(db, analysis_id)


@router.get("/versions", response_model=list[ReportVersionOut])
def get_versions(
    analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession
) -> list[ReportVersionOut]:
    analysis = service.get_analysis(db, analysis_id)
    return [_version_out(item) for item in versions.list_versions(db, analysis)]


@router.put("/sections", response_model=ReportStateOut)
def put_sections(
    analysis_id: uuid.UUID,
    payload: SectionsIn,
    request: Request,
    user: AnalystUser,
    db: DbSession,
) -> ReportStateOut:
    """Save the edited prose as the next version (analyst only, audit-logged)."""
    analysis = service.get_analysis(db, analysis_id)
    versions.save_sections(
        db,
        analysis=analysis,
        actor=user,
        sections=payload.sections,
        change_summary=payload.change_summary,
        source_ip=client_ip(request),
    )
    return _state(db, analysis_id)


@router.post("/versions/{number}/sign", response_model=ReportStateOut)
def post_sign(
    analysis_id: uuid.UUID,
    number: int,
    payload: SignIn,
    request: Request,
    user: AnalystUser,
    db: DbSession,
) -> ReportStateOut:
    """Sign the current version: it becomes immutable; later edits open the next one."""
    analysis = service.get_analysis(db, analysis_id)
    versions.sign(
        db,
        analysis=analysis,
        actor=user,
        number=number,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    return _state(db, analysis_id)
