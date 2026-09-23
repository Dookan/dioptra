"""Project endpoints: ``/api/v1/projects``."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Severity
from app.auth.deps import ActiveUser, client_ip, require_roles
from app.auth.models import Role, User
from app.core.clock import utc_now
from app.core.config import get_settings
from app.db.session import get_db
from app.ingest import service
from app.ingest.errors import ZipTooLarge
from app.projects.errors import InstalledAtInFuture
from app.projects.schemas import (
    AnalysisOut,
    GitIngestRequest,
    ProjectCreate,
    ProjectOut,
    TriageOut,
)
from app.workflow.triage import triage_status

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])

DbSession = Annotated[Session, Depends(get_db)]
#: Who may register a project and start an analysis (E1–E2): admin and analyst.
IngestUser = Annotated[User, Depends(require_roles(Role.ADMIN, Role.ANALYST))]


def analysis_out(analysis: Analysis) -> AnalysisOut:
    counts = dict.fromkeys((level.value for level in Severity), 0)
    report_counts = dict(counts)
    for finding in analysis.findings:
        counts[finding.severity.value] += 1
        if finding.in_report:
            report_counts[finding.severity.value] += 1
    payload = AnalysisOut.model_validate(analysis)
    payload.finding_counts = counts
    payload.report_counts = report_counts
    status = triage_status(analysis)
    payload.triage = TriageOut(
        total=status.total,
        confirmed=status.confirmed,
        false_positive=status.false_positive,
        pending=status.pending,
        complete=status.complete,
        third_party=status.third_party,
    )
    return payload


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate, request: Request, user: IngestUser, db: DbSession
) -> ProjectOut:
    installed_at = payload.system.installed_at
    if installed_at is not None and installed_at > utc_now().date():
        raise InstalledAtInFuture(f"installed_at={installed_at.isoformat()}")
    project = service.create_project(
        db,
        actor=user,
        name=payload.name,
        description=payload.description,
        system_name=payload.system.name,
        framework=payload.system.framework,
        database=payload.system.database,
        developer=payload.system.developer,
        installed_at=payload.system.installed_at,
        source_ip=client_ip(request),
    )
    return ProjectOut.model_validate(project)


@router.get("", response_model=list[ProjectOut])
def list_projects(_user: ActiveUser, db: DbSession) -> list[ProjectOut]:
    return [ProjectOut.model_validate(project) for project in service.list_projects(db)]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> ProjectOut:
    return ProjectOut.model_validate(service.get_project(db, project_id))


@router.get("/{project_id}/analyses", response_model=list[AnalysisOut])
def list_analyses(project_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> list[AnalysisOut]:
    service.get_project(db, project_id)
    return [analysis_out(item) for item in service.list_analyses(db, project_id)]


@router.post(
    "/{project_id}/ingest", response_model=AnalysisOut, status_code=status.HTTP_202_ACCEPTED
)
def ingest_zip(
    project_id: uuid.UUID,
    request: Request,
    user: IngestUser,
    db: DbSession,
    file: Annotated[UploadFile, File()],
) -> AnalysisOut:
    """Stage E2: upload the audited system as a ZIP archive."""
    project = service.get_project(db, project_id)
    declared = request.headers.get("content-length")
    # Reject by the declared length before a byte of the body is spooled; the
    # service re-checks the real size, so a lying header gains nothing.
    if declared is not None and declared.isdigit() and int(declared) > get_settings().max_zip_bytes:
        raise ZipTooLarge(f"content-length {declared}")
    analysis = service.ingest_zip(
        db,
        project=project,
        actor=user,
        upload=file.file,
        upload_size=file.size,
        filename=file.filename or "upload.zip",
        source_ip=client_ip(request),
    )
    db.refresh(analysis)
    return analysis_out(analysis)


@router.post(
    "/{project_id}/ingest/git", response_model=AnalysisOut, status_code=status.HTTP_202_ACCEPTED
)
def ingest_git(
    project_id: uuid.UUID,
    payload: GitIngestRequest,
    request: Request,
    user: IngestUser,
    db: DbSession,
) -> AnalysisOut:
    """Stage E2: clone a public HTTPS repository (in the worker, never here)."""
    project = service.get_project(db, project_id)
    analysis = service.ingest_git(
        db, project=project, actor=user, url=payload.url, source_ip=client_ip(request)
    )
    db.refresh(analysis)
    return analysis_out(analysis)
