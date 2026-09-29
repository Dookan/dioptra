"""Project endpoints: ``/api/v1/projects``."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.analysis.models import Analysis, AnalysisStatus, Severity
from app.analysis.progress import progress_of
from app.analysis.sweep import sweep_quietly
from app.auth.deps import ActiveUser, client_ip, require_roles
from app.auth.models import Role, User
from app.core.clock import utc_now
from app.core.config import get_settings
from app.db.session import get_db
from app.ingest import service, upload
from app.ingest.errors import UploadMediaTypeUnsupported
from app.projects.errors import InstalledAtInFuture
from app.projects.schemas import (
    AnalysisOut,
    GitIngestRequest,
    ProgressOut,
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
    progress = progress_of(analysis)
    if progress is not None:
        payload.progress = ProgressOut(
            step=progress.step, index=progress.index, total=progress.total
        )
    payload.cancel_requested = (
        analysis.status is AnalysisStatus.RUNNING and analysis.cancel_requested_at is not None
    )
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
async def ingest_zip(
    project_id: uuid.UUID,
    request: Request,
    user: IngestUser,
    db: DbSession,
    filename: Annotated[str, Query(max_length=1024)] = "upload.zip",
) -> AnalysisOut:
    """Stage E2: the audited system as a ZIP, sent as the RAW request body.

    Phase 10 (1.x contract change): no multipart. The route declares no body
    parameter, so ``IngestUser`` refuses an anonymous or unauthorised caller
    before a single byte of the body is read (`tasks/phase10-survey.md` §2.1);
    the body is then streamed to disk under a byte counter and the WORKER
    extracts it. Async on purpose: the body is consumed from the ASGI stream;
    every database call below is handed to the thread pool.
    """
    settings = get_settings()
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media not in upload.ZIP_MEDIA_TYPES:
        raise UploadMediaTypeUnsupported(f"content-type {media[:80]!r}")
    declared = request.headers.get("content-length")
    # Refuse by the declared length before a byte is read; the counter in
    # `spool_body` re-checks what actually arrives, so a lying header gains nothing.
    if declared is not None and declared.isdigit() and int(declared) > settings.max_zip_bytes:
        raise upload.too_large(settings.max_zip_bytes, f"content-length {declared}")
    project = await run_in_threadpool(service.get_project, db, project_id)
    # Before a new spool lands, clear the ones a dead process left (1.5.1).
    await run_in_threadpool(sweep_quietly, db, settings)
    analysis_id = uuid.uuid4()
    directory = upload.analysis_dir(settings, project.id, analysis_id)
    try:
        await upload.spool_body(
            request.stream(), directory / upload.UPLOAD_NAME, settings.max_zip_bytes
        )
        analysis = await run_in_threadpool(
            lambda: service.accept_zip(
                db,
                project=project,
                actor=user,
                analysis_id=analysis_id,
                filename=upload.display_name(filename),
                source_ip=client_ip(request),
            )
        )
    except BaseException:
        # Nothing of a refused or failed upload stays on disk. A row flushed
        # but not committed rolls back with the request; once `accept_zip`
        # has COMMITTED, the only failure left is the enqueue's, and
        # `_enqueue_or_fail` has already closed that row as FAILED.
        upload.discard(directory)
        raise

    def _out() -> AnalysisOut:
        db.refresh(analysis)
        return analysis_out(analysis)

    return await run_in_threadpool(_out)


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
    sweep_quietly(db, get_settings())
    analysis = service.ingest_git(
        db, project=project, actor=user, url=payload.url, source_ip=client_ip(request)
    )
    db.refresh(analysis)
    return analysis_out(analysis)
