"""Asynchronous PDF export endpoints (phase 8, ``tasks/phase8-survey.md``).

Every handler here either enqueues, reads a row or hands back a file the worker
already wrote: none of them renders. The export row of
``docs/roles-and-permissions.md`` gives all three roles the report, so every
endpoint is ``ActiveUser``; ownership of a JOB is the requester's or the
admin's (survey §7.2), checked in ``jobs.get_for``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from app.auth.deps import ActiveUser, client_ip
from app.db.session import get_db
from app.reports import jobs
from app.reports.models import ReportJob

router = APIRouter(prefix="/api/v1", tags=["report-jobs"])

DbSession = Annotated[Session, Depends(get_db)]


class ReportJobIn(BaseModel):
    #: The editor version to render; omitted means the current one.
    version: int | None = Field(default=None, ge=1)


class ReportJobOut(BaseModel):
    id: uuid.UUID
    analysis_id: uuid.UUID
    version: int | None
    format: str
    status: str
    requested_by_username: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    byte_size: int | None
    #: A machine code (``render_failed``, ``spool_full``, ``abandoned``…) the
    #: client turns into a sentence; never server-authored copy.
    detail: str | None
    #: In-flight jobs requested before this one; 0 unless QUEUED.
    ahead: int
    elapsed_seconds: int


def job_out(db: Session, job: ReportJob) -> ReportJobOut:
    return ReportJobOut(
        id=job.id,
        analysis_id=job.analysis_id,
        version=job.version,
        format=job.format,
        status=job.status.value,
        requested_by_username=job.requested_by_username,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        byte_size=job.byte_size,
        detail=job.detail,
        ahead=jobs.queue_position(db, job),
        elapsed_seconds=jobs.elapsed_seconds(job),
    )


@router.post("/analyses/{analysis_id}/report/jobs", status_code=202, response_model=ReportJobOut)
def request_report_job(
    analysis_id: uuid.UUID,
    body: ReportJobIn,
    request: Request,
    user: ActiveUser,
    db: DbSession,
) -> ReportJobOut:
    job = jobs.request_pdf(
        db,
        actor=user,
        analysis_id=analysis_id,
        version=body.version,
        source_ip=client_ip(request),
    )
    return job_out(db, job)


# Declared before `/report-jobs/{job_id}`: "mine" is not a uuid, and the order
# keeps the literal route from ever being parsed as one.
@router.get("/report-jobs/mine", response_model=ReportJobOut | None)
def my_report_job(user: ActiveUser, db: DbSession) -> ReportJobOut | None:
    job = jobs.latest_for(db, actor=user)
    return job_out(db, job) if job is not None else None


@router.get("/report-jobs/{job_id}", response_model=ReportJobOut)
def get_report_job(
    job_id: uuid.UUID, request: Request, user: ActiveUser, db: DbSession
) -> ReportJobOut:
    job = jobs.get_for(db, actor=user, job_id=job_id, source_ip=client_ip(request))
    return job_out(db, job)


def _discard(path: Path) -> None:
    path.unlink(missing_ok=True)


@router.get("/report-jobs/{job_id}/download")
def download_report_job(
    job_id: uuid.UUID, request: Request, user: ActiveUser, db: DbSession
) -> Response:
    body, filename, path = jobs.take_artefact(
        db, actor=user, job_id=job_id, source_ip=client_ip(request)
    )
    # The file goes once the response has been SENT (survey §7.3); if sending
    # fails the task never runs and the sweep removes the orphan later.
    return Response(
        content=body,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        background=BackgroundTask(_discard, path),
    )
