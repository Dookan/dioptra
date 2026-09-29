"""Analysis endpoints: ``/api/v1/analyses``."""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.analysis import cancel
from app.analysis.models import AnalysisStatus
from app.auth.deps import ActiveUser, client_ip, require_roles
from app.auth.models import Role, User
from app.core.config import get_settings
from app.db.session import get_db
from app.ingest import service
from app.ingest.errors import AnalysisNotFound, AnalysisNotReady
from app.projects.router import analysis_out
from app.projects.schemas import AnalysisOut, FindingOut, finding_out
from app.reports import engine, versions
from app.reports.errors import ReportPdfIsQueued

router = APIRouter(prefix="/api/v1/analyses", tags=["analyses"])

DbSession = Annotated[Session, Depends(get_db)]
ReportFormat = Literal["pdf", "html", "md", "docx"]
#: E2's roles; ``cancel.may_cancel`` narrows an analyst to their own analyses.
CancelUser = Annotated[User, Depends(require_roles(Role.ADMIN, Role.ANALYST))]

_MEDIA_TYPES: dict[str, str] = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


@router.get("/{analysis_id}", response_model=AnalysisOut)
def get_analysis(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> AnalysisOut:
    return analysis_out(service.get_analysis(db, analysis_id))


@router.post(
    "/{analysis_id}/cancel", response_model=AnalysisOut, status_code=status.HTTP_202_ACCEPTED
)
def cancel_analysis(
    analysis_id: uuid.UUID, request: Request, user: CancelUser, db: DbSession
) -> AnalysisOut:
    """Cancel a queued analysis, or ask a running one's worker to stop (phase 12).

    No body: no written reason, by `mmarin`'s decision (CLAUDE.md → Hard Rules →
    Auth). 202 because a running analysis is closed by its worker, seconds later.
    """
    analysis = cancel.request_cancel(
        db, get_settings(), actor=user, analysis_id=analysis_id, source_ip=client_ip(request)
    )
    return analysis_out(analysis)


@router.get("/{analysis_id}/findings", response_model=list[FindingOut])
def list_findings(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> list[FindingOut]:
    analysis = service.get_analysis(db, analysis_id)
    return [finding_out(finding) for finding in analysis.findings]


@router.get("/{analysis_id}/sbom")
def get_sbom(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> Response:
    """The CycloneDX 1.6 document as generated — the P5 inventory reads the same row."""
    analysis = service.get_analysis(db, analysis_id)
    if analysis.sbom is None:
        raise AnalysisNotFound("no sbom for this analysis")
    body = json.dumps(analysis.sbom.document, ensure_ascii=True, separators=(",", ":"))
    return Response(
        content=body,
        media_type="application/vnd.cyclonedx+json; version=1.6",
        headers={"Content-Disposition": 'attachment; filename="sbom.cdx.json"'},
    )


@router.get("/{analysis_id}/report")
def get_report(
    analysis_id: uuid.UUID,
    _user: ActiveUser,
    db: DbSession,
    format: ReportFormat = "pdf",  # noqa: A002 — the query parameter is named `format` on purpose
    version: int | None = None,
) -> Response:
    """Stage E8 export of the institutional report.

    ``version`` selects a snapshot of the editor (default: the current one;
    with no saved version the composed baseline renders).

    The PDF is no longer rendered here (phase 8): a large report took a minute
    of this request, and leaving the path open would make "one PDF at a time"
    the screen's rule rather than the server's. It is a job —
    ``POST …/report/jobs``. HTML, Markdown and DOCX stay synchronous.
    """
    if format == "pdf":
        raise ReportPdfIsQueued(str(analysis_id))
    analysis = service.get_analysis(db, analysis_id)
    if analysis.status is not AnalysisStatus.DONE:
        raise AnalysisNotReady(analysis.status.value)
    project = service.get_project(db, analysis.project_id)
    history = versions.list_versions(db, analysis)
    selected = versions.get_version(db, analysis, version) if version is not None else None
    if selected is None and history:
        selected = history[-1]
    body: bytes | str
    if format == "html":
        body = engine.render_html(analysis, project, version=selected, versions=history)
    elif format == "md":
        body = engine.render_markdown(analysis, project, version=selected, versions=history)
    else:
        body = engine.render_docx(analysis, project, version=selected, versions=history)
    disposition = "inline" if format == "html" else "attachment"
    filename = engine.report_file_name(project.name, format)
    return Response(
        content=body,
        media_type=_MEDIA_TYPES[format],
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"'},
    )
