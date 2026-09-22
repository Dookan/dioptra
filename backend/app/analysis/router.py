"""Analysis endpoints: ``/api/v1/analyses``."""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.analysis.models import AnalysisStatus
from app.auth.deps import ActiveUser
from app.db.session import get_db
from app.ingest import service
from app.ingest.errors import AnalysisNotFound, AnalysisNotReady
from app.projects.router import analysis_out
from app.projects.schemas import AnalysisOut, FindingOut, finding_out
from app.reports import engine, versions

router = APIRouter(prefix="/api/v1/analyses", tags=["analyses"])

DbSession = Annotated[Session, Depends(get_db)]
ReportFormat = Literal["pdf", "html", "md", "docx"]

_MEDIA_TYPES: dict[str, str] = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


@router.get("/{analysis_id}", response_model=AnalysisOut)
def get_analysis(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> AnalysisOut:
    return analysis_out(service.get_analysis(db, analysis_id))


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
    """
    analysis = service.get_analysis(db, analysis_id)
    if analysis.status is not AnalysisStatus.DONE:
        raise AnalysisNotReady(analysis.status.value)
    project = service.get_project(db, analysis.project_id)
    history = versions.list_versions(db, analysis)
    selected = versions.get_version(db, analysis, version) if version is not None else None
    if selected is None and history:
        selected = history[-1]
    body: bytes | str
    if format == "pdf":
        body = engine.render_pdf(analysis, project, version=selected, versions=history)
    elif format == "html":
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
