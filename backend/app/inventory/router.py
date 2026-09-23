"""Inventory endpoints: ``/api/v1/inventory`` (P5 day 18).

Reading is open to the three roles; refreshing the mirror (sync request,
dump import) is the admin's and the analyst's, with a written reason and an
audit row (docs/roles-and-permissions.md → inventory rows). No handler here
performs outbound I/O: the two mutations ENQUEUE.
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, Request, Response, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.deps import ActiveUser, client_ip, require_roles
from app.auth.models import Role, User
from app.core.config import get_settings
from app.db.session import get_db
from app.ingest import service as ingest_service
from app.inventory import documents, service, sync
from app.inventory.errors import DumpTooLarge, SbomMissing
from app.reports.engine import report_file_name

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])

DbSession = Annotated[Session, Depends(get_db)]
MirrorUser = Annotated[User, Depends(require_roles(Role.ADMIN, Role.ANALYST))]

CYCLONEDX_MEDIA_TYPE = "application/vnd.cyclonedx+json; version=1.6"


class JustificationIn(BaseModel):
    justification: str = Field(max_length=8000)


class TotalsOut(BaseModel):
    projects: int
    components: int
    vulnerable_components: int
    open_cves: int
    not_affected: int
    outdated: int
    uncomparable: int
    by_severity: dict[str, int]
    capped: bool


class LicenseOut(BaseModel):
    name: str
    count: int


class ProjectRowOut(BaseModel):
    project_id: str
    project_name: str
    analysis_id: str
    ordinal: int
    analysed_at: str
    components: int
    outdated: int
    open_cves: int
    vulnerable_components: int
    trend: int | None
    previous_analysis_id: str | None


class OpenRowOut(BaseModel):
    project_id: str
    project_name: str
    analysis_id: str
    component: str
    version: str | None
    ecosystem: str | None
    vulnerability_id: str
    cve: str
    score: float | None
    severity: str | None
    fixed_in: str | None
    summary: str | None
    vex_state: str
    justification: str | None
    verdict_by: str | None


class CryptoRowOut(BaseModel):
    primitive: str
    algorithm: str
    weak: bool
    occurrences: int
    path: str
    line: int | None


class SyncRunOut(BaseModel):
    source: str
    status: str
    started_at: str
    finished_at: str | None
    records_stored: int
    records_skipped: int
    requested_by: str | None


class VulnDbOut(BaseModel):
    last_update: str | None
    sync_enabled: bool
    interval_hours: int
    runs: list[SyncRunOut]


class InventoryOut(BaseModel):
    totals: TotalsOut
    licenses: list[LicenseOut]
    unlicensed: int
    projects: list[ProjectRowOut]
    open: list[OpenRowOut]
    crypto: list[CryptoRowOut]
    crypto_weak: int
    vulndb: VulnDbOut


class ImportAcceptedOut(BaseModel):
    token: str


@router.get("", response_model=InventoryOut)
def get_inventory(_user: ActiveUser, db: DbSession) -> InventoryOut:
    """The factory-wide panel (mockup 11). Reads the mirror; queries nothing live."""
    return InventoryOut(**service.overview(db, get_settings()))


def _analysis_with_sbom(db: Session, analysis_id: uuid.UUID) -> Any:
    analysis = ingest_service.get_analysis(db, analysis_id)
    if analysis.sbom is None:
        raise SbomMissing(str(analysis_id))
    return analysis


def _document_response(document: dict[str, Any], filename: str) -> Response:
    body = json.dumps(document, ensure_ascii=True, separators=(",", ":"))
    return Response(
        content=body,
        media_type=CYCLONEDX_MEDIA_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/analyses/{analysis_id}/cbom")
def get_cbom(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> Response:
    """The cryptographic bill of materials of one analysis, CycloneDX 1.6."""
    analysis = ingest_service.get_analysis(db, analysis_id)
    document = documents.cbom_document(analysis, service.crypto_assets_of(db, analysis))
    project = ingest_service.get_project(db, analysis.project_id)
    return _document_response(document, report_file_name(project.name, "cbom.cdx.json"))


@router.get("/analyses/{analysis_id}/vex")
def get_vex(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> Response:
    """The VEX document: the analyst's E3 verdicts over the correlated advisories."""
    analysis = _analysis_with_sbom(db, analysis_id)
    inventory = service.inventory_of(db, analysis)
    project = ingest_service.get_project(db, analysis.project_id)
    document = documents.vex_document(analysis, inventory.matches)
    return _document_response(document, report_file_name(project.name, "vex.cdx.json"))


@router.get("/analyses/{analysis_id}/components.csv")
def get_components_csv(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> Response:
    """The component table as CSV, every cell neutralised against formula injection."""
    analysis = _analysis_with_sbom(db, analysis_id)
    inventory = service.inventory_of(db, analysis)
    project = ingest_service.get_project(db, analysis.project_id)
    body = documents.components_csv(
        project.name, inventory.components, inventory.matches, inventory.outdated
    )
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report_file_name(project.name, "csv")}"'
        },
    )


@router.post("/vulndb/sync", status_code=status.HTTP_202_ACCEPTED)
def post_sync(
    payload: JustificationIn, request: Request, user: MirrorUser, db: DbSession
) -> Response:
    """ "Actualizar la base ahora": enqueue the sync job; this handler downloads nothing."""
    sync.request_sync(
        db, actor=user, justification=payload.justification, source_ip=client_ip(request)
    )
    return Response(status_code=status.HTTP_202_ACCEPTED)


@router.post(
    "/vulndb/import", response_model=ImportAcceptedOut, status_code=status.HTTP_202_ACCEPTED
)
def post_import(
    request: Request,
    user: MirrorUser,
    db: DbSession,
    file: Annotated[UploadFile, File()],
    justification: Annotated[str, Form(max_length=8000)],
) -> ImportAcceptedOut:
    """ "Importar base de vulnerabilidades": spool the dump; the worker parses it."""
    declared = request.headers.get("content-length")
    if (
        declared is not None
        and declared.isdigit()
        and int(declared) > get_settings().vulndb_max_dump_bytes
    ):
        raise DumpTooLarge(f"content-length {declared}")
    token = sync.request_import(
        db,
        actor=user,
        upload=file.file,
        upload_size=file.size,
        filename=file.filename or "",
        justification=justification,
        source_ip=client_ip(request),
    )
    return ImportAcceptedOut(token=token)
