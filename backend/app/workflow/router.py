"""Workflow endpoints. Phase 2: ``POST /api/v1/findings/{id}/verdict`` (E3 triage)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth.deps import AnalystUser, client_ip
from app.db.session import get_db
from app.projects.schemas import FindingOut, VerdictIn, finding_out
from app.workflow import triage

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

DbSession = Annotated[Session, Depends(get_db)]


@router.post("/{finding_id}/verdict", response_model=FindingOut)
def post_verdict(
    finding_id: uuid.UUID,
    payload: VerdictIn,
    request: Request,
    user: AnalystUser,
    db: DbSession,
) -> FindingOut:
    """Stage E3: confirm a finding or discard it as a false positive, with a written reason.

    Analyst only (docs/roles-and-permissions.md): the admin and the developer
    receive 403 and an ``authz.denied`` audit row from the role dependency.
    """
    finding = triage.get_finding(db, finding_id)
    triage.record_verdict(
        db,
        finding=finding,
        actor=user,
        verdict=payload.verdict,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    return finding_out(finding)
