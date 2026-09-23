"""Audit log read endpoint: ``GET /api/v1/audit`` (P5 day 19, "full audit log").

Scope by role, deny by default: the admin reads everything; an analyst or a
developer reads only rows whose actor is themselves (docs/roles-and-permissions.md,
with the "own projects" narrowing recorded in tasks/phase5-survey.md §7).
Justifications and targets are the writers' text; the screen renders them
as text.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth.deps import ActiveUser
from app.auth.models import Role
from app.db.session import get_db

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

DbSession = Annotated[Session, Depends(get_db)]
MAX_LIMIT = 500


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    occurred_at: datetime
    actor_username: str
    actor_role: str | None
    action: str
    target: str | None
    outcome: AuditOutcome
    justification: str | None


@router.get("", response_model=list[AuditEntryOut])
def list_audit(
    user: ActiveUser,
    db: DbSession,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 200,
) -> list[AuditEntryOut]:
    """The trail, newest first; ``since`` bounds it, ``limit`` caps it."""
    statement = select(AuditLogEntry)
    if user.role is not Role.ADMIN:
        statement = statement.where(AuditLogEntry.actor_username == user.username)
    if since is not None:
        statement = statement.where(AuditLogEntry.occurred_at >= since)
    statement = statement.order_by(AuditLogEntry.occurred_at.desc()).limit(limit)
    return [AuditEntryOut.model_validate(row) for row in db.scalars(statement)]
