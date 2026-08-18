"""The only supported way to write the audit trail.

There is deliberately no update or delete function anywhere in this module:
the append-only invariant is expressed in the API surface as well as in the
database triggers.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import AuditLogEntry, AuditOutcome


def _fit(value: str | None, limit: int) -> str | None:
    """Truncate an optional value to its column width, preserving None."""
    return value if value is None else value[:limit]


def record(
    session: Session,
    *,
    actor_username: str,
    action: str,
    outcome: AuditOutcome = AuditOutcome.OK,
    actor_id: uuid.UUID | None = None,
    actor_role: str | None = None,
    target: str | None = None,
    justification: str | None = None,
    source_ip: str | None = None,
) -> AuditLogEntry:
    """Append one entry. The caller commits with the surrounding transaction."""
    # Every bounded column is truncated to its width. `target` is the one that
    # actually receives untrusted length — deps.py writes "<METHOD> <path>" from
    # the request URL — and an over-long value would raise a driver DataError
    # inside the dependency, turning a 403 denial into a 500 AND losing the very
    # row that records the denial. The trail must never be what breaks a request.
    entry = AuditLogEntry(
        actor_username=actor_username[:64],
        actor_id=actor_id,
        actor_role=_fit(actor_role, 16),
        action=action[:64],
        outcome=outcome,
        target=_fit(target, 255),
        justification=justification,
        source_ip=_fit(source_ip, 45),
    )
    session.add(entry)
    session.flush()
    return entry


def entries_for_actor(
    session: Session, actor_username: str, limit: int = 100
) -> list[AuditLogEntry]:
    """Read the trail of one actor, newest first."""
    statement = (
        select(AuditLogEntry)
        .where(AuditLogEntry.actor_username == actor_username)
        .order_by(AuditLogEntry.occurred_at.desc())
        .limit(limit)
    )
    return list(session.scalars(statement))
