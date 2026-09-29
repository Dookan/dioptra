"""Cancelling an analysis (phase 12, `tasks/phase12-survey.md`).

Graceful, as `mmarin` defined it: not an error (its own status, CANCELLED);
it stops in seconds; it never collides with the finish. This module is the
API's half. A QUEUED analysis has no worker yet, so the request closes it at
once and removes its spool. A RUNNING one belongs to its worker: the request
only records ``cancel_requested_at``, and the worker — which polls it between
slices of every tool, the clone and the extraction — kills its tool, discards
its rows and closes the row itself (``pipeline._cancel``). The API never
deletes files a worker is using.

No written reason (§7.2, CLAUDE.md → Hard Rules → Auth, the second recorded
exception): it must be fast and without friction. The audit rows name who and
when, and each is written only by the conditional update that moved the row,
so a second click, a race or a 409 never adds one.
"""

from __future__ import annotations

import uuid

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, AnalysisStatus
from app.analysis.sweep import remove_analysis_tree, sweep_quietly
from app.audit import service as audit
from app.audit.models import AuditOutcome
from app.auth.errors import Forbidden
from app.auth.models import Role, User
from app.core.clock import utc_now
from app.core.config import Settings
from app.ingest import service
from app.ingest.errors import AnalysisNotCancellable


def may_cancel(actor: User, analysis: Analysis) -> bool:
    """The creator — while still analyst or admin — or any admin (§7.1)."""
    if actor.role is Role.ADMIN:
        return True
    return actor.role is Role.ANALYST and analysis.created_by_id == actor.id


def request_cancel(
    db: Session,
    settings: Settings,
    *,
    actor: User,
    analysis_id: uuid.UUID,
    source_ip: str | None,
) -> Analysis:
    """Cancel a QUEUED analysis, or ask its worker to stop a RUNNING one."""
    # The sweep first: a cancel whose worker died is closed here, on the next
    # click after the grace, not at the next ingest (survey §9.1).
    sweep_quietly(db, settings)
    analysis = service.get_analysis(db, analysis_id)
    if not may_cancel(actor, analysis):
        audit.record(
            db,
            actor_username=actor.username,
            actor_id=actor.id,
            actor_role=actor.role.value,
            action="authz.denied",
            outcome=AuditOutcome.DENIED,
            target=f"analysis {analysis_id} cancel",
            source_ip=source_ip,
        )
        db.commit()
        message = f"{actor.username} may not cancel analysis {analysis_id}"
        raise Forbidden(message)

    now = utc_now()
    queued = db.execute(
        update(Analysis)
        .where(Analysis.id == analysis_id, Analysis.status == AnalysisStatus.QUEUED)
        .values(status=AnalysisStatus.CANCELLED, cancel_requested_at=now, finished_at=now)
    )
    if _moved(queued):
        _audit(db, actor, "analysis.cancel.request", analysis_id, source_ip)
        _audit(db, actor, "analysis.cancel", analysis_id, source_ip)
        db.commit()
        # No worker holds a queued analysis: only its spool is on disk. Its
        # queue message stays and finds the row no longer QUEUED (1.5.1).
        remove_analysis_tree(settings, analysis.project_id, analysis_id)
        return _fresh(db, analysis_id)

    running = db.execute(
        update(Analysis)
        .where(
            Analysis.id == analysis_id,
            Analysis.status == AnalysisStatus.RUNNING,
            Analysis.cancel_requested_at.is_(None),
        )
        .values(cancel_requested_at=now)
    )
    if _moved(running):
        _audit(db, actor, "analysis.cancel.request", analysis_id, source_ip)
        db.commit()
        return _fresh(db, analysis_id)

    db.rollback()
    current = _fresh(db, analysis_id)
    if current.status is AnalysisStatus.RUNNING:
        return current  # already asked: the same answer, no second row
    raise AnalysisNotCancellable(current.status.value)


def _moved(result: object) -> bool:
    return getattr(result, "rowcount", 0) == 1


def _audit(
    db: Session, actor: User, action: str, analysis_id: uuid.UUID, source_ip: str | None
) -> None:
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action=action,
        target=str(analysis_id),
        source_ip=source_ip,
    )


def _fresh(db: Session, analysis_id: uuid.UUID) -> Analysis:
    """The row as it is NOW: a conditional update does not refresh loaded objects."""
    db.expire_all()
    return service.get_analysis(db, analysis_id)
