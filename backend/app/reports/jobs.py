"""Asynchronous PDF export: the request, the worker job, the download, the sweep.

Phase 8 (``tasks/phase8-survey.md``). A 516-page institutional PDF takes ~50 s,
all of it WeasyPrint; this module does not make it faster (survey §7.4). It
moves the render out of the request into the worker, the same shape as the
inventory's sync: the handler audits and enqueues, the worker renders and
writes its own audit row, and no request handler ever calls ``render_pdf``.

Rules held here, each decided by ``mmarin`` in the survey:

- one PDF in flight per person — a partial unique index, not a read-then-insert
  check (§7.1);
- at most ``max_concurrent_report_jobs`` RUNNING across the installation; a job
  over the cap is ACCEPTED and waits rather than being refused (§7.1);
- the requester or the admin downloads; anyone else is told the job does not
  exist (§7.2);
- the file is deleted once downloaded, a finished file nobody took is swept
  after ``report_job_retention_hours``, and the spool has a byte cap (§7.3).
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, cast

from sqlalchemy import func, select, text, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.analysis.models import AnalysisStatus
from app.audit import service as audit
from app.audit.models import AuditOutcome
from app.auth.models import Role, User
from app.core.clock import as_utc, utc_now
from app.core.config import Settings, get_settings
from app.db.session import get_session_factory
from app.ingest import service
from app.ingest.errors import AnalysisNotReady
from app.reports import engine, versions
from app.reports.errors import (
    ReportEnqueueFailed,
    ReportJobInFlight,
    ReportJobNotFound,
    ReportJobNotReady,
)
from app.reports.models import IN_FLIGHT, ReportJob, ReportJobStatus

logger = logging.getLogger("dioptra.reports.jobs")

#: Seconds a job deferred by the concurrency cap waits before asking again.
DEFER_SECONDS = 5
#: One constant key for PostgreSQL's advisory lock around the claim, so two
#: workers cannot both count "one below the cap" and both start.
_CLAIM_LOCK_KEY = 0x44494F50  # "DIOP"
_SUFFIX = ".pdf"


class _Claim(Enum):
    RUN = "run"
    DEFER = "defer"
    GONE = "gone"


def artefact_path(settings: Settings, job_id: uuid.UUID) -> Path:
    """The spool file of one job. Built from the uuid, never from a column."""
    return settings.report_spool_dir / f"{job_id}{_SUFFIX}"


# --- sweep ----------------------------------------------------------------------


@dataclass(frozen=True)
class SweepStats:
    abandoned: int
    expired: int
    strays: int
    #: QUEUED jobs whose broker message may be lost: enqueue them again once
    #: the caller has committed (``requeue``).
    requeued: tuple[uuid.UUID, ...] = ()


def sweep(db: Session, settings: Settings, *, now: datetime | None = None) -> SweepStats:
    """Free abandoned slots, expire old artefacts, remove files no job owns.

    Each in-flight state is judged by its own clock (``mmarin``, phase-8 panel):

    - a RUNNING job that started longer ago than the stale threshold is
      abandoned — the setting is floored above the render's RQ timeout, so a
      render still in progress never is;
    - a QUEUED job is NOT abandoned for waiting: a long queue behind one report
      worker is normal. When its last enqueue is older than the stale
      threshold its message may be lost (a broker restart), so it is enqueued
      AGAIN — harmless, because only a job still QUEUED is ever rendered —
      and it is abandoned only after ``report_job_retention_hours``.

    Called at API start-up and before every request and claim. The caller
    commits, then calls ``requeue(stats.requeued)``.
    """
    now = now or utc_now()
    stale_before = now - timedelta(minutes=settings.report_job_stale_minutes)
    expire_before = now - timedelta(hours=settings.report_job_retention_hours)
    abandoned = 0
    for condition in (
        (ReportJob.status == ReportJobStatus.RUNNING)
        & (func.coalesce(ReportJob.started_at, ReportJob.created_at) < stale_before),
        (ReportJob.status == ReportJobStatus.QUEUED) & (ReportJob.created_at < expire_before),
    ):
        result = db.execute(
            update(ReportJob)
            .where(condition)
            .values(status=ReportJobStatus.ERRORED, detail="abandoned", finished_at=now)
            .execution_options(synchronize_session=False)
        )
        abandoned += int(cast("CursorResult[Any]", result).rowcount or 0)

    lost = tuple(
        db.scalars(
            select(ReportJob.id).where(
                ReportJob.status == ReportJobStatus.QUEUED,
                ReportJob.enqueued_at < stale_before,
            )
        )
    )
    if lost:
        db.execute(
            update(ReportJob)
            .where(ReportJob.id.in_(lost), ReportJob.status == ReportJobStatus.QUEUED)
            .values(enqueued_at=now)
            .execution_options(synchronize_session=False)
        )

    old = db.scalars(
        select(ReportJob).where(
            ReportJob.status == ReportJobStatus.DONE, ReportJob.finished_at < expire_before
        )
    ).all()
    for job in old:
        job.status = ReportJobStatus.EXPIRED
        artefact_path(settings, job.id).unlink(missing_ok=True)

    strays = _remove_strays(db, settings, stale_before)
    if abandoned or old or strays or lost:
        logger.info(
            "report sweep abandoned=%s expired=%s strays=%s requeued=%s",
            abandoned,
            len(old),
            strays,
            len(lost),
        )
    return SweepStats(abandoned=abandoned, expired=len(old), strays=strays, requeued=lost)


def requeue(job_ids: tuple[uuid.UUID, ...]) -> None:
    """Enqueue again the jobs a sweep found waiting on a possibly lost message.

    After the commit, never inside it; a broker still down is logged and the
    next sweep tries again.
    """
    if not job_ids:
        return
    from app.core.queue import enqueue_report  # noqa: PLC0415

    for job_id in job_ids:
        try:
            enqueue_report(job_id)
        except Exception:  # noqa: BLE001 — retried by the next sweep
            logger.warning("could not re-enqueue report job %s", job_id, exc_info=True)


def sweep_and_requeue(db: Session, settings: Settings) -> SweepStats:
    """``sweep``, commit, then ``requeue`` — what every request-side caller wants."""
    stats = sweep(db, settings)
    db.commit()
    requeue(stats.requeued)
    return stats


def _remove_strays(db: Session, settings: Settings, older_than: datetime) -> int:
    """Delete spool files that belong to no DONE job.

    Only files older than the stale threshold: a worker writes the file and
    THEN commits DONE, so a younger file may be one whose row is a moment away.
    """
    spool = settings.report_spool_dir
    if not spool.is_dir():
        return 0
    live = {
        str(job_id)
        for job_id in db.scalars(
            select(ReportJob.id).where(ReportJob.status == ReportJobStatus.DONE)
        )
    }
    removed = 0
    cutoff = older_than.timestamp()
    for entry in spool.iterdir():
        if entry.is_symlink() or not entry.is_file():
            continue
        if entry.name.removesuffix(_SUFFIX) in live and entry.name.endswith(_SUFFIX):
            continue
        try:
            if entry.stat().st_mtime >= cutoff:
                continue
            entry.unlink(missing_ok=True)
            removed += 1
        except OSError:
            logger.warning("could not remove stray report file %s", entry.name)
    return removed


def _spool_bytes(settings: Settings) -> int:
    spool = settings.report_spool_dir
    if not spool.is_dir():
        return 0
    total = 0
    for entry in spool.iterdir():
        try:
            if entry.is_file() and not entry.is_symlink():
                total += entry.stat().st_size
        except OSError:
            continue
    return total


# --- what the request handlers call ----------------------------------------------


def in_flight_for(db: Session, username: str) -> ReportJob | None:
    return db.scalars(
        select(ReportJob).where(
            ReportJob.requested_by_username == username, ReportJob.status.in_(IN_FLIGHT)
        )
    ).first()


def request_pdf(
    db: Session,
    *,
    actor: User,
    analysis_id: uuid.UUID,
    version: int | None,
    source_ip: str | None,
) -> ReportJob:
    """Audit the request, insert the job, enqueue it. Renders nothing."""
    settings = get_settings()
    sweep_and_requeue(db, settings)
    analysis = service.get_analysis(db, analysis_id)
    if analysis.status is not AnalysisStatus.DONE:
        raise AnalysisNotReady(analysis.status.value)
    if version is not None:
        versions.get_version(db, analysis, version)  # typed 404 when it does not exist
    current = in_flight_for(db, actor.username)
    if current is not None:
        raise ReportJobInFlight(actor.username, context={"job": str(current.id)})

    job = ReportJob(
        analysis_id=analysis.id,
        version=version,
        format="pdf",
        requested_by_username=actor.username,
        requested_by_id=actor.id,
    )
    try:
        db.add(job)
        # The INSERT reaches the index HERE, not at commit: `audit.record`
        # flushes the session. Both must sit inside the `try`, or a lost race
        # escapes as a raw IntegrityError (coverage adversary, phase-8 panel).
        audit.record(
            db,
            actor_username=actor.username,
            actor_id=actor.id,
            actor_role=actor.role.value,
            action="report.export.request",
            target=f"{analysis.id} pdf v={version if version is not None else 'current'}",
            source_ip=source_ip,
        )
        db.commit()
    except IntegrityError as exc:
        # The index won a race the pre-check lost: same answer, same context.
        db.rollback()
        current = in_flight_for(db, actor.username)
        context = {"job": str(current.id)} if current is not None else None
        raise ReportJobInFlight(actor.username, context=context) from exc

    from app.core.queue import enqueue_report  # noqa: PLC0415

    try:
        enqueue_report(job.id)
    except Exception as exc:
        # A broker outage must not leave the person blocked by a job no worker
        # will ever see: the row closes, the client gets the typed contract.
        db.rollback()
        db.execute(
            update(ReportJob)
            .where(ReportJob.id == job.id, ReportJob.status == ReportJobStatus.QUEUED)
            .values(status=ReportJobStatus.ERRORED, detail="enqueue_failed", finished_at=utc_now())
        )
        db.commit()
        raise ReportEnqueueFailed(exc.__class__.__name__) from exc
    db.refresh(job)
    return job


def get_for(db: Session, *, actor: User, job_id: uuid.UUID, source_ip: str | None) -> ReportJob:
    """The job, for its requester or the admin; anyone else gets a 404 and a row."""
    job = db.get(ReportJob, job_id)
    if job is None:
        raise ReportJobNotFound(str(job_id))
    if actor.role is Role.ADMIN or job.requested_by_username == actor.username:
        return job
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="authz.denied",
        outcome=AuditOutcome.DENIED,
        target=f"report_job {job_id}",
        source_ip=source_ip,
    )
    db.commit()
    raise ReportJobNotFound(str(job_id))


def latest_for(db: Session, *, actor: User) -> ReportJob | None:
    """The caller's newest job still worth showing after a reload.

    In flight, or finished and not yet taken — so a person who reloads the page
    while their PDF renders gets the toast back, and one whose PDF finished
    while the tab was closed still receives it.
    """
    settings = get_settings()
    sweep_and_requeue(db, settings)
    return db.scalars(
        select(ReportJob)
        .where(
            ReportJob.requested_by_username == actor.username,
            ReportJob.status.in_((*IN_FLIGHT, ReportJobStatus.DONE)),
        )
        .order_by(ReportJob.created_at.desc())
    ).first()


def queue_position(db: Session, job: ReportJob) -> int:
    """How many in-flight jobs were requested before this one (0 when not queued)."""
    if job.status is not ReportJobStatus.QUEUED:
        return 0
    count = db.scalar(
        select(func.count())
        .select_from(ReportJob)
        .where(ReportJob.status.in_(IN_FLIGHT), ReportJob.created_at < job.created_at)
    )
    return int(count or 0)


def take_artefact(
    db: Session, *, actor: User, job_id: uuid.UUID, source_ip: str | None
) -> tuple[bytes, str, Path]:
    """Read a finished PDF for download. The caller deletes the returned path
    once the response has been sent; the row is marked taken here."""
    settings = get_settings()
    job = get_for(db, actor=actor, job_id=job_id, source_ip=source_ip)
    path = artefact_path(settings, job.id)
    if job.status is not ReportJobStatus.DONE:
        raise ReportJobNotReady(job.status.value)
    try:
        body = path.read_bytes()
    except OSError as exc:
        job.status = ReportJobStatus.EXPIRED
        job.detail = "artefact_missing"
        db.commit()
        raise ReportJobNotReady("artefact missing") from exc
    analysis = service.get_analysis(db, job.analysis_id)
    project = service.get_project(db, analysis.project_id)
    job.status = ReportJobStatus.EXPIRED
    job.downloaded_at = utc_now()
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="report.export.download",
        target=f"{job.analysis_id} job={job.id}",
        source_ip=source_ip,
    )
    db.commit()
    return body, engine.report_file_name(project.name, "pdf"), path


# --- the worker -------------------------------------------------------------------


def _claim(
    db: Session, job_id: uuid.UUID, settings: Settings
) -> tuple[_Claim, tuple[uuid.UUID, ...]]:
    """Mark the job RUNNING if the cap allows it. Commits either way.

    Also returns what the sweep wants re-enqueued; the caller does it after.
    """
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _CLAIM_LOCK_KEY})
    requeued = sweep(db, settings).requeued
    job = db.get(ReportJob, job_id)
    if job is None or job.status is not ReportJobStatus.QUEUED:
        db.commit()
        return _Claim.GONE, requeued
    running = db.scalar(
        select(func.count())
        .select_from(ReportJob)
        .where(ReportJob.status == ReportJobStatus.RUNNING)
    )
    if int(running or 0) >= settings.max_concurrent_report_jobs:
        # A deferral IS an enqueue: without this the sweep would add a second
        # message chain for a job that is merely waiting its turn.
        job.enqueued_at = utc_now()
        db.commit()
        return _Claim.DEFER, tuple(i for i in requeued if i != job_id)
    job.status = ReportJobStatus.RUNNING
    job.started_at = utc_now()
    db.commit()
    return _Claim.RUN, tuple(i for i in requeued if i != job_id)


def _finish(
    db: Session,
    job: ReportJob,
    *,
    status: ReportJobStatus,
    detail: str | None,
    size: int | None,
    rendered_version: int | None = None,
) -> bool:
    """Close a RUNNING job. Returns False when the sweep closed it first.

    Conditional on the row still being RUNNING: a job the sweep already marked
    abandoned must not be turned back into DONE, nor get a second outcome row
    in the trail (security auditor, phase-8 panel).
    """
    now = utc_now()
    result = db.execute(
        update(ReportJob)
        .where(ReportJob.id == job.id, ReportJob.status == ReportJobStatus.RUNNING)
        .values(status=status, detail=detail, byte_size=size, finished_at=now)
        .execution_options(synchronize_session=False)
    )
    if int(cast("CursorResult[Any]", result).rowcount or 0) == 0:
        db.rollback()
        logger.warning("report job %s was closed by the sweep while it rendered", job.id)
        return False
    version = f" v={rendered_version}" if rendered_version is not None else ""
    audit.record(
        db,
        # The actor comes from the ROW, never from the broker's job arguments.
        actor_username=job.requested_by_username,
        actor_id=job.requested_by_id,
        action="report.export",
        outcome=AuditOutcome.OK if status is ReportJobStatus.DONE else AuditOutcome.ERROR,
        # The version actually RENDERED: a request for "the current one" says
        # which one that turned out to be (invariant checker, phase-8 panel).
        target=f"{job.analysis_id} job={job.id}{version}" + (f" {detail}" if detail else ""),
    )
    db.commit()
    return True


def _write_artefact(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # O_EXCL: the name is the job id, so an existing file is never ours to reuse.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(body)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def run_report_job(job_id: str) -> None:
    """RQ entry point for one PDF export. Never raises: every outcome is a row."""
    try:
        parsed = uuid.UUID(str(job_id))
    except ValueError:
        logger.error("refusing report job with a malformed id")
        return
    settings = get_settings()
    with get_session_factory()() as db:
        claim, requeued = _claim(db, parsed, settings)
        requeue(requeued)
        if claim is _Claim.GONE:
            return
        if claim is _Claim.DEFER:
            from app.core.queue import enqueue_report  # noqa: PLC0415

            try:
                enqueue_report(parsed, delay_seconds=DEFER_SECONDS)
            except Exception:  # noqa: BLE001 — the stale sweep frees the slot eventually
                logger.exception("could not defer report job %s", parsed)
            return

        job = db.get(ReportJob, parsed)
        if job is None:  # pragma: no cover — claimed a moment ago in this session
            return
        try:
            analysis = service.get_analysis(db, job.analysis_id)
            project = service.get_project(db, analysis.project_id)
            history = versions.list_versions(db, analysis)
            selected = (
                versions.get_version(db, analysis, job.version)
                if job.version is not None
                else (history[-1] if history else None)
            )
            body = engine.render_pdf(analysis, project, version=selected, versions=history)
        except Exception:  # noqa: BLE001 — logged server-side; the row says render_failed
            logger.exception("report job %s failed to render", parsed)
            db.rollback()
            job = db.get(ReportJob, parsed)
            if job is not None:
                _finish(db, job, status=ReportJobStatus.ERRORED, detail="render_failed", size=None)
            return

        if _spool_bytes(settings) + len(body) > settings.report_spool_max_bytes:
            _finish(db, job, status=ReportJobStatus.ERRORED, detail="spool_full", size=None)
            return
        path = artefact_path(settings, job.id)
        try:
            _write_artefact(path, body)
        except OSError:
            logger.exception("report job %s could not write its artefact", parsed)
            _finish(db, job, status=ReportJobStatus.ERRORED, detail="write_failed", size=None)
            return
        rendered = selected.number if selected is not None else 1
        if not _finish(
            db,
            job,
            status=ReportJobStatus.DONE,
            detail=None,
            size=len(body),
            rendered_version=rendered,
        ):
            path.unlink(missing_ok=True)


def elapsed_seconds(job: ReportJob, *, now: datetime | None = None) -> int:
    """Seconds since the job started (or was requested), for the toast."""
    start = job.started_at or job.created_at
    end = job.finished_at or now or utc_now()
    return max(0, int((as_utc(end) - as_utc(start)).total_seconds()))
