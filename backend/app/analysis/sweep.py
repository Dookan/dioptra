"""Close the analyses a dead worker left behind, and the spools nobody will read.

Hardening 1.5.1 (`tasks/hardening-1.5.1-survey.md` §2, §5.1). No ``finally``
survives a killed process, so four things could outlive their purpose: a
partial ``upload.zip`` of an API killed mid-upload (no row), a spool whose
queue message was lost (QUEUED forever), and a worker killed during or after
extraction (RUNNING forever, spool and jail on disk). Up to 1 GiB of spool and
8 GiB of jail each, and a progress bar that never ends.

The sweep runs at API start-up and before each ingest, like the PDF export's
(``reports/jobs.py``). Every transition is conditional on the state it read,
so a pipeline that finishes at the same instant keeps its outcome, and the
pipeline's own transitions are conditional too (``pipeline.run_pipeline``),
so it cannot turn an abandoned row back into DONE. Nothing a person owns is
deleted: a finished analysis keeps its jail, only a stray spool goes.
"""

from __future__ import annotations

import logging
import shutil
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, AnalysisStatus, RawToolOutput, ToolRun
from app.audit import service as audit
from app.auth.models import SYSTEM_ACTOR
from app.core.clock import utc_now
from app.core.config import Settings
from app.ingest.upload import UPLOAD_NAME

logger = logging.getLogger("dioptra.sweep")

ABANDONED = "analysis_abandoned"
TERMINAL = frozenset({AnalysisStatus.DONE, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED})


@dataclass(frozen=True)
class AnalysisSweepStats:
    abandoned: int
    orphans_removed: int
    spools_removed: int
    cancelled: int = 0
    cancelled_trees_removed: int = 0


def sweep_analyses(
    db: Session, settings: Settings, *, now: datetime | None = None
) -> AnalysisSweepStats:
    """Abandon stale analyses, then clear the spools the pipeline never took. Commits."""
    now = now or utc_now()
    stale_running = now - timedelta(minutes=settings.analysis_stale_minutes)
    stale_queued = now - timedelta(hours=settings.analysis_queue_retention_hours)
    cancelled = _close_unanswered_cancels(
        db, settings, now, now - timedelta(minutes=settings.analysis_cancel_grace_minutes)
    )
    abandoned = _abandon_stale(db, settings, now, stale_running, stale_queued)
    orphans, spools = _clear_spools(db, settings, stale_running)
    trees = _clear_cancelled_trees(db, settings, stale_running)
    if abandoned or orphans or spools or cancelled or trees:
        logger.info(
            "analysis sweep abandoned=%s orphans=%s spools=%s cancelled=%s trees=%s",
            abandoned,
            orphans,
            spools,
            cancelled,
            trees,
        )
    return AnalysisSweepStats(abandoned, orphans, spools, cancelled, trees)


def _close_unanswered_cancels(
    db: Session, settings: Settings, now: datetime, asked_before: datetime
) -> int:
    """A cancel nobody answered: the worker died. Close it CANCELLED (phase 12).

    A live worker stops within seconds of the request, so a request older than
    the grace means no worker holds the row. Same outcome as the worker's own
    path: the run's rows deleted, the files removed, one audit row by
    ``system`` — written only if THIS update moved the row.
    """
    pending = (Analysis.status == AnalysisStatus.RUNNING) & (
        Analysis.cancel_requested_at < asked_before
    )
    candidates = db.execute(select(Analysis.id, Analysis.project_id).where(pending)).all()
    closed_count = 0
    for analysis_id, project_id in candidates:
        closed = db.execute(
            update(Analysis)
            .where(Analysis.id == analysis_id, pending)
            .values(status=AnalysisStatus.CANCELLED, current_step=None, finished_at=now)
        )
        if getattr(closed, "rowcount", 0) != 1:
            continue
        db.execute(delete(ToolRun).where(ToolRun.analysis_id == analysis_id))
        db.execute(delete(RawToolOutput).where(RawToolOutput.analysis_id == analysis_id))
        audit.record(
            db, actor_username=SYSTEM_ACTOR, action="analysis.cancel", target=str(analysis_id)
        )
        db.commit()
        remove_analysis_tree(settings, project_id, analysis_id)
        closed_count += 1
    db.commit()
    return closed_count


def _clear_cancelled_trees(db: Session, settings: Settings, finished_before: datetime) -> int:
    """The files a cancel left because its tool's kill was not confirmed.

    Only once the stale window has passed since the cancel — a backstop, not a
    proof: a container whose ``docker kill`` failed has no timeout left (its
    client was killed), so it runs until its tool ends by itself. Removing
    the tree then needs a sick Docker daemon to matter, and the stale window
    is the pipeline's own upper bound.
    """
    rows = db.execute(
        select(Analysis.id, Analysis.project_id).where(
            Analysis.status == AnalysisStatus.CANCELLED, Analysis.finished_at < finished_before
        )
    ).all()
    removed = 0
    for analysis_id, project_id in rows:
        directory = _analysis_dir(settings, project_id, analysis_id)
        if directory is not None and directory.is_dir() and not directory.is_symlink():
            remove_analysis_tree(settings, project_id, analysis_id)
            removed += 1
    return removed


def _abandon_stale(
    db: Session,
    settings: Settings,
    now: datetime,
    stale_running: datetime,
    stale_queued: datetime,
) -> int:
    # A RUNNING row with a cancel pending is the cancel pass's: it must end
    # CANCELLED, never FAILED `analysis_abandoned` (phase 12, invariant panel).
    running = (
        (Analysis.status == AnalysisStatus.RUNNING)
        & (Analysis.started_at < stale_running)
        & Analysis.cancel_requested_at.is_(None)
    )
    queued = (Analysis.status == AnalysisStatus.QUEUED) & (Analysis.created_at < stale_queued)
    candidates = db.execute(
        select(Analysis.id, Analysis.project_id, Analysis.status).where(or_(running, queued))
    ).all()
    abandoned = 0
    for analysis_id, project_id, status in candidates:
        condition = running if status is AnalysisStatus.RUNNING else queued
        closed = db.execute(
            update(Analysis)
            .where(Analysis.id == analysis_id, condition)
            .values(
                status=AnalysisStatus.FAILED,
                failure_code=ABANDONED,
                current_step=None,
                finished_at=now,
            )
        )
        if getattr(closed, "rowcount", 0) != 1:
            continue  # it moved on between the read and the update: its outcome stands
        audit.record(
            db,
            actor_username=SYSTEM_ACTOR,
            action="analysis.abandon",
            target=f"{analysis_id} was {status.value}",
        )
        db.commit()
        remove_analysis_tree(settings, project_id, analysis_id)
        abandoned += 1
    db.commit()
    return abandoned


def _analysis_dir(settings: Settings, project_id: uuid.UUID, analysis_id: uuid.UUID) -> Path | None:
    """The directory to delete, BUILT from ids and checked to stay under the root."""
    root = settings.workspace_root.resolve()
    directory = (root / str(project_id) / str(analysis_id)).resolve()
    if not directory.is_relative_to(root) or directory == root:
        return None
    return directory


def remove_analysis_tree(settings: Settings, project_id: uuid.UUID, analysis_id: uuid.UUID) -> None:
    directory = _analysis_dir(settings, project_id, analysis_id)
    if directory is not None:
        shutil.rmtree(directory, ignore_errors=True)


def _uuid_dirs(parent: Path) -> list[tuple[uuid.UUID, Path]]:
    """The children of ``parent`` that are real directories named by a uuid."""
    found: list[tuple[uuid.UUID, Path]] = []
    try:
        entries = sorted(parent.iterdir())
    except OSError:
        return found
    for entry in entries:
        try:
            if not stat.S_ISDIR(entry.lstat().st_mode):  # never a symlink
                continue
            ident = uuid.UUID(entry.name)
            if str(ident) != entry.name:
                # Not the canonical spelling the platform writes: the path the
                # sweep rebuilds from the id would miss it — so it is not ours.
                continue
            found.append((ident, entry))
        except (OSError, ValueError):
            continue
    return found


def _clear_spools(db: Session, settings: Settings, older_than: datetime) -> tuple[int, int]:
    """Remove ``upload.zip`` spools older than the stale window that no pipeline will take.

    No row: an upload whose API died before the commit — the whole directory
    goes. A finished row: a spool its ``finally`` never removed — the spool
    alone goes, the jail IS the analysis. QUEUED and RUNNING are the other
    pass's. A young spool is never touched: its upload may still be arriving.
    """
    root = settings.workspace_root
    if not root.is_dir():
        return 0, 0
    cutoff = older_than.timestamp()
    orphans = spools = 0
    for project_id, project_dir in _uuid_dirs(root):
        for analysis_id, analysis_dir in _uuid_dirs(project_dir):
            spool = analysis_dir / UPLOAD_NAME
            try:
                info = spool.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_mtime >= cutoff:
                continue
            row = db.get(Analysis, analysis_id)
            if row is None:
                remove_analysis_tree(settings, project_id, analysis_id)
                orphans += 1
            elif row.status in TERMINAL:
                # A cancelled row's jail is `_clear_cancelled_trees`'s, after the
                # stale window: removing it here could pull it from under a
                # container whose kill was not confirmed.
                spool.unlink(missing_ok=True)
                spools += 1
    return orphans, spools


def sweep_quietly(db: Session, settings: Settings) -> None:
    """``sweep_analyses`` for request paths and start-up: a failure is logged, never raised."""
    try:
        sweep_analyses(db, settings)
    except Exception:  # noqa: BLE001 — the next sweep tries again
        db.rollback()
        logger.warning("analysis sweep failed", exc_info=True)
