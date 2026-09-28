"""The vulnerability mirror's sync and import jobs, and the requests that enqueue them.

This module holds the ONLY outbound connection the platform ever opens
(``download``), and it runs in the worker as an RQ job. A request handler
never calls it: the panel's button and the file import both ENQUEUE and
return (Hard Rule "No CDNs", level 3; tasks/phase5-survey.md §2, §4).
"""

from __future__ import annotations

import logging
import re
import shutil
import ssl
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.audit.models import AuditOutcome

# SYSTEM_ACTOR is re-exported here for existing callers; auth refuses it as a
# username (RESERVED_USERNAMES), so a row by "system" is always the platform.
from app.auth.models import SYSTEM_ACTOR as SYSTEM_ACTOR
from app.auth.models import User
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.queue import SYNC_JOB_ID
from app.db.session import get_session_factory
from app.inventory import importers
from app.inventory.errors import (
    DumpInvalid,
    DumpKindUnknown,
    DumpTooLarge,
    EnqueueFailed,
    SyncDisabled,
)
from app.inventory.models import SyncSource, SyncStatus, VulnDbSync
from app.workflow.triage import clean_justification

logger = logging.getLogger("dioptra.inventory.sync")

_COPY_CHUNK = 1024 * 1024
#: A job argument is broker-writable; only a real username shape reaches the
#: audit trail as the actor, anything else is attributed to the system.
_ACTOR = re.compile(r"^[a-z]{2,64}$")


def actor_of(requested_by: str | None) -> str:
    if isinstance(requested_by, str) and _ACTOR.match(requested_by):
        return requested_by
    return SYSTEM_ACTOR


def next_sync_job_id(settings: Settings, now: float | None = None) -> str:
    """The id of the NEXT scheduled sync: the fixed id plus its time slot.

    The successor must NOT reuse the running job's id: RQ deletes the finished
    job's hash (`result_ttl=0`) — which would be the successor's — and the
    scheduler then drops the orphaned entry, ending the chain after one run
    (reproduced against a real worker by the day-18 precommit panel). A slot
    suffix keeps replicas deduplicated and every successor distinct from its
    predecessor.
    """
    interval = max(settings.vulndb_sync_interval_hours, 1) * 3600
    slot = int(now if now is not None else time.time()) // interval + 1
    return f"{SYNC_JOB_ID}-{slot}"


class DownloadFailed(DumpInvalid):
    code = "vulndb_download_failed"
    message_key = "errors.inventory.downloadFailed"


def _opener() -> urllib_request.OpenerDirector:
    """HTTPS only, certificate verification on, and NO redirect following.

    A redirect is how an https endpoint would turn into an http one, or into
    a host the operator never configured; refusing them keeps the connection
    exactly where the settings point.
    """
    context = ssl.create_default_context()
    opener = urllib_request.OpenerDirector()
    opener.add_handler(urllib_request.HTTPSHandler(context=context))
    opener.add_handler(urllib_request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib_request.HTTPErrorProcessor())
    return opener


def download(url: str, destination: Path, *, max_bytes: int, timeout_seconds: int) -> int:
    """Stream ``url`` into ``destination`` under a byte cap. Returns the size."""
    if not url.startswith("https://"):
        raise DownloadFailed("only https is allowed")
    written = 0
    try:
        with (
            _opener().open(url, timeout=timeout_seconds) as response,
            destination.open("wb") as out,
        ):
            if getattr(response, "status", 200) != 200:
                raise DownloadFailed(f"status {getattr(response, 'status', '?')}")
            while True:
                chunk = response.read(_COPY_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise DumpTooLarge(f"{url} exceeds {max_bytes} bytes")
                out.write(chunk)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        destination.unlink(missing_ok=True)
        raise DownloadFailed(exc.__class__.__name__) from exc
    except (DumpTooLarge, DumpInvalid):
        # Our own refusals (cap, non-200): the partial file goes too.
        destination.unlink(missing_ok=True)
        raise
    return written


def _record_run(
    db: Session,
    *,
    source: SyncSource,
    status: SyncStatus,
    stats: importers.ImportStats | None,
    detail: str | None,
    requested_by: str | None,
    started_at: datetime,
) -> None:
    db.add(
        VulnDbSync(
            source=source,
            status=status,
            started_at=started_at,
            finished_at=utc_now(),
            records_seen=stats.seen if stats else 0,
            records_stored=stats.stored if stats else 0,
            records_skipped=stats.skipped if stats else 0,
            detail=(detail or "")[:500] or None,
            requested_by_username=requested_by,
        )
    )
    db.commit()


def last_update(db: Session) -> VulnDbSync | None:
    """The most recent run that brought data in — the panel's "copia local del …"."""
    statement = (
        select(VulnDbSync)
        .where(VulnDbSync.status.in_([SyncStatus.OK, SyncStatus.PARTIAL]))
        .order_by(VulnDbSync.finished_at.desc())
        .limit(1)
    )
    return db.scalars(statement).first()


def recent_runs(db: Session, limit: int = 5) -> list[VulnDbSync]:
    statement = select(VulnDbSync).order_by(VulnDbSync.started_at.desc()).limit(limit)
    return list(db.scalars(statement))


def spool_path(settings: Settings, token: str, kind: str) -> Path:
    suffix = {"osv-zip": "zip", "nvd-json": "json", "nvd-json-gz": "json.gz"}[kind]
    return settings.vulndb_spool_dir / f"{token}.{suffix}"


def _sync_one(
    db: Session,
    settings: Settings,
    *,
    source: SyncSource,
    url: str,
    kind: str,
    requested_by: str | None,
) -> bool:
    started = utc_now()
    settings.vulndb_spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    spool = spool_path(settings, f"sync-{uuid.uuid4().hex}", kind)
    try:
        download(
            url,
            spool,
            max_bytes=settings.vulndb_max_dump_bytes,
            timeout_seconds=settings.vulndb_download_timeout_seconds,
        )
        stats = importers.import_dump(
            db, spool, kind=kind, max_bytes=settings.vulndb_max_dump_bytes
        )
    except (DumpInvalid, DumpTooLarge) as exc:
        db.rollback()
        _record_run(
            db,
            source=source,
            status=SyncStatus.FAILED,
            stats=None,
            detail=f"{url}: {exc.code}",
            requested_by=requested_by,
            started_at=started,
        )
        return False
    finally:
        spool.unlink(missing_ok=True)
    status = SyncStatus.OK if stats.skipped == 0 else SyncStatus.PARTIAL
    _record_run(
        db,
        source=source,
        status=status,
        stats=stats,
        detail=url,
        requested_by=requested_by,
        started_at=started,
    )
    return True


def stale(db: Session, settings: Settings) -> bool:
    """No successful sync younger than the interval (or the interval is 0)."""
    latest = last_update(db)
    if latest is None or latest.finished_at is None:
        return True
    if settings.vulndb_sync_interval_hours == 0:
        return True
    age = utc_now() - latest.finished_at
    return age >= timedelta(hours=settings.vulndb_sync_interval_hours)


def run_sync_job(requested_by: str | None = None, *, force: bool = False) -> None:
    """RQ entry point. Never raises; every outcome is a ``vulndb_syncs`` row."""
    settings = get_settings()
    requested_by = None if requested_by is None else actor_of(requested_by)
    try:
        _run_sync(settings, requested_by, force=force)
    except Exception:  # noqa: BLE001 — the job's own promise: a row, never a traceback
        logger.exception("vulnerability sync crashed")
        with get_session_factory()() as db:
            db.rollback()
            _record_run(
                db,
                source=SyncSource.OSV,
                status=SyncStatus.FAILED,
                stats=None,
                detail="sync crashed; see the worker log",
                requested_by=requested_by,
                started_at=utc_now(),
            )
            audit.record(
                db,
                actor_username=requested_by or SYSTEM_ACTOR,
                action="vulndb.sync",
                outcome=AuditOutcome.ERROR,
                target="vulndb",
            )
            db.commit()
    finally:
        reschedule(settings)


def _run_sync(settings: Settings, requested_by: str | None, *, force: bool) -> None:
    with get_session_factory()() as db:
        if not settings.vulndb_sync_enabled:
            _record_run(
                db,
                source=SyncSource.OSV,
                status=SyncStatus.SKIPPED,
                stats=None,
                detail="sync disabled (DIOPTRA_VULNDB_SYNC_ENABLED=false)",
                requested_by=requested_by,
                started_at=utc_now(),
            )
            return
        if not force and not stale(db, settings):
            logger.info("vulnerability mirror is fresh; nothing to sync")
        else:
            ok = True
            for ecosystem in settings.vulndb_osv_ecosystems:
                ok &= _sync_one(
                    db,
                    settings,
                    source=SyncSource.OSV,
                    url=f"{settings.vulndb_osv_base_url}/{ecosystem}/all.zip",
                    kind=importers.OSV_ZIP,
                    requested_by=requested_by,
                )
            for year in settings.vulndb_nvd_years:
                ok &= _sync_one(
                    db,
                    settings,
                    source=SyncSource.NVD,
                    url=f"{settings.vulndb_nvd_base_url}/nvdcve-2.0-{year}.json.gz",
                    kind=importers.NVD_JSON_GZ,
                    requested_by=requested_by,
                )
            audit.record(
                db,
                actor_username=requested_by or SYSTEM_ACTOR,
                action="vulndb.sync",
                outcome=AuditOutcome.OK if ok else AuditOutcome.ERROR,
                target="vulndb",
            )
            db.commit()


def reschedule(settings: Settings) -> None:
    """Queue the next scheduled sync under the NEXT slot's id (see ``next_sync_job_id``)."""
    if settings.queue_inline or not settings.vulndb_sync_enabled:
        return
    if settings.vulndb_sync_interval_hours <= 0:
        return
    from app.core.queue import (
        enqueue_sync,  # noqa: PLC0415 — the queue imports this module lazily too
    )

    try:
        enqueue_sync(
            None,
            delay_seconds=settings.vulndb_sync_interval_hours * 3600,
            job_id=next_sync_job_id(settings),
        )
    except Exception:  # noqa: BLE001 — the broker being down must not kill the worker's job
        logger.exception("could not schedule the next vulnerability sync")


def run_import_job(token: str, kind: str, requested_by: str) -> None:
    """RQ entry point for a dump the API spooled. Never raises."""
    settings = get_settings()
    requested_by = actor_of(requested_by)
    if kind not in importers.DUMP_KINDS:
        logger.error("refusing import of unknown kind %r", kind)
        return
    try:
        uuid.UUID(token)
    except ValueError:
        logger.error("refusing import with a malformed token")
        return
    spool = spool_path(settings, token, kind)
    started = utc_now()
    with get_session_factory()() as db:
        try:
            stats = importers.import_dump(
                db, spool, kind=kind, max_bytes=settings.vulndb_max_dump_bytes
            )
        except Exception as exc:  # noqa: BLE001 — every outcome is a row; a typed error names itself
            db.rollback()
            code = getattr(exc, "code", exc.__class__.__name__)
            if not isinstance(exc, DumpInvalid | DumpTooLarge | OSError):
                logger.exception("vulnerability import crashed")
            _record_run(
                db,
                source=SyncSource.IMPORT,
                status=SyncStatus.FAILED,
                stats=None,
                detail=f"{kind}: {code}",
                requested_by=requested_by,
                started_at=started,
            )
            audit.record(
                db,
                actor_username=requested_by,
                action="vulndb.import",
                outcome=AuditOutcome.ERROR,
                target=f"{kind}:{token}",
            )
            db.commit()
            return
        finally:
            spool.unlink(missing_ok=True)
        _record_run(
            db,
            source=SyncSource.IMPORT,
            status=SyncStatus.OK if stats.skipped == 0 else SyncStatus.PARTIAL,
            stats=stats,
            detail=kind,
            requested_by=requested_by,
            started_at=started,
        )
        audit.record(
            db, actor_username=requested_by, action="vulndb.import", target=f"{kind}:{token}"
        )
        db.commit()


# --- what the request handlers call --------------------------------------------


def request_sync(db: Session, *, actor: User, justification: str, source_ip: str | None) -> None:
    """Audit the request and enqueue the job. The handler performs no I/O."""
    reason = clean_justification(justification)
    settings = get_settings()
    if not settings.vulndb_sync_enabled:
        raise SyncDisabled("DIOPTRA_VULNDB_SYNC_ENABLED is false")
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="vulndb.sync.request",
        target="vulndb",
        justification=reason,
        source_ip=source_ip,
    )
    db.commit()
    from app.core.queue import enqueue_sync  # noqa: PLC0415

    enqueue_sync(actor.username, force=True)


def dump_kind_for(filename: str) -> str:
    lowered = filename.lower()
    if lowered.endswith(".zip"):
        return importers.OSV_ZIP
    if lowered.endswith(".json.gz"):
        return importers.NVD_JSON_GZ
    if lowered.endswith(".json"):
        return importers.NVD_JSON
    raise DumpKindUnknown(filename[:80])


def accept_import(
    db: Session,
    *,
    actor: User,
    token: str,
    kind: str,
    spool: Path,
    justification: str,
    source_ip: str | None,
) -> str:
    """A dump the route already streamed to ``spool``: audit, enqueue, return the token.

    Phase 10, addendum A: the copy loop moved to ``dump_upload.receive_dump``,
    which writes the file straight to disk as it arrives. Everything that
    decides whether the import is ACCEPTED stays here, and a refusal removes
    the spool so nothing waits for a worker that will never be told.
    """
    from app.core.queue import enqueue_import  # noqa: PLC0415

    try:
        reason = clean_justification(justification)
        audit.record(
            db,
            actor_username=actor.username,
            actor_id=actor.id,
            actor_role=actor.role.value,
            action="vulndb.import.request",
            target=f"{kind}:{token}",
            justification=reason,
            source_ip=source_ip,
        )
        db.commit()
    except BaseException:
        # A refused reason or a database that cannot take the audit row: no
        # row means no job, so the streamed file must not stay behind.
        spool.unlink(missing_ok=True)
        raise
    try:
        enqueue_import(token, kind, actor.username)
    except Exception as exc:
        # A broker outage must not leave a large file in the spool the worker
        # shares, nor a bare 500: the file goes, the client gets the
        # {code, message_key} contract, and the request row stays as the trace.
        spool.unlink(missing_ok=True)
        raise EnqueueFailed(exc.__class__.__name__) from exc
    return token


def discard_spool(settings: Settings) -> None:
    """Remove every spooled dump (operator maintenance; nothing calls it at runtime)."""
    shutil.rmtree(settings.vulndb_spool_dir, ignore_errors=True)
