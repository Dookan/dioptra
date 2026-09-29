"""The ZIP upload, streamed to disk after authentication (phase 10).

Why this module exists (`tasks/phase10-survey.md` §2.1): the route used to
declare ``UploadFile``, so FastAPI parsed the multipart body — and Starlette
spooled all of it into the API's RAM-backed ``/tmp`` — while it solved the
endpoint's parameters, BEFORE ``IngestUser`` could refuse an anonymous caller.
A body with no ``Content-Length`` (chunked) passed the only pre-body check.
At 200 MiB behind nginx that was bounded; at 1 GiB it is not something a RAM
tmpfs can bound.

Now the route declares no body parameter, so authentication resolves first,
and the raw body is copied here into a file on the workspaces volume under a
byte counter that does not trust any header. The worker extracts it
(:func:`extract_upload`), so the request lasts as long as the upload and no
longer — and a slow unpack of several GiB is the worker's time, the same way
``git clone`` already is.
"""

from __future__ import annotations

import os
import shutil
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import BinaryIO

import anyio
from starlette.requests import ClientDisconnect

from app.core.config import Settings
from app.core.process import StopCheck
from app.ingest.archive import ExtractionLimits, extract_zip
from app.ingest.errors import UploadInterrupted, UploadMissing, UploadTooLarge

#: The spool's fixed name inside the analysis directory, beside the jail
#: (``src/``) and the tools' ``out/``. Built from uuids only — the client's
#: file name never becomes a path.
UPLOAD_NAME = "upload.zip"
#: Media types the route accepts for the raw body. `x-zip-compressed` is what
#: Windows browsers put on a `.zip` File; octet-stream is what curl sends.
ZIP_MEDIA_TYPES = frozenset(
    {"application/zip", "application/x-zip-compressed", "application/octet-stream"}
)
#: Writes are batched and handed to a worker thread, so the event loop never
#: blocks on the disk and a 1 GiB upload costs ~1 000 thread hops, not ~16 000.
_WRITE_BATCH = 1024 * 1024
_MIB = 1024 * 1024


def analysis_dir(settings: Settings, project_id: uuid.UUID, analysis_id: uuid.UUID) -> Path:
    """``<workspace_root>/<project>/<analysis>`` — the jail's parent."""
    return settings.workspace_root / str(project_id) / str(analysis_id)


def too_large(max_bytes: int, detail: str) -> UploadTooLarge:
    """The refusal, carrying the limit the screen shows (whole MiB, rounded down)."""
    return UploadTooLarge(detail, context={"limit_mib": str(max_bytes // _MIB)})


def display_name(raw: str | None) -> str:
    """The client's file name as a LABEL: last component, no control chars, capped.

    It only ever becomes ``Analysis.source_ref`` (text, escaped at every
    render); it is never joined to a path.
    """
    text = "".join(ch for ch in (raw or "") if ch.isprintable())
    text = text.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return text[:255] or "upload.zip"


def _open_spool(target: Path) -> BinaryIO:
    """Create ``target`` exclusively, ``0600``, in a ``0700`` directory."""
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def _abandon(out: BinaryIO, target: Path) -> None:
    """Close and remove a partial spool. Sync, so no cancellation can skip it."""
    out.close()
    target.unlink(missing_ok=True)


async def spool_body(chunks: AsyncIterator[bytes], target: Path, max_bytes: int) -> int:
    """Copy ``chunks`` into ``target`` (created, ``0600``), refusing past ``max_bytes``.

    Counts what ARRIVES: a lying or absent ``Content-Length`` gains nothing.
    On any failure the file is removed; the caller owns the directory. Every
    filesystem call is handed to a thread — this runs on the event loop.
    """
    out = await anyio.to_thread.run_sync(_open_spool, target)
    written = 0
    pending = bytearray()
    try:
        try:
            async for chunk in chunks:
                written += len(chunk)
                if written > max_bytes:
                    raise too_large(max_bytes, f"{written} bytes streamed")
                pending += chunk
                if len(pending) >= _WRITE_BATCH:
                    batch, pending = bytes(pending), bytearray()
                    await anyio.to_thread.run_sync(out.write, batch)
        except ClientDisconnect as exc:
            raise UploadInterrupted(f"client left after {written} bytes") from exc
        if pending:
            await anyio.to_thread.run_sync(out.write, bytes(pending))
    except BaseException:
        # Synchronous on purpose: under a cancellation every await here would
        # be cancelled too and leave the partial archive behind; closing and
        # unlinking are microsecond calls (phase-10 addendum panel).
        _abandon(out, target)
        raise
    await anyio.to_thread.run_sync(out.close)
    return written


def discard(directory: Path) -> None:
    """Remove an analysis directory this request created. Never raises."""
    shutil.rmtree(directory, ignore_errors=True)


def extract_upload(
    workspace: Path, settings: Settings, *, should_stop: StopCheck | None = None
) -> None:
    """Worker side: unpack the spooled ZIP into ``workspace`` (the jail), then drop it.

    ``archive.extract_zip`` is unchanged — every guard it had in the request it
    has here. The spool is deleted whatever happens; a failed extraction also
    removes the jail (the archive does that) and so leaves nothing of the
    upload behind, while the analysis row records the typed failure.
    """
    spool = workspace.parent / UPLOAD_NAME
    if workspace.exists():
        # Only the worker extracts since phase 10, and the pipeline claims a row
        # once (QUEUED → RUNNING), so a jail that already exists here is the
        # remains of an extraction a killed worker left half done. Analysing it
        # would report on a partial tree as if it were whole: refuse, and the
        # caller removes it (`tasks/hardening-1.5.1-survey.md` §11.10b).
        spool.unlink(missing_ok=True)
        message = f"{workspace} already exists before extraction"
        raise UploadMissing(message)
    if not spool.is_file():
        raise UploadMissing(str(spool))
    try:
        with spool.open("rb") as source:
            extract_zip(
                source,
                workspace,
                ExtractionLimits(
                    max_entries=settings.max_zip_entries,
                    max_unpacked_bytes=settings.max_unpacked_bytes,
                    max_ratio=settings.max_zip_ratio,
                ),
                should_stop=should_stop,
            )
    finally:
        spool.unlink(missing_ok=True)
