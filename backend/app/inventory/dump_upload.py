"""The vulnerability-dump import, read part by part straight to disk (phase 10, addendum A).

The route used to call Starlette's ``request.form()``, which spools the WHOLE
file into the API's ``/tmp`` — a 512 MiB tmpfs in RAM — before anything looks
at it, so the real ceiling of an import was that RAM, not the setting, and the
file was written twice. OSV's npm dump alone is 207 MiB and growing
(`tasks/phase10-survey.md` → Addendum A).

Here the multipart body is parsed AS IT ARRIVES with python-multipart's
streaming parser (the one Starlette uses; no new dependency): the written
justification goes to memory under its own cap, the file goes straight to
``<vulndb_spool_dir>/<token>.<kind>`` (``O_EXCL``, ``0600``) under a byte
counter that ignores every header. Exactly two parts are accepted, ``file``
and ``justification``, once each. Any refusal removes the partial file.

The callbacks only touch memory; every filesystem call happens between two
``parser.write`` calls, in a worker thread — this runs on the event loop.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

import anyio
from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.requests import ClientDisconnect

from app.core.config import Settings
from app.core.errors import ValidationFailed
from app.ingest.errors import UploadInterrupted
from app.inventory.errors import DumpInvalid, DumpTooLarge
from app.inventory.sync import dump_kind_for, spool_path

#: The justification's cap, as `Form(max_length=8000)` carried it before.
MAX_JUSTIFICATION_CHARS = 8000
#: UTF-8 is at most four bytes a character: the byte bound that implies it.
_MAX_JUSTIFICATION_BYTES = MAX_JUSTIFICATION_CHARS * 4
#: A part's headers are a few hundred bytes; python-multipart's own default.
_MAX_HEADER_BYTES = 4224
#: Headers per part: a form part carries one or two; python-multipart's default.
_MAX_HEADERS = 8
_WRITE_BATCH = 1024 * 1024
_PARTS = ("file", "justification")


@dataclass
class ReceivedDump:
    """What a completed import body left behind: a spool on disk and a reason."""

    kind: str
    spool: Path
    justification: str


@dataclass
class _State:
    """Everything the parser callbacks write. Memory only, never the disk."""

    max_bytes: int
    header_field: bytearray = field(default_factory=bytearray)
    header_value: bytearray = field(default_factory=bytearray)
    disposition: bytes = b""
    part: str | None = None
    seen: set[str] = field(default_factory=set)
    filename: str | None = None
    justification: bytearray = field(default_factory=bytearray)
    pending: bytearray = field(default_factory=bytearray)
    written: int = 0
    headers: int = 0
    #: Set only by the CLOSING boundary. `finalize()` does not check that the
    #: body reached it, so a body cut short would otherwise pass as complete
    #: with a truncated file (phase-10 addendum panel).
    ended: bool = False

    def begin(self) -> None:
        self.header_field.clear()
        self.header_value.clear()
        self.disposition = b""
        self.part = None
        self.headers = 0

    def end(self) -> None:
        self.ended = True

    def header_end(self) -> None:
        self.headers += 1
        if self.headers > _MAX_HEADERS:
            raise ValidationFailed("too many part headers")
        if self.header_field.strip().lower() == b"content-disposition":
            self.disposition = bytes(self.header_value)
        self.header_field.clear()
        self.header_value.clear()

    def headers_finished(self) -> None:
        _kind, options = parse_options_header(self.disposition)
        name = options.get(b"name", b"").decode("utf-8", errors="replace")
        if name not in _PARTS or name in self.seen:
            # A third part, a repeated one or an unknown name: this route takes
            # exactly one file and one reason.
            raise ValidationFailed(f"unexpected part {name[:40]!r}")
        self.seen.add(name)
        self.part = name
        if name == "file":
            raw = options.get(b"filename", b"").decode("utf-8", errors="replace")
            # Only the extension is read (`dump_kind_for`); the name never
            # becomes a path — the spool is named after the token.
            self.filename = raw

    def data(self, chunk: bytes) -> None:
        if self.part == "justification":
            self.justification += chunk
            if len(self.justification) > _MAX_JUSTIFICATION_BYTES:
                raise ValidationFailed("justification too long")
        elif self.part == "file":
            self.written += len(chunk)
            if self.written > self.max_bytes:
                raise DumpTooLarge(f"{self.written} bytes streamed")
            self.pending += chunk


def _open_spool(target: Path) -> BinaryIO:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def _abandon(out: BinaryIO | None, target: Path | None) -> None:
    """Close and remove a partial spool. Sync, so no cancellation can skip it."""
    if out is not None:
        out.close()
    if target is not None:
        target.unlink(missing_ok=True)


def boundary_of(content_type: str) -> bytes:
    """The multipart boundary, or a typed refusal (no body is read before this)."""
    media, options = parse_options_header(content_type)
    boundary = options.get(b"boundary", b"")
    if media != b"multipart/form-data" or not boundary or len(boundary) > 200:
        raise ValidationFailed("not a multipart body with a boundary")
    return boundary


async def receive_dump(
    chunks: AsyncIterator[bytes], boundary: bytes, token: str, settings: Settings
) -> ReceivedDump:
    """Parse the import body as it arrives; the file lands on disk, never in RAM."""
    state = _State(max_bytes=settings.vulndb_max_dump_bytes)

    def on_header_field(data: bytes, start: int, end: int) -> None:
        state.header_field += data[start:end]
        if len(state.header_field) > _MAX_HEADER_BYTES:
            raise ValidationFailed("part header too long")

    def on_header_value(data: bytes, start: int, end: int) -> None:
        state.header_value += data[start:end]
        if len(state.header_value) > _MAX_HEADER_BYTES:
            raise ValidationFailed("part header too long")

    def on_part_data(data: bytes, start: int, end: int) -> None:
        state.data(data[start:end])

    parser = MultipartParser(
        boundary,
        {
            "on_part_begin": state.begin,
            "on_header_field": on_header_field,
            "on_header_value": on_header_value,
            "on_header_end": state.header_end,
            "on_headers_finished": state.headers_finished,
            "on_part_data": on_part_data,
            "on_end": state.end,
        },
    )
    out: BinaryIO | None = None
    target: Path | None = None
    kind: str | None = None
    try:
        try:
            async for chunk in chunks:
                parser.write(chunk)
                if state.filename is not None and out is None:
                    kind = dump_kind_for(state.filename)  # DumpKindUnknown, typed
                    target = spool_path(settings, token, kind)
                    out = await anyio.to_thread.run_sync(_open_spool, target)
                if out is not None and len(state.pending) >= _WRITE_BATCH:
                    batch, state.pending = bytes(state.pending), bytearray()
                    await anyio.to_thread.run_sync(out.write, batch)
            parser.finalize()
        except ClientDisconnect as exc:
            raise UploadInterrupted(f"client left after {state.written} bytes") from exc
        except MultipartParseError as exc:
            raise ValidationFailed("malformed multipart body") from exc
        if not state.ended:
            raise ValidationFailed("the body ended before its closing boundary")
        if out is None or target is None or kind is None:
            raise ValidationFailed("the file part is missing")
        if "justification" not in state.seen:
            raise ValidationFailed("the justification part is missing")
        if state.pending:
            await anyio.to_thread.run_sync(out.write, bytes(state.pending))
            state.pending = bytearray()
        await anyio.to_thread.run_sync(out.close)
        out = None
        if state.written == 0:
            raise DumpInvalid("empty upload")
        text = state.justification.decode("utf-8", errors="replace")
        if len(text) > MAX_JUSTIFICATION_CHARS:
            raise ValidationFailed("justification too long")
        return ReceivedDump(kind=kind, spool=target, justification=text)
    except BaseException:
        # Synchronous on purpose: under a cancellation (a server shutdown, a
        # cancel scope above the route) every await here would be cancelled
        # too and leave up to a GiB behind. Closing a file and unlinking one
        # are microsecond calls (phase-10 addendum panel).
        _abandon(out, target)
        raise
