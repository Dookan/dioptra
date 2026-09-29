"""ZIP extraction into a per-analysis jail.

Guards (threat model → ZIP ingest): zip-slip via ``..`` or absolute names,
entry-count bombs, decompression bombs (declared size AND actual streamed
bytes — a lying header must not bypass the cap), symlinks and special entries
never materialized. Extraction is streamed; nothing is decompressed in memory.
"""

from __future__ import annotations

import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from app.core.process import StopCheck, Stopped
from app.ingest.errors import InvalidArchive, TooManyEntries, ZipBomb, ZipSlipDetected, ZipTooLarge

_CHUNK = 1024 * 1024
#: A stoppable extraction (phase 12) asks every this many entries or bytes.
STOP_EVERY_ENTRIES = 1000
STOP_EVERY_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ExtractionLimits:
    max_entries: int
    max_unpacked_bytes: int
    max_ratio: int


@dataclass(frozen=True)
class ExtractionReport:
    files: int
    bytes_written: int
    skipped_special: int


def _is_special(info: zipfile.ZipInfo) -> bool:
    """Symlinks, devices, sockets: never followed, never created."""
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) == 0:
        # No type bits at all (Windows-made archives, Python's writestr): a
        # plain member, not a special one.
        return False
    return stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))


def _safe_relative(name: str) -> PurePosixPath:
    if "\\" in name or "\x00" in name:
        raise ZipSlipDetected("backslash or NUL in entry name")
    path = PurePosixPath(name)
    if path.is_absolute() or name.startswith(("/", "//")):
        raise ZipSlipDetected("absolute entry name")
    if any(part in ("..", "") for part in path.parts if part != "."):
        raise ZipSlipDetected("parent reference in entry name")
    if len(name) > 1024:
        raise ZipSlipDetected("entry name too long")
    return path


def extract_zip(
    source: BinaryIO,
    jail: Path,
    limits: ExtractionLimits,
    *,
    should_stop: StopCheck | None = None,
) -> ExtractionReport:
    """Extract ``source`` under ``jail``. The jail must not exist yet.

    ``should_stop`` is asked every ``STOP_EVERY_ENTRIES`` entries or
    ``STOP_EVERY_BYTES`` written; a yes raises ``Stopped`` and the jail is
    removed like on any other failure (phase 12). The guards do not change.
    """
    jail = jail.resolve()
    jail.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        return _extract(source, jail, limits, should_stop)
    except Exception:
        shutil.rmtree(jail, ignore_errors=True)
        raise


def _extract(
    source: BinaryIO, jail: Path, limits: ExtractionLimits, should_stop: StopCheck | None
) -> ExtractionReport:
    try:
        archive = zipfile.ZipFile(source)
    except (zipfile.BadZipFile, OSError) as exc:
        raise InvalidArchive("not a zip file") from exc

    with archive:
        entries = archive.infolist()
        if len(entries) > limits.max_entries:
            raise TooManyEntries(f"{len(entries)} entries")
        declared = sum(entry.file_size for entry in entries)
        compressed = sum(entry.compress_size for entry in entries)
        if declared > limits.max_unpacked_bytes:
            raise ZipTooLarge(f"declared {declared} bytes")
        if compressed > 0 and declared // compressed > limits.max_ratio:
            raise ZipBomb(f"ratio {declared // compressed}:1")

        written = 0
        files = 0
        skipped = 0
        asked_at = 0
        for index, entry in enumerate(entries):
            if should_stop is not None and index % STOP_EVERY_ENTRIES == 0 and should_stop():
                raise Stopped("extraction")
            relative = _safe_relative(entry.filename)
            if _is_special(entry):
                skipped += 1
                continue
            target = (jail / relative).resolve()
            if not target.is_relative_to(jail):
                raise ZipSlipDetected("entry escapes the jail")
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                with archive.open(entry) as member, target.open("wb") as out:
                    while chunk := member.read(_CHUNK):
                        written += len(chunk)
                        if written > limits.max_unpacked_bytes:
                            # The header lied about the size: the stream is the truth.
                            raise ZipBomb("streamed bytes exceed the cap")
                        out.write(chunk)
                        if should_stop is not None and written - asked_at >= STOP_EVERY_BYTES:
                            # One member can be gigabytes: ask inside it too.
                            asked_at = written
                            if should_stop():
                                raise Stopped("extraction")
            except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
                # RuntimeError covers encrypted members; we never take a password.
                raise InvalidArchive(f"cannot read entry: {exc.__class__.__name__}") from exc
            target.chmod(0o600)
            files += 1
    return ExtractionReport(files=files, bytes_written=written, skipped_special=skipped)
