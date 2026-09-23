"""Dump importers: OSV ``all.zip`` and NVD CVE JSON 2.0 feeds → the mirror.

Both run in the WORKER (the sync job and the import job) and never in a
request. A dump is untrusted input whatever its origin: an entry-count cap,
per-entry size caps, a decompression-ratio cap and a bounded streaming
parser bound the zip; every record is shaped with caps at persistence; a
record that does not fit is COUNTED and skipped, never raised on (survey §2).
"""

from __future__ import annotations

import gzip
import json
import logging
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.cvss import base_score, severity_for_score
from app.analysis.models import Severity
from app.core.clock import utc_now
from app.inventory.errors import DumpInvalid, DumpTooLarge
from app.inventory.models import (
    MAX_ALIASES,
    MAX_ECOSYSTEM_CHARS,
    MAX_EVENTS_PER_RANGE,
    MAX_PACKAGE_NAME_CHARS,
    MAX_PACKAGES_PER_RECORD,
    MAX_RANGES_PER_PACKAGE,
    MAX_SUMMARY_CHARS,
    MAX_VERSION_CHARS,
    MAX_VERSIONS_PER_PACKAGE,
    MAX_VULNERABILITY_ID_CHARS,
    Vulnerability,
    VulnerabilityPackage,
    VulnerabilitySource,
)

logger = logging.getLogger("dioptra.inventory.import")

#: An OSV ecosystem dump holds tens of thousands of small files.
MAX_ZIP_ENTRIES = 500_000
#: One OSV record; the largest real ones are a few hundred KiB.
MAX_RECORD_BYTES = 4 * 1024 * 1024
#: A yearly NVD feed inflates ~10×; anything beyond this ratio is a bomb.
MAX_RATIO = 60
#: Records per commit: a 100 000-record feed never holds one transaction.
BATCH_SIZE = 500
#: The streaming NVD reader's chunk and its largest pending buffer.
_CHUNK = 1024 * 1024
_MAX_PENDING = MAX_RECORD_BYTES * 2

DumpKind = str
OSV_ZIP: DumpKind = "osv-zip"
NVD_JSON: DumpKind = "nvd-json"
NVD_JSON_GZ: DumpKind = "nvd-json-gz"
DUMP_KINDS: frozenset[str] = frozenset({OSV_ZIP, NVD_JSON, NVD_JSON_GZ})


@dataclass
class ImportStats:
    seen: int = 0
    stored: int = 0
    skipped: int = 0
    detail: list[str] = field(default_factory=list)

    def note(self, text: str) -> None:
        if len(self.detail) < 10:
            self.detail.append(text[:120])


@dataclass(frozen=True)
class Record:
    """A shaped, bounded advisory ready to persist."""

    id: str
    source: VulnerabilitySource
    aliases: list[str]
    summary: str | None
    score: float | None
    vector: str | None
    severity: Severity | None
    published_at: datetime | None
    modified_at: datetime | None
    withdrawn: bool
    packages: list[dict[str, Any]]


# --- small shaping helpers -----------------------------------------------------


def _text(value: object, limit: int) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped[:limit] if stripped else None
    return None


def _when(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _score_from_vector(vector: str | None) -> tuple[float | None, Severity | None]:
    if vector is None:
        return None, None
    try:
        score = base_score(vector)
    except ValueError:
        return None, None
    return score, severity_for_score(score)


def _severity_from_word(word: object) -> Severity | None:
    if not isinstance(word, str):
        return None
    try:
        return Severity(word.strip().lower())
    except ValueError:
        return None


def _events(raw_events: object) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for event in raw_events if isinstance(raw_events, list) else []:
        if not isinstance(event, dict):
            continue
        shaped: dict[str, str] = {}
        for kind in ("introduced", "fixed", "last_affected"):
            value = _text(event.get(kind), MAX_VERSION_CHARS)
            if value is not None:
                shaped[kind] = value
        if shaped:
            events.append(shaped)
        if len(events) >= MAX_EVENTS_PER_RANGE:
            break
    return events


def _packages(raw_affected: object) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    for entry in raw_affected if isinstance(raw_affected, list) else []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if not isinstance(package, dict):
            continue
        ecosystem = _text(package.get("ecosystem"), MAX_ECOSYSTEM_CHARS)
        name = _text(package.get("name"), MAX_PACKAGE_NAME_CHARS)
        if ecosystem is None or name is None:
            continue
        # OSV spells sub-ecosystems as "Debian:11" or "Maven:https://…"; the
        # part before the colon is the ecosystem the PURL type maps to.
        ecosystem = ecosystem.split(":", 1)[0]
        if ecosystem == "PyPI":
            name = name.lower().replace("_", "-").replace(".", "-")
        versions = [
            text
            for text in (_text(v, MAX_VERSION_CHARS) for v in (entry.get("versions") or []))
            if text is not None
        ][:MAX_VERSIONS_PER_PACKAGE]
        ranges: list[dict[str, Any]] = []
        for range_entry in entry.get("ranges") or []:
            if not isinstance(range_entry, dict):
                continue
            ranges.append(
                {
                    "type": _text(range_entry.get("type"), 16) or "ECOSYSTEM",
                    "events": _events(range_entry.get("events")),
                }
            )
            if len(ranges) >= MAX_RANGES_PER_PACKAGE:
                break
        packages.append(
            {"ecosystem": ecosystem, "name": name, "versions": versions, "ranges": ranges}
        )
        if len(packages) >= MAX_PACKAGES_PER_RECORD:
            break
    return packages


# --- OSV -----------------------------------------------------------------------


def shape_osv(raw: object) -> Record | None:
    """One OSV JSON record → :class:`Record`, or ``None`` when it does not fit."""
    if not isinstance(raw, dict):
        return None
    identifier = _text(raw.get("id"), MAX_VULNERABILITY_ID_CHARS)
    if identifier is None:
        return None
    aliases = [
        alias
        for alias in (_text(a, MAX_VULNERABILITY_ID_CHARS) for a in (raw.get("aliases") or []))
        if alias is not None
    ][:MAX_ALIASES]
    vector: str | None = None
    for entry in raw.get("severity") or []:
        if isinstance(entry, dict) and str(entry.get("type", "")).upper().startswith("CVSS_V3"):
            vector = _text(entry.get("score"), 120)
            break
    score, severity = _score_from_vector(vector)
    if severity is None:
        database_specific = raw.get("database_specific")
        if isinstance(database_specific, dict):
            severity = _severity_from_word(database_specific.get("severity"))
    summary = _text(raw.get("summary"), MAX_SUMMARY_CHARS) or _text(
        raw.get("details"), MAX_SUMMARY_CHARS
    )
    return Record(
        id=identifier,
        source=VulnerabilitySource.OSV,
        aliases=aliases,
        summary=summary,
        score=score,
        vector=vector,
        severity=severity,
        published_at=_when(raw.get("published")),
        modified_at=_when(raw.get("modified")),
        withdrawn=_when(raw.get("withdrawn")) is not None,
        packages=_packages(raw.get("affected")),
    )


def iter_osv_zip(path: Path, *, max_bytes: int) -> Iterator[object]:
    """Yield every JSON record of an OSV ``all.zip``, under the survey's caps.

    Entry NAMES are never used for anything (there is nothing to slip into:
    entries are read into memory, never extracted), only their JSON content.
    """
    size = path.stat().st_size
    if size > max_bytes:
        raise DumpTooLarge(f"{size} bytes")
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise DumpInvalid("not a zip archive") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise DumpTooLarge(f"{len(infos)} entries")
        declared = sum(info.file_size for info in infos)
        if declared > max_bytes * MAX_RATIO:
            raise DumpTooLarge(f"{declared} bytes declared")
        for info in infos:
            if info.is_dir() or not info.filename.lower().endswith(".json"):
                continue
            if info.file_size > MAX_RECORD_BYTES:
                yield None  # counted as skipped by the caller
                continue
            try:
                with archive.open(info) as handle:
                    data = handle.read(MAX_RECORD_BYTES + 1)
            except (NotImplementedError, RuntimeError, zlib.error, OSError, ValueError):
                # An unsupported compression method, an encrypted entry or
                # corrupt deflate data is ONE bad record, not a dead job.
                yield None
                continue
            if len(data) > MAX_RECORD_BYTES:
                yield None
                continue
            try:
                yield json.loads(data)
            except (ValueError, UnicodeDecodeError, RecursionError):
                # RecursionError: a record nested thousands deep is a bomb
                # aimed at the parser; it is skipped like any malformed one.
                yield None


# --- NVD -----------------------------------------------------------------------


def shape_nvd(raw: object) -> Record | None:
    """One ``{"cve": {...}}`` item of an NVD 2.0 feed → :class:`Record`."""
    if not isinstance(raw, dict):
        return None
    cve = raw.get("cve")
    if not isinstance(cve, dict):
        return None
    identifier = _text(cve.get("id"), MAX_VULNERABILITY_ID_CHARS)
    if identifier is None or not identifier.upper().startswith("CVE-"):
        return None
    summary: str | None = None
    for description in cve.get("descriptions") or []:
        if isinstance(description, dict) and description.get("lang") == "en":
            summary = _text(description.get("value"), MAX_SUMMARY_CHARS)
            break
    vector: str | None = None
    score: float | None = None
    severity: Severity | None = None
    metrics = cve.get("metrics")
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key)
            if not isinstance(entries, list) or not entries:
                continue
            first = entries[0]
            data = first.get("cvssData") if isinstance(first, dict) else None
            if not isinstance(data, dict):
                continue
            vector = _text(data.get("vectorString"), 120)
            raw_score = data.get("baseScore")
            if isinstance(raw_score, int | float) and not isinstance(raw_score, bool):
                score = float(raw_score)
                severity = severity_for_score(score)
            break
    if score is None:
        score, severity = _score_from_vector(vector)
    return Record(
        id=identifier.upper(),
        source=VulnerabilitySource.NVD,
        aliases=[],
        summary=summary,
        score=score,
        vector=vector,
        severity=severity,
        published_at=_when(cve.get("published")),
        modified_at=_when(cve.get("lastModified")),
        withdrawn=str(cve.get("vulnStatus", "")).lower() in {"rejected", "withdrawn"},
        packages=[],
    )


def _open_feed(path: Path, *, gzipped: bool) -> IO[bytes]:
    if gzipped:
        return cast("IO[bytes]", gzip.open(path, "rb"))
    return path.open("rb")


def iter_nvd_feed(path: Path, *, gzipped: bool, max_bytes: int) -> Iterator[object]:
    """Stream the items of ``{"vulnerabilities": [ … ]}`` without loading the feed.

    A yearly feed is hundreds of megabytes inflated; the reader keeps at most
    two records' worth of bytes pending and decodes one object at a time
    with ``JSONDecoder.raw_decode``.
    """
    size = path.stat().st_size
    if size > max_bytes:
        raise DumpTooLarge(f"{size} bytes")
    decoder = json.JSONDecoder()
    inflated = 0
    pending = ""
    started = False
    finished = False
    try:
        with _open_feed(path, gzipped=gzipped) as handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                inflated += len(chunk)
                if inflated > max_bytes * MAX_RATIO:
                    raise DumpTooLarge(f"{inflated} bytes inflated")
                if finished:
                    # Everything after the closing bracket is trailing junk:
                    # never buffered, never parsed — the array is what we read.
                    break
                pending += chunk.decode("utf-8", errors="replace")
                if not started:
                    marker = pending.find('"vulnerabilities"')
                    if marker < 0:
                        if len(pending) > _MAX_PENDING:
                            raise DumpInvalid("no vulnerabilities array")
                        continue
                    bracket = pending.find("[", marker)
                    if bracket < 0:
                        if len(pending) > _MAX_PENDING:
                            raise DumpInvalid("no vulnerabilities array")
                        continue
                    pending = pending[bracket + 1 :]
                    started = True
                while True:
                    stripped = pending.lstrip(" \t\r\n,")
                    if stripped.startswith("]"):
                        pending = ""
                        finished = True
                        break
                    if not stripped:
                        pending = stripped
                        break
                    try:
                        item, end = decoder.raw_decode(stripped)
                    except (ValueError, RecursionError):
                        if len(stripped) > _MAX_PENDING:
                            raise DumpInvalid("record too large or malformed") from None
                        pending = stripped
                        break
                    pending = stripped[end:]
                    yield item
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise DumpInvalid("feed unreadable") from exc
    if not started:
        raise DumpInvalid("no vulnerabilities array")
    if not finished and pending.strip(" \t\r\n,"):
        # Bytes the decoder could never close: a truncated feed or a record
        # nested past the parser's depth. Refused, never silently dropped.
        raise DumpInvalid("truncated or malformed record")


# --- persistence ---------------------------------------------------------------


def upsert(db: Session, record: Record) -> bool:
    """Store one record; ``False`` when the stored copy is as new or newer."""
    existing = db.get(Vulnerability, record.id)
    if existing is not None:
        if (
            existing.modified_at is not None
            and record.modified_at is not None
            and record.modified_at <= existing.modified_at
        ):
            return False
        if existing.source is VulnerabilitySource.OSV and record.source is VulnerabilitySource.NVD:
            # NVD knows no packages: it may ENRICH an OSV row (score, text),
            # never replace it — a wholesale replace would wipe the join and
            # the advisory would stop correlating (precommit panel, day 18).
            existing.score = existing.score if existing.score is not None else record.score
            existing.vector = existing.vector or record.vector
            existing.severity = existing.severity or record.severity
            existing.summary = existing.summary or record.summary
            existing.synced_at = utc_now()
            return True
        existing.source = record.source
        existing.aliases = record.aliases
        existing.summary = record.summary
        existing.score = record.score
        existing.vector = record.vector
        existing.severity = record.severity
        existing.published_at = record.published_at
        existing.modified_at = record.modified_at
        existing.withdrawn = record.withdrawn
        existing.synced_at = utc_now()
        existing.packages = [VulnerabilityPackage(**package) for package in record.packages]
        return True
    db.add(
        Vulnerability(
            id=record.id,
            source=record.source,
            aliases=record.aliases,
            summary=record.summary,
            score=record.score,
            vector=record.vector,
            severity=record.severity,
            published_at=record.published_at,
            modified_at=record.modified_at,
            withdrawn=record.withdrawn,
            packages=[VulnerabilityPackage(**package) for package in record.packages],
        )
    )
    return True


def import_records(db: Session, records: Iterator[object], *, kind: DumpKind) -> ImportStats:
    """Shape and persist every record of a dump, committing in batches."""
    shape = shape_osv if kind == OSV_ZIP else shape_nvd
    stats = ImportStats()
    pending = 0
    for raw in records:
        stats.seen += 1
        record = shape(raw)
        if record is None:
            stats.skipped += 1
            continue
        if upsert(db, record):
            stats.stored += 1
        else:
            stats.skipped += 1
        pending += 1
        if pending >= BATCH_SIZE:
            db.commit()
            pending = 0
    db.commit()
    return stats


def import_dump(db: Session, path: Path, *, kind: DumpKind, max_bytes: int) -> ImportStats:
    """Import one dump file of the given kind. Raises the typed errors only."""
    if kind == OSV_ZIP:
        records = iter_osv_zip(path, max_bytes=max_bytes)
    elif kind in {NVD_JSON, NVD_JSON_GZ}:
        records = iter_nvd_feed(path, gzipped=kind == NVD_JSON_GZ, max_bytes=max_bytes)
    else:
        raise DumpInvalid(f"unknown dump kind {kind!r}")
    return import_records(db, records, kind=kind)


def known_ids(db: Session, identifiers: list[str]) -> set[str]:
    """Which of these advisory ids the mirror holds (used by tests and the panel)."""
    if not identifiers:
        return set()
    rows = db.scalars(select(Vulnerability.id).where(Vulnerability.id.in_(identifiers)))
    return set(rows)
