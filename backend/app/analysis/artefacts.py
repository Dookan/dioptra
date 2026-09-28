"""Sensitive artefacts committed to the audited tree (phase 11).

A database dump, a directory of user uploads, an ``.env`` file, a private key
or a large log shipped AS SOURCE is often the most serious fact about a
system, and no scanner of the pipeline reports it: Semgrep skips any target
over ``--max-target-bytes`` (a 234 MB dump is invisible to it) and Gitleaks
finds a secret INSIDE a file, never the file itself (`tasks/phase11-survey.md`
§1–§2).

This is our own deterministic walk, in the shape of
``metrics.scan_commented_code``: in the worker, over the jail, never following
a symlink, capped. Three properties are load-bearing:

- **It reads only a HEAD** of each candidate (``HEAD_BYTES``) plus ``lstat``
  for the size, so a 234 MB dump costs one 4 KiB read.
- **It never republishes what it finds.** A hit's ``detail`` is a canonical
  signature label, a count, or the KEY names of an ``.env`` — never a byte of a
  dump row, a value or an image. The finding's job is to say the data is
  there, not to copy it into the database, the report or the screen.
- **Dependency directories are walked too** (§5): a library does not ship a
  ``production.sql``; one under ``vendor/`` was put there by the team.

Only ``.git`` is skipped: its objects are compressed and its history is the
secrets layer's (Gitleaks ``git`` pass).
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from app.analysis.catalog import ARTEFACT_COUNT_SNIPPET, ARTEFACT_MESSAGES, describe
from app.analysis.cwe_owasp import owasp_for
from app.analysis.models import SEVERITY_ORDER, Severity, ToolCategory
from app.analysis.normalizer import MAX_MESSAGE, MAX_PATH, MAX_SNIPPET, NormalizedFinding

#: Bytes read from the start of a candidate file. Every signature below sits
#: in the first lines of its format.
HEAD_BYTES = 4096
#: Regular files looked at before the walk stops and records a coverage gap.
MAX_FILES = 300_000
#: Hits kept: a tree with more is reported with the cap as a gap.
MAX_HITS = 500
_SKIPPED_DIRS = frozenset({".git"})

DUMP = "artefact-database-dump"
UPLOADS = "artefact-user-uploads"
ENV = "artefact-env-file"
PRIVATE_KEY = "artefact-private-key"
LOG = "artefact-log-file"
RULE_IDS: tuple[str, ...] = (DUMP, UPLOADS, ENV, PRIVATE_KEY, LOG)
#: The name the scan carries in `tools`, the coverage table and the raw output.
TOOL = "artefacts"

#: rule → (CWE, severity), `tasks/phase11-survey.md` §4 and §6.4–§6.5. CWE-538
#: rather than 530 for a dump: 530 is in no OWASP Top 10:2021 list and would
#: print as unclassified; 530 is in the catalog's references instead.
RULE_TABLE: dict[str, tuple[int, Severity]] = {
    DUMP: (538, Severity.HIGH),
    UPLOADS: (538, Severity.MEDIUM),
    ENV: (538, Severity.HIGH),
    PRIVATE_KEY: (321, Severity.HIGH),
    LOG: (532, Severity.LOW),
}

# --- database dumps -------------------------------------------------------------

_SQL_SUFFIXES = (".sql", ".dump", ".pgdump", ".bak", ".sql.gz")
_SQLITE_SUFFIXES = (".sqlite", ".sqlite3", ".db")
_SQLITE_MAGIC = b"SQLite format 3\x00"
_PGDMP_MAGIC = b"PGDMP"
#: (label, pattern) in priority order. The LABEL is what a finding carries,
#: never the matched bytes: an INSERT line holds a row of the dump.
_DUMP_SIGNATURES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("-- PostgreSQL database dump", re.compile(rb"^--\s*PostgreSQL database dump", re.M)),
    ("-- MySQL dump", re.compile(rb"^--\s*MySQL dump", re.M)),
    ("-- MariaDB dump", re.compile(rb"^--\s*MariaDB dump", re.M)),
    ("COPY … FROM stdin;", re.compile(rb"^COPY\s.+\sFROM\s+stdin;", re.M | re.I)),
    ("INSERT INTO …", re.compile(rb"^\s*INSERT\s+INTO\s", re.M | re.I)),
)
#: Small hand-written seed data is normal source; over the floor it is a dump.
SEED_FLOOR_BYTES = 100 * 1024
_SEED_SEGMENTS = frozenset({"fixtures", "seeds", "seeders", "seed"})

# --- uploads --------------------------------------------------------------------

_UPLOAD_NAMES = frozenset({"uploads", "upload", "media"})
_UPLOAD_SUFFIXES = frozenset(
    {".jpg", ".jpeg", ".png", ".gif", ".webp", ".pdf", ".doc", ".docx", ".xls", ".xlsx"}
)
UPLOADS_MIN_FILES = 10

# --- .env -----------------------------------------------------------------------

_ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.dist"})
_ENV_LINE = re.compile(
    # Greedy tail, stripped afterwards: a lazy `.*?` before `\s*$` is quadratic
    # on one long line, and every `.env*` name is a candidate (security panel).
    rb"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]{0,63})\s*=(?P<value>.*)$"
)
_MAX_ENV_KEYS = 40

# --- private keys ---------------------------------------------------------------

_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_KEY_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})
_PEM_PRIVATE = re.compile(
    rb"-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?)PRIVATE KEY-----"
)

# --- logs -----------------------------------------------------------------------

LOG_MIN_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ArtefactHit:
    """One thing the scan saw. ``detail`` is a label or a count, never content."""

    rule_id: str
    path: str
    size: int
    detail: str
    files: int = 1


@dataclass(frozen=True)
class ArtefactScan:
    hits: tuple[ArtefactHit, ...]
    files_seen: int
    #: True when ``MAX_FILES`` stopped the walk: a coverage gap, never a pass.
    truncated: bool


def _read_head(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(HEAD_BYTES)


def _gunzip_head(raw: bytes) -> bytes:
    """The first bytes of a gzip member, from a compressed head that is itself capped."""
    try:
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, HEAD_BYTES)
    except zlib.error:
        return b""


def _is_seed(rel: PurePosixPath) -> bool:
    return rel.name.lower().startswith("seed") or any(
        part.lower() in _SEED_SEGMENTS for part in rel.parts[:-1]
    )


def _dump_label(path: Path, rel: PurePosixPath, size: int) -> str | None:
    name = rel.name.lower()
    if name.endswith(_SQLITE_SUFFIXES):
        return "SQLite format 3" if _read_head(path).startswith(_SQLITE_MAGIC) else None
    if not name.endswith(_SQL_SUFFIXES):
        return None
    head = _read_head(path)
    if name.endswith(".gz"):
        head = _gunzip_head(head)
    if head.startswith(_PGDMP_MAGIC):
        return "PGDMP"
    # DDL alone (migrations, schema.sql) matches none of these: no data rows.
    label = next((label for label, pattern in _DUMP_SIGNATURES if pattern.search(head)), None)
    if label is None or (_is_seed(rel) and size < SEED_FLOOR_BYTES):
        return None
    return label


def _env_keys(path: Path, rel: PurePosixPath) -> str | None:
    name = rel.name
    if not (name == ".env" or name.startswith(".env.")) or name in _ENV_TEMPLATES:
        return None
    keys: list[str] = []
    filled = False
    for line in _read_head(path).splitlines():
        match = _ENV_LINE.match(line)
        if match is None:
            continue
        value = match.group("value").strip().strip(b"\"'").strip()
        if not value or value.startswith(b"#"):
            continue
        filled = True
        key = match.group("key").decode("ascii")
        if key not in keys and len(keys) < _MAX_ENV_KEYS:
            keys.append(key)
    # Only the NAMES leave this function; the values are never kept.
    return ", ".join(keys) if filled else None


def _private_key_label(path: Path, rel: PurePosixPath) -> str | None:
    name = rel.name.lower()
    if not (name.endswith(_KEY_SUFFIXES) or name in _KEY_NAMES):
        return None
    head = _read_head(path)
    match = _PEM_PRIVATE.search(head)
    if match is not None:
        kind = match.group("kind").decode("ascii")
        return f"-----BEGIN {kind}PRIVATE KEY-----"
    # PKCS#12 is DER: a SEQUENCE whose first element is INTEGER 3 (the version).
    if name.endswith((".p12", ".pfx")) and head[:1] == b"\x30" and b"\x02\x01\x03" in head[:8]:
        return "PKCS#12"
    return None


def _upload_root(rel_dir: PurePosixPath) -> PurePosixPath | None:
    """The shallowest upload-named directory on ``rel_dir``'s path, if any."""
    parts = rel_dir.parts
    for index, part in enumerate(parts):
        if part in _UPLOAD_NAMES or (part == "app" and index > 0 and parts[index - 1] == "storage"):
            return PurePosixPath(*parts[: index + 1])
    return None


def _common_dir(paths: list[PurePosixPath]) -> PurePosixPath:
    common = paths[0].parts
    for other in paths[1:]:
        parts = other.parts
        size = 0
        while size < min(len(common), len(parts)) and common[size] == parts[size]:
            size += 1
        common = common[:size]
    return PurePosixPath(*common)


def scan_artefacts(root: Path, *, max_files: int = MAX_FILES) -> ArtefactScan:
    """Walk ``root`` and report the artefacts it holds. Deterministic and capped."""
    hits: list[ArtefactHit] = []
    #: upload root → [(relative file, size, is an upload-type file)]
    uploads: dict[PurePosixPath, list[tuple[PurePosixPath, int, bool]]] = {}
    #: directory → [(size)] of logs over the floor
    logs: dict[PurePosixPath, list[int]] = {}
    seen = 0
    truncated = False
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            # `.git` only at the ROOT, where it is the repository the secrets
            # layer walks: a `.git/` deeper down is just a directory the tree
            # named, and a dump hidden in it is still reported (security panel).
            if not (name in _SKIPPED_DIRS and Path(current) == root)
            and not Path(current, name).is_symlink()
        )
        rel_dir = PurePosixPath(Path(current).relative_to(root).as_posix())
        upload_root = _upload_root(rel_dir) if rel_dir.parts else None
        for name in sorted(files):
            if seen >= max_files:
                truncated = True
                break
            path = Path(current, name)
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue  # symlinks, FIFOs, devices: never opened
            seen += 1
            rel = rel_dir / name
            size = info.st_size
            lowered = name.lower()
            if upload_root is not None:
                is_upload = PurePosixPath(lowered).suffix in _UPLOAD_SUFFIXES
                uploads.setdefault(upload_root, []).append((rel, size, is_upload))
            if lowered.endswith(".log") and size > LOG_MIN_BYTES:
                logs.setdefault(rel_dir, []).append(size)
            try:
                label = _dump_label(path, rel, size)
                if label is not None:
                    hits.append(ArtefactHit(DUMP, rel.as_posix(), size, label))
                    continue
                keys = _env_keys(path, rel)
                if keys is not None:
                    hits.append(ArtefactHit(ENV, rel.as_posix(), size, keys))
                    continue
                key_label = _private_key_label(path, rel)
                if key_label is not None:
                    hits.append(ArtefactHit(PRIVATE_KEY, rel.as_posix(), size, key_label))
            except OSError:
                continue
        if truncated:
            break

    for entries in uploads.values():
        typed = [rel for rel, _size, is_upload in entries if is_upload]
        if len(typed) < UPLOADS_MIN_FILES:
            continue
        # Reported where the uploaded files actually sit: the deepest directory
        # holding all of them, so a tree fanned out per user still counts once.
        where = _common_dir([rel.parent for rel in typed])
        inside = [size for rel, size, _ in entries if where == rel.parent or where in rel.parents]
        hits.append(
            ArtefactHit(UPLOADS, where.as_posix(), sum(inside), f"{len(inside)}", len(inside))
        )
    for directory, sizes in logs.items():
        hits.append(ArtefactHit(LOG, directory.as_posix(), sum(sizes), f"{len(sizes)}", len(sizes)))
    # Worst first, so the hit cap evicts a LOW log before a HIGH key — the
    # alphabetical order of the rule ids is not a severity (security panel).
    hits.sort(key=lambda hit: (SEVERITY_ORDER[RULE_TABLE[hit.rule_id][1]], hit.rule_id, hit.path))
    if len(hits) > MAX_HITS:
        hits = hits[:MAX_HITS]
        truncated = True
    return ArtefactScan(hits=tuple(hits), files_seen=seen, truncated=truncated)


def human_size(size: int) -> str:
    """Bytes as the report prints them: whole units, no locale."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{round(size / 1024)} KB"
    return f"{round(size / (1024 * 1024))} MB"


def _snippet(hit: ArtefactHit) -> str:
    if hit.rule_id in (UPLOADS, LOG):
        return ARTEFACT_COUNT_SNIPPET.format(files=hit.files, size=human_size(hit.size))
    return hit.detail


def to_finding(hit: ArtefactHit) -> NormalizedFinding:
    """One hit as an ordinary finding: triage, the report and every export take it as is."""
    cwe, severity = RULE_TABLE[hit.rule_id]
    entry = describe(cwe, artefact_rule=hit.rule_id)
    path = hit.path[:MAX_PATH]
    message = ARTEFACT_MESSAGES[hit.rule_id].format(
        files=hit.files, size=human_size(hit.size), detail=hit.detail
    )
    key = f"{path}\x00\x00{hit.rule_id}"
    return NormalizedFinding(
        category=ToolCategory.ARTEFACT,
        tools=(TOOL,),
        rule_id=hit.rule_id,
        cwe=cwe,
        owasp=owasp_for(cwe),
        title=entry.title,
        severity=severity,
        cvss_score=None,
        cvss_vector=None,
        path=path,
        line=None,
        snippet=_snippet(hit)[:MAX_SNIPPET],
        message=message[:MAX_MESSAGE],
        advisory=None,
        references=(),
        fingerprint=hashlib.sha256(key.encode("utf-8")).hexdigest(),
    )


__all__ = [
    "TOOL",
    "human_size",
    "to_finding",
    "DUMP",
    "ENV",
    "LOG",
    "PRIVATE_KEY",
    "RULE_IDS",
    "UPLOADS",
    "ArtefactHit",
    "ArtefactScan",
    "scan_artefacts",
]
