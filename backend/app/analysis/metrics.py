"""Code metrics: Lizard (complexity), cloc (line counts) and the commented-code scan.

The Lizard and cloc outputs come from tools run over the audited tree; the
scan reads the tree itself. All three inputs are hostile: rows are capped,
files are read up to a fixed size, symlinks are never followed.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from app.analysis.normalizer import DEFAULT_ROOTS, normalize_path

MAX_LIZARD_ROWS = 5000
_SKIPPED_DIRS = frozenset(
    {"node_modules", ".git", "vendor", "dist", "build", "venv", ".venv", "__pycache__"}
)
# `.vue`, `.css`, `.scss` and `.html` joined on 2026-09-24: the anchor report of
# the MINCYT frontend lists Vue and CSS files, whose commented-out code lives in
# `<!-- … -->` and `/* … */` blocks the line-comment scan never saw.
_SOURCE_SUFFIXES = frozenset(
    {".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".vue", ".css", ".scss", ".html"}
)
_HASH_COMMENT_SUFFIXES = frozenset({".py"})
#: Block comments, as (opener, closer). Python has none worth reading here.
_BLOCK_COMMENTS = (("/*", "*/"), ("<!--", "-->"))
#: What makes a comment's body count as code. Deliberately the SAME breadth as
#: the generator of the institution's anchor reports (`mmarin`, 2026-09-24:
#: the "Errores y prácticas" section must list what the anchor listed): a
#: statement ending, a keyword, an arrow, an assignment, or a call — which also
#: matches prose shaped like one ("Vista Especial (Sin Layout)"). The report
#: calls these files "con código comentado"; the breadth is the anchor's.
_CODE_SIGNAL = re.compile(
    r";\s*$|\{\s*$|\}\s*[;,]?\s*$|=>"
    r"|\b(function|const|let|var|return|import|export|require|class|def|public|private|elif)\b"
    r"|\b(if|for|while|switch|catch)\s*\("
    r"|console\.|System\.|printf\s*\(|print\s*\(|await\b"
    r"|\b\w+\s*=\s*[^=]"
    r"|\b\w+\s*\([^)]*\)\s*[;{]?\s*$"
)
#: Tool directives and task notes are not disabled code. `nota` is matched, not
#: shown: audited code is often commented in Spanish.
_NOT_CODE = re.compile(
    r"^\s*(todo|fixme|note|nota|hack|xxx|eslint|prettier|@ts-|noqa|type:)\b", re.IGNORECASE
)
#: A markup element in a comment (typically `<!-- … -->`) is disabled template
#: code, not prose.
_MARKUP_LIKE = re.compile(r"^\s*</?[A-Za-z][\w-]*(\s|>|/|$)")
_COMMENTED_LINES_THRESHOLD = 2
#: `_CODE_SIGNAL` was quadratic on a long line (unanchored `\w+` and `[^)]*`,
#: measured 14.7 s on 32 KB) and runs in the worker over hostile files. The
#: `\b` before both `\w+` alternatives (phase-10 panel, 2026-09-28) makes a
#: failed match restart at word starts only — same lines matched, 13.8 ms →
#: 0.09 ms on a 999-character word — and this cap stays as the second bound. A
#: disabled statement is never kilobytes long; a longer line is minified or
#: encoded data, so it is not code by definition and never reaches the regex.
_MAX_COMMENT_LINE = 1000


def _to_int(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def parse_lizard_csv(text: str, roots: Sequence[str] = DEFAULT_ROOTS) -> list[dict[str, Any]]:
    """``lizard --csv`` → per-function rows, most complex first.

    Columns: nloc, ccn, token, param, length, location, file, function,
    long_name, start, end. Malformed rows are skipped, never raised on.
    """
    rows: list[dict[str, Any]] = []
    for record in csv.reader(io.StringIO(text)):
        if len(record) < 11:
            continue
        nloc, ccn, _token, params = (_to_int(value) for value in record[:4])
        start, end = _to_int(record[9]), _to_int(record[10])
        if nloc is None or ccn is None:
            continue  # the header row, or garbage
        rows.append(
            {
                "path": normalize_path(record[6], roots)[:1024],
                "function": record[7].strip()[:200],
                "line": start,
                "end_line": end,
                "nloc": nloc,
                "ccn": ccn,
                "params": params if params is not None else 0,
            }
        )
    rows.sort(key=lambda row: (-row["ccn"], row["path"], row["line"] or 0, row["function"]))
    return rows[:MAX_LIZARD_ROWS]


def parse_cloc_json(text: str) -> dict[str, dict[str, int]]:
    """``cloc --json`` → ``{language: {files, blank, comment, code}}`` including ``SUM``."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(document, dict):
        return {}
    result: dict[str, dict[str, int]] = {}
    for language, counts in document.items():
        if language == "header" or not isinstance(counts, dict):
            continue
        files = counts.get("nFiles", counts.get("files", 0))
        result[str(language)[:64]] = {
            "files": _as_int(files),
            "blank": _as_int(counts.get("blank")),
            "comment": _as_int(counts.get("comment")),
            "code": _as_int(counts.get("code")),
        }
    return result


def _as_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _looks_like_code(body: str) -> bool:
    stripped = body.strip()
    if not stripped or len(stripped) > _MAX_COMMENT_LINE or _NOT_CODE.match(stripped):
        return False
    return bool(_MARKUP_LIKE.match(stripped) or _CODE_SIGNAL.search(stripped))


def _count_commented_code(path: Path, max_bytes: int) -> int:
    marker = "#" if path.suffix in _HASH_COMMENT_SUFFIXES else "//"
    blocks = () if path.suffix in _HASH_COMMENT_SUFFIXES else _BLOCK_COMMENTS
    with path.open("rb") as handle:
        raw = handle.read(max_bytes)
    count = 0
    closer: str | None = None  # set while inside a block comment
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if closer is None:
            opened = next(((o, c) for o, c in blocks if stripped.startswith(o)), None)
            if opened is None:
                if stripped.startswith(marker) and _looks_like_code(stripped[len(marker) :]):
                    count += 1
                continue
            stripped = stripped[len(opened[0]) :]
            closer = opened[1]
        body, ends, _ = stripped.partition(closer)
        # A leading `*` is the conventional gutter of a `/* … */` block, not code.
        if _looks_like_code(body.strip().lstrip("*")):
            count += 1
        if ends:
            closer = None
    return count


def scan_commented_code(
    root: Path, *, max_files: int = 5000, max_bytes_per_file: int = 1_000_000
) -> list[str]:
    """Files with commented-out code (report section "Errores y prácticas").

    Heuristic on purpose: a comment line whose body ends like a statement or
    starts like one. A file with three or more such lines is listed.
    Deterministic, capped, and it never follows a symlink.
    """
    listed: list[str] = []
    seen = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name not in _SKIPPED_DIRS and not Path(current, name).is_symlink()
        )
        for name in sorted(files):
            if seen >= max_files:
                return sorted(listed)
            path = Path(current, name)
            if path.suffix not in _SOURCE_SUFFIXES or path.is_symlink() or not path.is_file():
                continue
            seen += 1
            try:
                count = _count_commented_code(path, max_bytes_per_file)
            except OSError:
                continue
            if count >= _COMMENTED_LINES_THRESHOLD:
                listed.append(path.relative_to(root).as_posix())
    return sorted(listed)


__all__ = [
    "MAX_LIZARD_ROWS",
    "parse_cloc_json",
    "parse_lizard_csv",
    "scan_commented_code",
]
