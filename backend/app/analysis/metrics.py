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
from pathlib import Path
from typing import Any

MAX_LIZARD_ROWS = 5000
_SKIPPED_DIRS = frozenset(
    {"node_modules", ".git", "vendor", "dist", "build", "venv", ".venv", "__pycache__"}
)
_SOURCE_SUFFIXES = frozenset({".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java"})
_HASH_COMMENT_SUFFIXES = frozenset({".py"})
#: A comment whose body looks like a statement rather than prose.
_CODE_LIKE = re.compile(
    r"^\s*(const|let|var|return|if|for|while|function|import|export|def|class|print|console\.)\b"
)
_COMMENTED_LINES_THRESHOLD = 3


def _to_int(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def parse_lizard_csv(text: str) -> list[dict[str, Any]]:
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
                "path": _relative_posix(record[6])[:1024],
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


def _relative_posix(path: str) -> str:
    text = path.strip().replace("\\", "/")
    if text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _looks_like_code(body: str) -> bool:
    stripped = body.strip()
    if not stripped:
        return False
    if stripped.endswith((";", "{", "}")):
        return True
    if _CODE_LIKE.match(stripped):
        return True
    return "= " in stripped and "(" in stripped


def _count_commented_code(path: Path, max_bytes: int) -> int:
    marker = "#" if path.suffix in _HASH_COMMENT_SUFFIXES else "//"
    with path.open("rb") as handle:
        raw = handle.read(max_bytes)
    count = 0
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.lstrip()
        if stripped.startswith(marker) and _looks_like_code(stripped[len(marker) :]):
            count += 1
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
