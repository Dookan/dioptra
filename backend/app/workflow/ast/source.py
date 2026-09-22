"""Reading one file of the audited tree for the AST layer.

The jail is the only root; a path from the plan that resolves outside it is
"not found", never an error that reveals the host layout.
"""

from __future__ import annotations

from pathlib import Path

from app.analysis.models import Analysis
from app.workflow.ast.errors import FunctionNotFound, SourceTooLarge, UnsupportedLanguage

MAX_SOURCE_BYTES = 512 * 1024

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".py": "python",
}


def language_for(path: str) -> str:
    suffix = Path(path).suffix.lower()
    language = LANGUAGE_BY_SUFFIX.get(suffix)
    if language is None:
        raise UnsupportedLanguage(suffix or "(no extension)")
    return language


def load_source(analysis: Analysis, path: str) -> bytes:
    """The file's bytes, from inside the jail only, size-capped."""
    if analysis.workspace_path is None:
        raise FunctionNotFound("analysis has no workspace")
    jail = Path(analysis.workspace_path).resolve()
    candidate = (jail / path).resolve()
    if not candidate.is_relative_to(jail) or not candidate.is_file():
        raise FunctionNotFound(path[:200])
    if candidate.stat().st_size > MAX_SOURCE_BYTES:
        raise SourceTooLarge(path[:200])
    return candidate.read_bytes()
