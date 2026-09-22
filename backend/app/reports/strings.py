"""Loader of the institutional report strings.

The strings themselves live in ``templates/report/strings.json`` — report
CONTENT in Spanish, verbatim from the anchor reports, the carve-out CLAUDE.md
names. This module only reads the file once; it contains no copy of its own.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

TEMPLATES_DIR = (Path(__file__).resolve().parents[2] / "templates" / "report").resolve()


@lru_cache(maxsize=1)
def report_strings() -> dict[str, Any]:
    """The parsed strings file, cached for the process lifetime."""
    data = json.loads((TEMPLATES_DIR / "strings.json").read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        message = "templates/report/strings.json must be a JSON object"
        raise TypeError(message)
    return data
