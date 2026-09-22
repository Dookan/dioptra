"""Turning approved-design text into identifiers and literals, safely.

Case titles are the developer's own words and function names come from the
audited AST: both reach a generated source file, so every one of them is
escaped AT THIS BOUNDARY before it becomes an identifier, a string literal or
a comment. Nothing here inspects meaning — the platform never interprets the
developer's prose (docs/workflow-gates.md → Test brief).
"""

from __future__ import annotations

import json
import re
import unicodedata

MAX_SLUG_CHARS = 48

#: JavaScript treats these as line terminators inside a string literal, and
#: ``json.dumps`` leaves them raw — they would break out of the quotes.
_JS_LINE_TERMINATORS = {" ": "\\u2028", " ": "\\u2029"}

_NON_SLUG = re.compile(r"[^a-z0-9]+")


def slug(text: str, *, fallback: str) -> str:
    """A lowercase ASCII identifier fragment; ``fallback`` when nothing survives."""
    folded = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    cleaned = _NON_SLUG.sub("_", folded.lower()).strip("_")
    cleaned = cleaned[:MAX_SLUG_CHARS].strip("_")
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"{fallback}_{cleaned}" if cleaned else fallback
    return cleaned


def js_string(text: str) -> str:
    """A double-quoted JavaScript string literal for arbitrary text."""
    literal = json.dumps(one_line(text), ensure_ascii=False)
    for character, escape in _JS_LINE_TERMINATORS.items():
        literal = literal.replace(character, escape)
    return literal


def py_string(text: str) -> str:
    """A Python string literal for arbitrary text (``repr`` quotes and escapes)."""
    return repr(one_line(text))


def one_line(text: str) -> str:
    """Collapse to a single line: a newline in a ``//`` or ``#`` comment escapes it."""
    return " ".join(text.split())


def comment(text: str) -> str:
    """Comment-safe text: one line, and never closing a block comment."""
    return one_line(text).replace("*/", "* /")
