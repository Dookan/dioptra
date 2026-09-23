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


def php_string(text: str) -> str:
    """A SINGLE-quoted PHP string literal for arbitrary text.

    Single quotes are the smallest escape surface PHP offers: they interpolate
    nothing — no ``$var``, no ``{$expr}``, no ``\n`` — so a backslash and a
    quote are the whole of it. A double-quoted literal would make every ``$``
    in a developer's title an interpolation, i.e. code.
    """
    return "'" + one_line(text).replace("\\", "\\\\").replace("'", "\\'") + "'"


def studly(text: str, *, fallback: str) -> str:
    """StudlyCase, from the same ASCII slug every other identifier is built on.

    PHPUnit resolves a test class by file name, so the class and the file must
    agree; both are built from this.
    """
    return "".join(part.capitalize() for part in slug(text, fallback=fallback).split("_") if part)


def one_line(text: str) -> str:
    """Collapse to a single line: a newline in a ``//`` or ``#`` comment escapes it."""
    return " ".join(text.split())


def comment(text: str) -> str:
    """Comment-safe text: one line, and never ending the comment it sits in.

    Two sequences end a comment, and PHP is why there are two. ``*/`` closes a
    block comment in every language here. ``?>`` leaves PHP MODE ALTOGETHER —
    it ends a ``//`` line comment and everything after it is output, so a value
    carrying ``?> <?php …`` injects statements into a file that still passes
    ``php -l``. Proven inside `dioptra-sandbox-php:latest` by the precommit
    security panel, 2026-09-23: the values reaching here include brief-item
    text lifted from the AUDITED source (``$x === '?> <?php …'`` is a legal PHP
    condition), so this is hostile input, not prose.
    """
    return one_line(text).replace("*/", "* /").replace("?>", "? >")
