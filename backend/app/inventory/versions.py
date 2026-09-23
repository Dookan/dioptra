"""Version comparison for the BOM ↔ CVE correlation.

One tolerant comparer for every ecosystem rather than a parser per packaging
standard (survey §4): a version is split into segments, numeric segments
compare as integers, and a version that carries a non-numeric tail
(``1.0.0-rc1``) orders BEFORE its numeric prefix (``1.0.0``) — that is the
one ordering rule every ecosystem the platform knows agrees on. Anything the
comparer cannot parse is reported as such, and the correlation lists the
component as "versión no comparable" instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_SEGMENT = re.compile(r"\d+|[A-Za-z]+")
_MAX_CHARS = 100


@dataclass(frozen=True, order=False)
class ParsedVersion:
    #: Numeric segments in order (``1.2.3`` → ``(1, 2, 3)``); trailing zeros dropped.
    numbers: tuple[int, ...]
    #: Lower-cased alphabetic tail after the numbers (``rc``, ``beta``, …); empty = a release.
    tail: tuple[str | int, ...]

    def _key(self) -> tuple[tuple[int, ...], int, tuple[str | int, ...]]:
        # A release (no tail) sorts AFTER any pre-release of the same numbers.
        return (self.numbers, 1 if not self.tail else 0, self.tail)

    def __lt__(self, other: ParsedVersion) -> bool:
        return self._key() < other._key()

    def __le__(self, other: ParsedVersion) -> bool:
        return self._key() <= other._key()

    def __gt__(self, other: ParsedVersion) -> bool:
        return self._key() > other._key()

    def __ge__(self, other: ParsedVersion) -> bool:
        return self._key() >= other._key()


def parse(version: object) -> ParsedVersion | None:
    """Parse a version string, or ``None`` when it holds nothing comparable."""
    if not isinstance(version, str):
        return None
    text = version.strip()[:_MAX_CHARS]
    if text.startswith(("v", "V")) and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    # An epoch ("1:2.3") and build metadata ("+build.7") never change ordering
    # between two versions of the same package in practice; both are dropped.
    if ":" in text:
        text = text.split(":", 1)[1]
    text = text.split("+", 1)[0]
    # A range or a wildcard ("^1.2.3", "~1.2", "*", ">=1.0") is a SPEC, not a
    # version: nothing that does not start with a digit is comparable.
    if not text or not text[0].isdigit():
        return None
    segments = _SEGMENT.findall(text)
    if not segments or not segments[0].isdigit():
        return None
    numbers: list[int] = []
    tail: list[str | int] = []
    for segment in segments:
        if segment.isdigit() and not tail:
            numbers.append(int(segment))
        elif segment.isdigit():
            tail.append(int(segment))
        else:
            tail.append(segment.lower())
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    return ParsedVersion(numbers=tuple(numbers), tail=tuple(tail))


def _events(range_entry: dict[str, Any]) -> list[tuple[str, ParsedVersion]]:
    out: list[tuple[str, ParsedVersion]] = []
    events = range_entry.get("events")
    if not isinstance(events, list):
        return out
    for event in events:
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected"):
            raw = event.get(kind)
            if not isinstance(raw, str):
                continue
            parsed = parse(raw)
            if parsed is not None:
                out.append((kind, parsed))
    return out


def affected(version: ParsedVersion, versions: list[Any], ranges: list[Any]) -> bool:
    """Is ``version`` inside the advisory's explicit list or one of its ranges?

    OSV semantics: a range is a sequence of events; ``introduced`` opens an
    affected interval, the next ``fixed`` closes it exclusively and
    ``last_affected`` closes it inclusively. ``GIT`` ranges carry commit
    hashes, which nothing in an SBOM can be compared to, so they are ignored.
    """
    for listed in versions:
        parsed = parse(listed)
        if parsed is not None and parsed._key() == version._key():
            return True
    for range_entry in ranges:
        if not isinstance(range_entry, dict):
            continue
        if str(range_entry.get("type", "")).upper() == "GIT":
            continue
        introduced: ParsedVersion | None = None
        for kind, bound in _events(range_entry):
            if kind == "introduced":
                introduced = bound
                continue
            if introduced is None:
                continue
            if kind == "fixed" and introduced <= version < bound:
                return True
            if kind == "last_affected" and introduced <= version <= bound:
                return True
            introduced = None
        # An interval opened and never closed: everything from `introduced` on.
        if introduced is not None and introduced <= version:
            return True
    return False


def first_fix_after(version: ParsedVersion, ranges: list[Any]) -> str | None:
    """The smallest ``fixed`` version above ``version``, as the advisory spells it."""
    best: tuple[ParsedVersion, str] | None = None
    for range_entry in ranges:
        if not isinstance(range_entry, dict):
            continue
        events = range_entry.get("events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            raw = event.get("fixed")
            if not isinstance(raw, str):
                continue
            parsed = parse(raw)
            if parsed is None or parsed <= version:
                continue
            if best is None or parsed < best[0]:
                best = (parsed, raw.strip()[:_MAX_CHARS])
    return None if best is None else best[1]
