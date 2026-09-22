"""Reading back what the sandbox produced.

The three result files are ATTACKER-CONTROLLED DATA: they are written by a
process running the audited code. So they are parsed as data — never
evaluated, never trusted for shape — and every list that comes out of them is
bounded. A file that is missing, truncated or not the document it claims is a
coverage figure of zero and a recorded reason, not an exception.

Coverage is normalised to one shape for both languages:

- Python: ``coverage json`` gives ``executed_lines``, ``missing_lines`` and,
  with ``--branch``, ``executed_branches`` / ``missing_branches`` as
  ``[from, to]`` line pairs.
- JavaScript: the v8 provider emits an istanbul document — ``statementMap``
  keyed by id with line ranges, ``s`` with hit counts, ``branchMap`` with a
  ``line`` per branch and ``b`` with the count of each of its arms.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

MAX_SURVIVORS = 200
MAX_FAILED_CASES = 200


@dataclass(frozen=True)
class Coverage:
    """What the run executed, per line, in the module under test."""

    executed_lines: frozenset[int]
    missing_lines: frozenset[int]
    #: Lines holding a branch where at least one arm was never taken.
    partial_branch_lines: frozenset[int]
    total_branches: int
    covered_branches: int

    @property
    def statement_percent(self) -> float:
        total = len(self.executed_lines) + len(self.missing_lines)
        return 100.0 if total == 0 else round(100.0 * len(self.executed_lines) / total, 1)

    @property
    def branch_percent(self) -> float:
        if self.total_branches == 0:
            return 100.0
        return round(100.0 * self.covered_branches / self.total_branches, 1)

    def covers_line(self, line: int | None) -> bool:
        """A brief item's line counts only when it ran AND its branch is complete."""
        if line is None:
            return False
        return line in self.executed_lines and line not in self.partial_branch_lines

    def as_dict(self) -> dict[str, Any]:
        return {
            "executed_lines": sorted(self.executed_lines),
            "missing_lines": sorted(self.missing_lines),
            "partial_branch_lines": sorted(self.partial_branch_lines),
            "total_branches": self.total_branches,
            "covered_branches": self.covered_branches,
            "statement_percent": self.statement_percent,
            "branch_percent": self.branch_percent,
        }


EMPTY_COVERAGE = Coverage(
    executed_lines=frozenset(),
    missing_lines=frozenset(),
    partial_branch_lines=frozenset(),
    total_branches=0,
    covered_branches=0,
)


@dataclass(frozen=True)
class Mutation:
    tool: str
    killed: int | None
    total: int | None
    survived: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "killed": self.killed,
            "total": self.total,
            "survived": self.survived,
        }


EMPTY_MUTATION = Mutation(tool="none", killed=None, total=None, survived=[])


def _document(raw: bytes | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _ints(values: Any) -> set[int]:
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, int)}


def parse_coverage(raw: bytes | None, *, language: str, module_file: str) -> Coverage:
    document = _document(raw)
    if document is None:
        return EMPTY_COVERAGE
    if language == "python":
        return _python_coverage(document, module_file)
    return _istanbul_coverage(document, module_file)


def _python_coverage(document: dict[str, Any], module_file: str) -> Coverage:
    files = document.get("files")
    if not isinstance(files, dict):
        return EMPTY_COVERAGE
    entry = files.get(module_file)
    if not isinstance(entry, dict):
        entry = next((value for value in files.values() if isinstance(value, dict)), None)
    if entry is None:
        return EMPTY_COVERAGE

    executed = _ints(entry.get("executed_lines"))
    missing = _ints(entry.get("missing_lines"))
    taken = _branch_pairs(entry.get("executed_branches"))
    untaken = _branch_pairs(entry.get("missing_branches"))
    return Coverage(
        executed_lines=frozenset(executed),
        missing_lines=frozenset(missing),
        partial_branch_lines=frozenset(source for source, _ in untaken),
        total_branches=len(taken) + len(untaken),
        covered_branches=len(taken),
    )


def _branch_pairs(values: Any) -> list[tuple[int, int]]:
    if not isinstance(values, list):
        return []
    pairs: list[tuple[int, int]] = []
    for item in values:
        if (
            isinstance(item, list)
            and len(item) == 2
            and isinstance(item[0], int)
            and isinstance(item[1], int)
        ):
            pairs.append((item[0], item[1]))
    return pairs


def _istanbul_coverage(document: dict[str, Any], module_file: str) -> Coverage:
    entry = next(
        (
            value
            for key, value in document.items()
            if isinstance(value, dict) and str(key).endswith(module_file)
        ),
        None,
    )
    if entry is None:
        entry = next((value for value in document.values() if isinstance(value, dict)), None)
    if entry is None:
        return EMPTY_COVERAGE

    executed: set[int] = set()
    missing: set[int] = set()
    statements = entry.get("statementMap")
    counts = entry.get("s")
    if isinstance(statements, dict) and isinstance(counts, dict):
        for key, location in statements.items():
            line = _start_line(location)
            if line is None:
                continue
            hit = counts.get(key)
            (executed if isinstance(hit, int) and hit > 0 else missing).add(line)
    missing -= executed

    partial: set[int] = set()
    total = covered = 0
    branches = entry.get("branchMap")
    branch_counts = entry.get("b")
    if isinstance(branches, dict) and isinstance(branch_counts, dict):
        for key, branch in branches.items():
            arms = branch_counts.get(key)
            if not isinstance(arms, list) or not isinstance(branch, dict):
                continue
            line = branch.get("line")
            if not isinstance(line, int):
                line = _start_line(branch.get("loc"))
            total += len(arms)
            taken = sum(1 for arm in arms if isinstance(arm, int) and arm > 0)
            covered += taken
            if taken < len(arms) and line is not None:
                partial.add(line)
    return Coverage(
        executed_lines=frozenset(executed),
        missing_lines=frozenset(missing),
        partial_branch_lines=frozenset(partial),
        total_branches=total,
        covered_branches=covered,
    )


def _start_line(location: Any) -> int | None:
    if not isinstance(location, dict):
        return None
    start = location.get("start")
    if not isinstance(start, dict):
        return None
    line = start.get("line")
    return line if isinstance(line, int) else None


def parse_mutation(raw: bytes | None) -> Mutation:
    """Our own normalised document, written by the wrapper inside the image."""
    document = _document(raw)
    if document is None:
        return EMPTY_MUTATION
    survived: list[dict[str, str]] = []
    for item in document.get("survived") or []:
        if not isinstance(item, dict):
            continue
        survived.append(
            {
                "id": str(item.get("id", ""))[:200],
                "line": str(item.get("line", ""))[:12],
                "mutant": str(item.get("mutant", ""))[:400],
            }
        )
        if len(survived) >= MAX_SURVIVORS:
            break
    killed = document.get("killed")
    total = document.get("total")
    return Mutation(
        tool=str(document.get("tool", "unknown"))[:40],
        killed=killed if isinstance(killed, int) else None,
        total=total if isinstance(total, int) else None,
        survived=survived,
    )


def parse_failed_cases(raw: bytes | None) -> list[str]:
    """Case names JUnit reported as failed or errored.

    Parsed with a bounded regular expression rather than an XML parser: the
    document is written by the audited code's own test run, and an XML parser
    is a larger attack surface (entities, external DTDs) than this needs.
    """
    if not raw:
        return []
    import re

    text = raw.decode("utf-8", "replace")
    failed: list[str] = []
    for match in re.finditer(r"<testcase\b[^>]*\bname=\"([^\"]{0,300})\"([^>]*)>", text):
        name, rest = match.group(1), match.group(2)
        # Cut at the element boundary: a fixed window would cross
        # `</testcase>` and hang the NEXT case's failure on this one. pytest
        # self-closes a passing case, vitest does not.
        tail = text[match.end() :].split("</testcase>", 1)[0][:400]
        if rest.rstrip().endswith("/"):
            continue
        if "<failure" in tail or "<error" in tail:
            failed.append(name)
        if len(failed) >= MAX_FAILED_CASES:
            break
    return failed
