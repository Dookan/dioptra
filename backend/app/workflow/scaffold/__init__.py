"""Stage E6 (day 16): the deterministic test scaffold of one planned function.

**The platform MUST NOT write tests** (CLAUDE.md → Hard Rules). What is
generated here is a file name, the imports and one named case per APPROVED
case — never an assertion, never test data, never logic. Everything comes
from the AST and from the design the developer approved at E5, so the same
row always produces the byte-identical file; that is what lets the E6 gate
compare what the developer stored against what the platform offered.

The generated comments are English like the rest of the code base
(CLAUDE.md → English everywhere in code). That is also the technical answer:
the file is compared byte for byte, so its content may not depend on the UI
language of whoever happened to open the screen.

The imports name the module by its BASENAME, because that is the layout the
E7 sandbox provides: one attempt directory per planned function holding the
module under test and this file, and nothing else (`app/sandbox/workspace.py`).
Keeping the audited tree's directories would also break mutmut, which refuses
outright to mutate a module whose dotted path starts with ``src.``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from app.workflow.ast.source import language_for
from app.workflow.errors import DesignNotApproved
from app.workflow.models import CaseDesign
from app.workflow.scaffold.text import comment, js_string, one_line, py_string, slug

#: The case id opens the case name; the E6 gate finds a case by this prefix,
#: so the developer may reword the title but must keep the id.
CASE_SEPARATOR = " · "

_JS_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_PY_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_KIND_WORD = {
    "branch": "branch",
    "boundary": "boundary",
    "error": "error path",
    "malicious": "malicious input",
}


@dataclass(frozen=True)
class ScaffoldCase:
    """One case of the approved design as it appears in the generated file."""

    id: str
    #: Python: the function name. JS/TS: the full ``it()`` title.
    name: str
    title: str
    covers: list[str]


@dataclass(frozen=True)
class ScaffoldFile:
    filename: str
    language: str
    runner: str
    #: What the file imports the module under test by.
    import_specifier: str
    content: str
    cases: list[ScaffoldCase]


def _brief_items(design: CaseDesign) -> dict[str, dict[str, Any]]:
    """The approved snapshot's items by id, tolerant of a malformed row.

    Every writer normalises before storing, so a wrong shape means the row was
    corrupted underneath us — and `gates.leave_tests` may not raise on it.
    """
    brief = design.brief if isinstance(design.brief, dict) else {}
    items = brief.get("items")
    if not isinstance(items, list):
        return {}
    return {str(item.get("id")): item for item in items if isinstance(item, dict)}


def _stored_cases(design: CaseDesign) -> list[dict[str, Any]]:
    cases = design.cases if isinstance(design.cases, list) else []
    return [case for case in cases if isinstance(case, dict)]


def _item_note(item: dict[str, Any]) -> str:
    """One comment line describing a brief item, from the approved snapshot."""
    kind = _KIND_WORD.get(str(item.get("kind")), "item")
    text = comment(str(item.get("text") or ""))
    detail = comment(str(item.get("detail") or ""))
    values = [comment(str(value)) for value in item.get("values") or []]
    parts = [kind]
    if text:
        parts.append(f'"{text}"')
    if detail:
        parts.append(f"({detail})")
    if values:
        parts.append("values: " + ", ".join(values))
    line = item.get("line")
    if isinstance(line, int):
        parts.append(f"at line {line}")
    return " ".join(parts)


def _covers_of(case: dict[str, Any]) -> list[str]:
    covers = case.get("covers")
    return [str(value) for value in covers] if isinstance(covers, list) else []


def _covers_notes(covers: list[str], items: dict[str, dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for item_id in covers:
        item = items.get(item_id)
        notes.append(f"{item_id} — {_item_note(item)}" if item else f"{item_id}")
    return notes


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _stem(path: str) -> str:
    name = _basename(path)
    return name.rsplit(".", 1)[0] if "." in name else name


def _discriminator(path: str, line: int | None) -> str:
    """Six hex characters of the full path and line.

    The file name is built from basenames, so ``components/index.ts::render``
    and ``utils/index.ts::render`` would otherwise collide — and E7 copies
    every planned function's file into ONE run directory. Deterministic by
    construction: the same row always yields the same six characters.
    """
    seed = f"{path}:{line if line is not None else ''}".encode()
    return hashlib.sha256(seed).hexdigest()[:6]


def build_scaffold(design: CaseDesign) -> ScaffoldFile:
    """The scaffold for one APPROVED design row.

    Refuses an unapproved row: without the snapshot there is no case list the
    E7 re-audit could measure the developer's file against.
    """
    if design.approved_at is None or not design.brief:
        raise DesignNotApproved(f"{design.path}:{design.line} {design.function}"[:200])
    language = language_for(design.path)
    if language == "python":
        return _python_scaffold(design)
    return _javascript_scaffold(design, language)


def _javascript_scaffold(design: CaseDesign, language: str) -> ScaffoldFile:
    items = _brief_items(design)
    function = design.function
    suffix = design.path.rsplit(".", 1)[-1]
    stem = slug(_stem(design.path), fallback="module")
    mark = _discriminator(design.path, design.line)
    filename = f"{stem}.{slug(function, fallback='fn')}.{mark}.dioptra.test.{suffix}"
    specifier = "./" + _basename(design.path)

    named = bool(_JS_IDENTIFIER.match(function))
    if named:
        import_line = f"import {{ {function} }} from {js_string(specifier)};"
    else:
        # A method or a name JavaScript cannot import by identifier: import the
        # module and let the developer reach into it.
        import_line = f"import * as subject from {js_string(specifier)};"

    lines = [
        f"// Dioptra · E6 scaffold — {comment(function)} ({comment(design.path)}:{design.line})",
        "// The platform does not write tests. The names below and the brief",
        "// items each case must demonstrate come from the design you approved;",
        "// every assertion, every input and every expected value is yours.",
        "// Keep the case id at the start of each title — E6 finds your case by it.",
        "",
        'import { describe, it } from "vitest";',
        import_line,
        "",
        f"describe({js_string(function)}, () => {{",
    ]
    cases: list[ScaffoldCase] = []
    stored = _stored_cases(design)
    for index, case in enumerate(stored, start=1):
        case_id = f"C{index}"
        title = one_line(str(case.get("title") or ""))
        name = f"{case_id}{CASE_SEPARATOR}{title}"
        covers = _covers_of(case)
        cases.append(ScaffoldCase(id=case_id, name=name, title=title, covers=covers))
        lines.append(f"  it({js_string(name)}, () => {{")
        for note in _covers_notes(covers, items):
            lines.append(f"    // covers {note}")
        lines.append("    // TODO(developer): write this case.")
        lines.append("  });")
        if index < len(stored):
            lines.append("")
    lines.append("});")
    lines.append("")
    return ScaffoldFile(
        filename=filename,
        language=language,
        runner="vitest",
        import_specifier=specifier,
        content="\n".join(lines),
        cases=cases,
    )


def _docstring_safe(text: str) -> str:
    """Comment-safe text that also survives a Python docstring.

    Quotes are folded so the triple quote cannot close early, and backslashes
    with it: a path may contain one (git ingest allows it; ZIP ingest already
    refuses backslash entries), and a stray ``\\N{`` alone would make the
    generated file a ``SyntaxError``.
    """
    return comment(text).replace("\\", "/").replace('"', "'")


def python_module(path: str) -> str | None:
    """The module name the sandbox will expose, or ``None`` when it is not importable.

    The sandbox puts the module under test at the root of the attempt
    directory, so the import is by basename — ``src/helpers/edad.py`` becomes
    ``edad``. A stem that is not a Python identifier (``my-lib.py``) has no
    import at all and the scaffold says so instead of emitting a broken one.
    """
    stem = _stem(path)
    return stem if _PY_IDENTIFIER.match(stem) else None


def _python_scaffold(design: CaseDesign) -> ScaffoldFile:
    items = _brief_items(design)
    function = design.function
    function_slug = slug(function, fallback="fn")
    stem = slug(_stem(design.path), fallback="module")
    mark = _discriminator(design.path, design.line)
    filename = f"test_{stem}_{function_slug}_{mark}_dioptra.py"
    module = python_module(design.path)
    importable = module is not None and bool(_PY_IDENTIFIER.match(function))

    lines = [
        '"""Dioptra · E6 scaffold — '
        + _docstring_safe(function)
        + " ("
        + _docstring_safe(design.path)
        + f":{design.line}).",
        "",
        "The platform does not write tests. The names below and the brief items",
        "each case must demonstrate come from the design you approved; every",
        "assertion, every input and every expected value is yours.",
        "",
        "Keep the case id at the start of each function name — E6 finds your",
        "case by it.",
        '"""',
        "",
    ]
    if importable:
        lines.append(f"from {module} import {function}")
    else:
        lines.append(
            "# TODO(developer): import the function under test from " + comment(design.path)
        )
    lines.append("")
    lines.append("")

    cases: list[ScaffoldCase] = []
    stored = _stored_cases(design)
    for index, case in enumerate(stored, start=1):
        case_id = f"C{index}"
        title = one_line(str(case.get("title") or ""))
        name = f"test_c{index}_{slug(title, fallback=function_slug)}"
        covers = _covers_of(case)
        cases.append(ScaffoldCase(id=case_id, name=name, title=title, covers=covers))
        lines.append(f"def {name}() -> None:")
        lines.append(f"    {py_string(name_title(case_id, title))}")
        for note in _covers_notes(covers, items):
            lines.append(f"    # covers {note}")
        lines.append("    # TODO(developer): write this case.")
        if index < len(stored):
            lines.append("")
            lines.append("")
    lines.append("")
    return ScaffoldFile(
        filename=filename,
        language="python",
        runner="pytest",
        import_specifier=module or design.path,
        content="\n".join(lines),
        cases=cases,
    )


def name_title(case_id: str, title: str) -> str:
    return f"{case_id}{CASE_SEPARATOR}{title}"
