"""E6 scaffolds: deterministic, assertion-free, and safe with hostile case titles.

The scaffold is the ONLY thing the platform contributes to a test file
(CLAUDE.md → Hard Rules), so these tests pin both halves of that promise: the
same design always yields the byte-identical file, and no assertion of any
kind appears in it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

import pytest

from app.core.clock import utc_now
from app.workflow.errors import DesignNotApproved, UnparsableTests
from app.workflow.models import CaseDesign
from app.workflow.scaffold import build_scaffold, python_module
from app.workflow.scaffold.inspect import inspect_cases
from app.workflow.scaffold.text import MAX_SLUG_CHARS, js_string, py_string, slug

ITEMS: list[dict[str, Any]] = [
    {"id": "R1", "kind": "branch", "line": 4, "text": "whole <= 0", "detail": "true", "values": []},
    {
        "id": "F1",
        "kind": "boundary",
        "line": 4,
        "text": "whole <= 0",
        "detail": "<=",
        "values": ["-1", "0", "1"],
    },
    {
        "id": "M1",
        "kind": "malicious",
        "line": 5,
        "text": "Hallazgo */ <script>",
        "detail": "dioptra.no-cdn",
        "values": ["CWE-829"],
    },
]

#: Quotes, a backslash, a block-comment close and a JavaScript line terminator.
HOSTILE_TITLE = 'Caso "raro" con \\ barra, */ cierre y   salto'


def _design(
    path: str = "src/width-class.ts",
    function: str = "widthClass",
    cases: list[dict[str, Any]] | None = None,
    *,
    approved: bool = True,
) -> CaseDesign:
    design = CaseDesign(
        path=path,
        function=function,
        line=3,
        cases=cases if cases is not None else [{"title": "Caso normal", "covers": ["R1", "F1"]}],
        brief={"function": function, "path": path, "items": ITEMS},
        created_by_username="cperez",
    )
    if approved:
        design.approved_at = utc_now()
        design.approved_by_username = "cperez"
    return design


def _code_only(content: str) -> str:
    """The generated file without its comment lines (which tell the developer what to do)."""
    return "\n".join(line for line in content.splitlines() if not line.lstrip().startswith("//"))


def test_the_scaffold_is_byte_identical_across_processes() -> None:
    """Determinism has to survive a fresh interpreter, not just a second call.

    An in-process comparison passes even when the generator iterates a ``set``:
    the hash seed is fixed for the life of one process. Two subprocesses with
    different ``PYTHONHASHSEED`` are what actually pins it.
    """
    script = (
        "import sys;"
        "sys.path.insert(0, '.');"
        "from app.core.clock import utc_now;"
        "from app.workflow.models import CaseDesign;"
        "from app.workflow.scaffold import build_scaffold;"
        "import json;"
        "items = json.loads(sys.argv[1]);"
        "d = CaseDesign(path='src/width-class.ts', function='widthClass', line=3,"
        " cases=[{'title': 'Uno', 'covers': ['R1', 'F1', 'M1']},"
        " {'title': 'Dos', 'covers': ['F1', 'R1']}],"
        " brief={'items': items}, created_by_username='cperez');"
        "d.approved_at = utc_now();"
        "sys.stdout.write(build_scaffold(d).content)"
    )
    outputs = set()
    for seed in ("0", "1", "12345", "999"):
        result = subprocess.run(  # noqa: S603 — our own interpreter and our own script
            [sys.executable, "-c", script, json.dumps(ITEMS)],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.add(result.stdout)
    assert len(outputs) == 1, "the scaffold changed with the hash seed"


def test_the_scaffold_is_deterministic_and_holds_no_assertion() -> None:
    design = _design(
        cases=[
            {"title": "Ancho cero cuando el total es 0", "covers": ["R1", "F1"]},
            {"title": "Entrada maliciosa del hallazgo", "covers": ["M1"]},
        ]
    )
    first = build_scaffold(design)
    assert first.content == build_scaffold(design).content
    assert first.filename == "width_class.widthclass.6a467e.dioptra.test.ts"
    assert first.runner == "vitest"

    content = first.content
    assert 'import { widthClass } from "./width-class.ts";' in content
    assert 'it("C1 · Ancho cero cuando el total es 0", () => {' in content
    assert "// covers F1 — boundary" in content and "values: -1, 0, 1" in content
    for forbidden in ("expect(", "assert", "toBe", "toEqual", "==="):
        assert forbidden not in _code_only(content), forbidden
    # A brief item's text is audited source: it may not close the comment.
    assert "*/ <script>" not in content and "* / <script>" in content


def test_a_hostile_case_title_cannot_break_out_of_the_generated_file() -> None:
    ts = build_scaffold(_design(cases=[{"title": HOSTILE_TITLE, "covers": ["R1"]}]))
    # It still parses, and the title lives inside one string literal.
    bodies = inspect_cases(ts.content, "src/width-class.ts", ts.cases)
    assert [body.id for body in bodies] == ["C1"] and not bodies[0].written
    assert " " not in ts.content
    assert ts.content.count('it("C1 ') == 1

    py = build_scaffold(
        _design(path="src/escape.py", function="mermaid_escape", cases=[{"title": HOSTILE_TITLE}])
    )
    assert py.filename == "test_escape_mermaid_escape_078855_dioptra.py"
    assert py.runner == "pytest" and "from escape import mermaid_escape" in py.content
    bodies = inspect_cases(py.content, "src/escape.py", py.cases)
    assert [body.id for body in bodies] == ["C1"] and not bodies[0].written


def test_an_unapproved_design_gets_no_scaffold() -> None:
    with pytest.raises(DesignNotApproved):
        build_scaffold(_design(approved=False))


def test_a_path_python_cannot_import_becomes_a_todo_not_a_broken_import() -> None:
    # The sandbox puts the module at the attempt directory's root, so the
    # import is by basename — never the audited tree's dotted path.
    assert python_module("src/helpers/edad.py") == "edad"
    assert python_module("my-lib/edad-2.py") is None
    scaffold = build_scaffold(_design(path="my-lib/edad-2.py", function="obtener_edad"))
    assert "\nfrom " not in scaffold.content
    assert (
        "# TODO(developer): import the function under test from my-lib/edad-2.py"
        in scaffold.content
    )


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("    // TODO(developer): write this case.", False),
        ("    const x = 1;", True),
        ('    "just a string";', False),
    ],
)
def test_a_javascript_case_counts_only_with_a_statement_of_its_own(
    written: str, expected: bool
) -> None:
    scaffold = build_scaffold(_design(cases=[{"title": "Caso", "covers": ["R1"]}]))
    content = f'it("C1 · Caso", () => {{\n{written}\n}});\n'
    assert inspect_cases(content, "src/width-class.ts", scaffold.cases)[0].written is expected


@pytest.mark.parametrize(
    "content",
    [
        'it.skip("C1 · Caso", () => {\n  const x = 1;\n});\n',
        # The suite around the case is skipped: nothing in it runs either.
        'describe.skip("s", () => {\n  it("C1 · Caso", () => {\n    const x = 1;\n  });\n});\n',
        'describe.todo("s", () => {\n  it("C1 · Caso", () => {\n    const x = 1;\n  });\n});\n',
    ],
)
def test_a_skipped_javascript_case_is_not_a_written_case(content: str) -> None:
    scaffold = build_scaffold(_design(cases=[{"title": "Caso", "covers": ["R1"]}]))
    assert not inspect_cases(content, "src/width-class.ts", scaffold.cases)[0].present
    concurrent = 'it.concurrent("C1 · Caso", () => {\n  const x = 1;\n});\n'
    assert inspect_cases(concurrent, "src/width-class.ts", scaffold.cases)[0].written
    nested = 'describe("s", () => {\n  it("C1 · Caso", () => {\n    const x = 1;\n  });\n});\n'
    assert inspect_cases(nested, "src/width-class.ts", scaffold.cases)[0].written


def test_a_concise_arrow_body_is_a_written_case() -> None:
    """``it("C1 · x", () => expect(f()).toBe(1))`` has no block, but it is written."""
    scaffold = build_scaffold(_design(cases=[{"title": "Caso", "covers": ["R1"]}]))
    concise = 'it("C1 · Caso", () => expect(widthClass(1, 2)).toBe("w50"));\n'
    assert inspect_cases(concise, "src/width-class.ts", scaffold.cases)[0].written


@pytest.mark.parametrize(
    "decorator", ["@pytest.mark.skip", '@pytest.mark.skipif(True, reason="x")']
)
def test_a_skipped_python_case_is_not_a_written_case(decorator: str) -> None:
    scaffold = build_scaffold(
        _design(path="src/escape.py", function="mermaid_escape", cases=[{"title": "Caso"}])
    )
    name = scaffold.cases[0].name
    content = f"{decorator}\ndef {name}() -> None:\n    assert mermaid_escape(1) == 1\n"
    assert not inspect_cases(content, "src/escape.py", scaffold.cases)[0].present
    plain = f"def {name}() -> None:\n    assert mermaid_escape(1) == 1\n"
    assert inspect_cases(plain, "src/escape.py", scaffold.cases)[0].written


def test_an_absurd_case_number_does_not_raise_inside_the_gate() -> None:
    """A digit run past CPython's ``int()`` limit must read as unwritten, not raise."""
    scaffold = build_scaffold(_design(cases=[{"title": "Caso", "covers": ["R1"]}]))
    huge = "9" * 4400
    js = f'it("C{huge} · Caso", () => {{\n  const x = 1;\n}});\n'
    assert not inspect_cases(js, "src/width-class.ts", scaffold.cases)[0].present

    py_scaffold = build_scaffold(
        _design(path="src/escape.py", function="mermaid_escape", cases=[{"title": "Caso"}])
    )
    py = f"def test_c{huge}_x() -> None:\n    assert 1\n"
    assert not inspect_cases(py, "src/escape.py", py_scaffold.cases)[0].present


def test_a_backslash_in_the_path_cannot_break_the_python_scaffold() -> None:
    """A path may hold a backslash (git ingest); ``\\N{`` alone is a SyntaxError."""
    scaffold = build_scaffold(
        _design(path="src/a\\N{x}.py", function="mermaid_escape", cases=[{"title": "Caso"}])
    )
    compile(scaffold.content, "<scaffold>", "exec")
    # The docstring is where a backslash would be an escape; in the `#` comment
    # below it Python does not interpret escapes at all.
    docstring = scaffold.content.split('"""')[1]
    assert "\\" not in docstring and "a/N{x}.py" in docstring


def test_two_functions_with_the_same_basename_get_different_files() -> None:
    """E7 copies every planned function's file into ONE run directory."""
    first = build_scaffold(_design(path="components/index.ts", function="render"))
    second = build_scaffold(_design(path="utils/index.ts", function="render"))
    assert first.filename != second.filename
    assert build_scaffold(_design(path="components/index.ts", function="render")).filename == (
        first.filename
    )


def test_a_malformed_design_row_yields_an_empty_scaffold_not_an_exception() -> None:
    """The gate may not raise: a corrupted row reads as "no cases", never a crash."""
    design = _design(cases=[{"title": "Caso", "covers": ["R1"]}])
    design.brief = {"items": "not a list"}
    design.cases = [None, "nope", {"title": "Bien", "covers": "no"}]  # type: ignore[list-item]
    scaffold = build_scaffold(design)
    assert [case.id for case in scaffold.cases] == ["C1"]
    assert scaffold.cases[0].covers == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("    # TODO(developer): write this case.\n    pass", False),
        ("    ...", False),
        ("    assert obtener_edad(1) == 1", True),
    ],
)
def test_a_python_case_counts_only_with_a_statement_of_its_own(body: str, expected: bool) -> None:
    scaffold = build_scaffold(
        _design(path="src/escape.py", function="mermaid_escape", cases=[{"title": "Caso"}])
    )
    content = f'def {scaffold.cases[0].name}() -> None:\n    "C1 · Caso"\n{body}\n'
    assert inspect_cases(content, "src/escape.py", scaffold.cases)[0].written is expected


def test_a_test_file_that_does_not_parse_is_refused_not_guessed() -> None:
    scaffold = build_scaffold(_design(cases=[{"title": "Caso", "covers": ["R1"]}]))
    with pytest.raises(UnparsableTests):
        inspect_cases("it('C1 · Caso', () => { const ", "src/width-class.ts", scaffold.cases)


def test_text_helpers_escape_at_their_boundary() -> None:
    assert slug("obtenerEdad", fallback="fn") == "obteneredad"
    assert slug("¡Año 2026!", fallback="fn") == "ano_2026"
    assert slug("", fallback="fn") == "fn"
    assert slug("9lives", fallback="fn") == "fn_9lives"
    # A 200-char case title must not become a 200-char generated identifier.
    assert len(slug("x" * 200, fallback="fn")) == MAX_SLUG_CHARS
    assert js_string('a "b" \\ c') == '"a \\"b\\" \\\\ c"'
    # A JavaScript line terminator never survives into a literal: the
    # whitespace collapse removes it, and the explicit escape is the backstop.
    assert " " not in js_string("x y")
    assert py_string("a 'b' \\ c") == repr("a 'b' \\ c")


def test_a_half_written_case_call_is_read_not_crashed_on() -> None:
    """``it("C1 · Caso");`` is an ordinary half-finished edit, not an error.

    Reading the callback without checking that it is there raises
    ``IndexError``, which is neither a ``WorkflowError`` nor an ``AstError`` —
    so it would escape the gate's ``except`` and break "the gate may not raise".
    """
    scaffold = build_scaffold(_design(cases=[{"title": "Caso", "covers": ["R1"]}]))
    for content in ('it("C1 · Caso");\n', "it();\n", 'it("C1 · Caso", );\n'):
        assert not inspect_cases(content, "src/width-class.ts", scaffold.cases)[0].present


def _case_body_lines(content: str, opener: str, comment_marker: str) -> list[str]:
    """The generated lines between a case's opener and its end, stripped."""
    body = content.split(opener, 1)[1]
    lines = []
    for line in body.splitlines()[:]:
        stripped = line.strip()
        if stripped in ("});", ""):
            break
        lines.append(stripped)
    del comment_marker
    return lines


def test_audited_item_text_cannot_escape_the_generated_comment() -> None:
    """A brief item's text is AUDITED SOURCE and lands in a ``//`` / ``#`` comment.

    Without the one-line collapse, a newline inside it would end the comment
    and the rest would be a live statement in the developer's file.
    """
    hostile_item = {
        "id": "R1",
        "kind": "branch",
        "line": 4,
        "text": "linea1\nconst pwned = 1;",
        "detail": "true",
        "values": ["a\nconst also = 2;"],
    }
    design = _design(cases=[{"title": "Caso", "covers": ["R1"]}])
    design.brief = {"items": [hostile_item]}
    ts = build_scaffold(design)
    assert "\nconst pwned" not in ts.content and "\nconst also" not in ts.content
    for line in _case_body_lines(ts.content, 'it("C1 · Caso", () => {', "//"):
        assert line.startswith("//"), line

    design.path = "src/escape.py"
    design.function = "mermaid_escape"
    py = build_scaffold(design)
    assert "\nconst pwned" not in py.content
    for line in _case_body_lines(py.content, f"def {py.cases[0].name}() -> None:", "#"):
        assert line.startswith("#") or line.startswith("'"), line


def test_a_brief_that_is_not_a_document_at_all_is_tolerated() -> None:
    """A corrupted ``brief`` column must not make the gate raise either."""
    for broken in ("not a dict", ["x"], 7):
        design = _design(cases=[{"title": "Caso", "covers": ["R1"]}])
        design.brief = broken  # type: ignore[assignment]
        scaffold = build_scaffold(design)
        assert [case.id for case in scaffold.cases] == ["C1"]


def test_an_approved_design_without_its_snapshot_gets_no_scaffold() -> None:
    """Approval stores the brief; without it E7 has nothing to measure against."""
    design = _design(cases=[{"title": "Caso", "covers": ["R1"]}])
    design.brief = {}
    with pytest.raises(DesignNotApproved):
        build_scaffold(design)


def test_a_function_name_that_is_not_an_identifier_degrades_instead_of_breaking() -> None:
    """A method (``obj.method``) cannot be imported by name in either language."""
    ts = build_scaffold(_design(function="obj.method"))
    assert 'import * as subject from "./width-class.ts";' in ts.content
    assert "import { obj.method }" not in ts.content

    py = build_scaffold(
        _design(path="src/escape.py", function="obj.method", cases=[{"title": "Caso"}])
    )
    assert "from escape import obj.method" not in py.content
    assert "# TODO(developer): import the function under test from src/escape.py" in py.content
    compile(py.content, "<scaffold>", "exec")
