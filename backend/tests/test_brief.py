"""E5 day 15: the test brief is deterministic and its basis paths match a hand count.

The plan's acceptance for the day: briefs for at least three REAL functions
whose basis paths, counted by hand, match the platform's count. The three
fixtures under ``tests/fixtures/ast/real_*`` are verbatim copies of this
repository's own functions; every number below was counted on the listing.
"""

from __future__ import annotations

from pathlib import Path

import app.db.registry  # noqa: F401 — configures the mappers before Analysis() is built
from app.analysis.models import Analysis, ToolCategory, Verdict
from app.workflow.ast.extract import build_graph
from app.workflow.brief import Brief, boundary_values, brief_as_dict, build_brief
from tests.support import make_finding

FIXTURES = Path(__file__).parent / "fixtures" / "ast"


def _brief(name: str, language: str, function: str, analysis: Analysis | None = None) -> Brief:
    graph = build_graph((FIXTURES / name).read_bytes(), language, function, None)
    return build_brief(analysis or Analysis(), name, graph)


def _ids(brief: Brief, kind: str) -> list[str]:
    return [item.id for item in brief.items if item.kind == kind]


# --- three real functions, counted by hand ---------------------------------


def test_width_class_ts_hand_count() -> None:
    # widthClass: one `if` with one `||` → 1 + 1 + 1 = 3 basis paths:
    # (whole <= 0) short-circuits, (part <= 0) alone, neither.
    brief = _brief("real_width_class.ts", "typescript", "widthClass")
    assert brief.complexity == 3
    assert brief.min_cases == 3  # no SAST finding inside → no malicious case
    assert brief.params == ["part: number", "whole: number"]
    branches = [(i.line, i.detail) for i in brief.items if i.kind == "branch"]
    assert branches == [(4, "true"), (4, "false")]
    boundaries = [(i.text, i.values) for i in brief.items if i.kind == "boundary"]
    assert boundaries == [("whole <= 0", ["-1", "0", "1"]), ("part <= 0", ["-1", "0", "1"])]
    errors = [(i.line, i.detail) for i in brief.items if i.kind == "error"]
    assert errors == [(4, "early_return")]  # the final return (line 6) is not an error path
    assert [i.id for i in brief.items] == ["R1", "R2", "F1", "F2", "E1"]


def test_mermaid_escape_py_hand_count() -> None:
    # mermaid_escape: for (1) + if (1) + elif ×3 (3) + `or` (1) → 1 + 6 = 7.
    brief = _brief("real_mermaid_escape.py", "python", "mermaid_escape")
    assert brief.complexity == 7
    assert brief.min_cases == 7
    # Every decision has both sides: the loop, the if and the three elifs → 10 branch items.
    assert len(_ids(brief, "branch")) == 10
    assert [i.line for i in brief.items if i.kind == "branch"] == [
        10,
        10,
        12,
        12,
        14,
        14,
        16,
        16,
        18,
        18,
    ]
    boundaries = {i.text: i.values for i in brief.items if i.kind == "boundary"}
    assert boundaries == {
        "char == '\"'": ['"', ""],
        'char == "#"': ["#", ""],
        "code < 32": ["31", "32", "33"],
        "code == 127": ["126", "127", "128"],
    }
    # `char in "<>…"` is membership, not a literal comparison → no boundary.
    assert _ids(brief, "error") == []  # one final return, no raise


def test_risk_matrix_py_hand_count() -> None:
    # risk_matrix: if (1) + for (1) + if (1) + for (1) + `or` ×2 (2) + ternary ×2 (2)
    # → 1 + 8 = 9. The lambdas' own conditionals are nested functions: excluded.
    brief = _brief("real_risk_matrix.py", "python", "risk_matrix")
    assert brief.complexity == 9
    assert brief.min_cases == 9
    branches = [(i.line, i.detail) for i in brief.items if i.kind == "branch"]
    assert branches == [
        (10, "true"),
        (10, "false"),
        (13, "true"),
        (13, "false"),
        (14, "true"),
        (14, "false"),
        (17, "true"),
        (17, "false"),
    ]
    assert _ids(brief, "boundary") == []  # `is None` / `is not None` are not literal comparisons
    assert [(i.line, i.detail) for i in brief.items if i.kind == "error"] == [(11, "early_return")]


# --- boundary values ---------------------------------------------------------


def test_boundary_values_by_literal_kind() -> None:
    assert boundary_values(18, ">=") == ["17", "18", "19"]
    assert boundary_values(0, "<=") == ["-1", "0", "1"]
    assert boundary_values(-1, "!=") == ["-2", "-1", "0"]
    assert boundary_values(0.5, "<") == ["0.4", "0.5", "0.6"]
    assert boundary_values(0.25, "===") == ["0.24", "0.25", "0.26"]
    assert boundary_values(100.0, ">") == ["99", "100", "101"]
    assert boundary_values(1e3, ">") == ["999", "1000", "1001"]
    assert boundary_values("admin", "===") == ["admin", ""]
    assert boundary_values("", "===") == [""]  # the empty literal, once
    assert boundary_values("admin", "<") == ["admin"]
    assert boundary_values(float("inf"), "<") == []


def test_boundaries_from_every_operator_and_compound_expressions() -> None:
    source = b"""
function f(a, b, c, s) {
  if (a < 1 && b <= 2 || c > 3) { return 1; }
  if (a >= 4 && b == 5 && c != 6) { return 2; }
  if (s === "x" || s !== `y` || s === `t${a}`) { return 3; }
  if (a >= 0x10 || b > 1_000 || c < -2.5 || a === 10n) { return 4; }
  if (a > (5) || (a) === (-2)) { return 5; }
  const inner = () => a > 99;
  return 0;
}
"""
    brief = build_brief(Analysis(), "f.js", build_graph(source, "javascript", "f", None))
    boundaries = [(i.detail, i.values) for i in brief.items if i.kind == "boundary"]
    assert boundaries == [
        ("<", ["0", "1", "2"]),
        ("<=", ["1", "2", "3"]),
        (">", ["2", "3", "4"]),
        (">=", ["3", "4", "5"]),
        ("==", ["4", "5", "6"]),
        ("!=", ["5", "6", "7"]),
        ("===", ["x", ""]),
        ("!==", ["y", ""]),
        # the template with a substitution is not a literal; `a > 99` is inside a nested function
        (">=", ["15", "16", "17"]),
        (">", ["999", "1000", "1001"]),
        ("<", ["-2.6", "-2.5", "-2.4"]),
        ("===", ["9", "10", "11"]),
        (">", ["4", "5", "6"]),  # parentheses around a literal are transparent
        ("===", ["-3", "-2", "-1"]),
    ]


def test_hostile_literals_never_raise_and_stay_bounded() -> None:
    huge_hex = "0x" + "f" * 5000  # int(text, 16) accepts it; str(value - 1) would not
    huge_dec = "9" * 5000
    long_string = "s" * 3000
    source = (
        "function h(x, s) {\n"
        f"  if (x == {huge_hex} || x === {huge_dec} || x > 1e400 || s === '{long_string}') "
        "{ return 1; }\n  return 0;\n}\n"
    ).encode()
    brief = build_brief(Analysis(), "h.js", build_graph(source, "javascript", "h", None))
    boundaries = [(i.detail, i.values) for i in brief.items if i.kind == "boundary"]
    # The numbers are dropped (no boundary is worth testing there); the string is clipped.
    assert [d for d, _ in boundaries] == ["==="]
    assert len(boundaries[0][1][0]) == 60 and boundaries[0][1][1] == ""
    assert boundary_values("x" * 200, "===")[0].endswith("…")


def test_a_try_right_after_a_loop_adds_no_phantom_branch() -> None:
    # The except edge leaves the try marker, which sits right under the loop:
    # the loop's branch items must stay "enter" and "skip" only.
    source = b"""
def t(items):
    for item in items:
        print(item)
    try:
        int(items[0])
    except ValueError:
        return -1
    return 0
"""
    brief = build_brief(Analysis(), "t.py", build_graph(source, "python", "t", None))
    branches = [(i.line, i.detail) for i in brief.items if i.kind == "branch"]
    assert branches == [(3, "true"), (3, "false")]
    assert [(i.line, i.detail) for i in brief.items if i.kind == "error"] == [
        (7, "handler"),
        (8, "early_return"),
    ]


def test_a_try_as_the_whole_loop_body_adds_no_loop_branch() -> None:
    # An empty try body makes the loop's back edge leave the try marker with
    # the label "loop": that is not a branch to design a case for.
    source = b"""
function w(items) {
  for (const item of items) { try {} catch (e) { console.log(e); } }
  return 0;
}
"""
    brief = build_brief(Analysis(), "w.js", build_graph(source, "javascript", "w", None))
    branches = [(i.line, i.detail) for i in brief.items if i.kind == "branch"]
    assert branches == [(3, "true"), (3, "false")]
    assert all(i.detail != "loop" for i in brief.items)


def test_python_chained_comparison_and_prefixed_strings() -> None:
    source = b"""
def f(x, s):
    if 0 < x <= 10 and s == r'raw' and s != f"{x}" and x == 3j:
        return 1
    return 0
"""
    brief = build_brief(Analysis(), "f.py", build_graph(source, "python", "f", None))
    boundaries = [(i.text, i.values) for i in brief.items if i.kind == "boundary"]
    assert boundaries == [
        ("0 < x", ["-1", "0", "1"]),
        ("x <= 10", ["9", "10", "11"]),
        ("s == r'raw'", ["raw", ""]),
    ]  # `x == 3j`: a complex literal has no boundary


# --- error paths and malicious cases ----------------------------------------


def test_error_paths_throw_handler_and_early_return_only() -> None:
    source = b"""
function g(x) {
  if (!x) throw new Error("no");
  try { JSON.parse(x); } catch (e) { return null; }
  if (x === 1) { return 1; }
  return 2;
}
"""
    brief = build_brief(Analysis(), "g.js", build_graph(source, "javascript", "g", None))
    errors = [(i.line, i.detail) for i in brief.items if i.kind == "error"]
    assert errors == [(3, "throw"), (4, "handler"), (4, "early_return"), (5, "early_return")]


def test_malicious_case_per_sast_finding_inside_the_function() -> None:
    graph = build_graph((FIXTURES / "sample.js").read_bytes(), "javascript", "validateForm", None)
    analysis = Analysis()
    inside = make_finding(0, path="src/sample.js", line=4, title="Registro sin sanear")
    outside = make_finding(1, path="src/sample.js", line=30)
    other_file = make_finding(2, path="src/other.js", line=4)
    discarded = make_finding(3, path="src/sample.js", line=5, verdict=Verdict.FALSE_POSITIVE)
    sca = make_finding(4, path="src/sample.js", line=6, category=ToolCategory.SCA)
    no_line = make_finding(5, path="src/sample.js", line=None)
    analysis.findings = [inside, outside, other_file, discarded, sca, no_line]
    brief = build_brief(analysis, "src/sample.js", graph)
    malicious = [i for i in brief.items if i.kind == "malicious"]
    assert [(i.id, i.line, i.text, i.values, i.finding_id) for i in malicious] == [
        ("M1", 4, "Registro sin sanear", ["CWE-79"], str(inside.id))
    ]
    assert brief.min_cases == brief.complexity + 1
    # Both ends of the function are inside (lines 2..9 for validateForm); the neighbours are not.
    first_line, last_line = graph.line, graph.nodes[-1].line or 0
    assert (first_line, last_line) == (2, 9)
    for line, expected in (
        (first_line, 1),
        (last_line, 1),
        (first_line - 1, 0),
        (last_line + 1, 0),
    ):
        analysis.findings = [make_finding(9, path="src/sample.js", line=line)]
        edge_brief = build_brief(analysis, "src/sample.js", graph)
        assert sum(1 for i in edge_brief.items if i.kind == "malicious") == expected, line
    analysis.findings = [inside, outside, other_file, discarded, sca, no_line]
    # A confirmed verdict keeps the case; unknown CWE → no value, still a case.
    inside.verdict = Verdict.CONFIRMED
    inside.cwe = None
    again = build_brief(analysis, "src/sample.js", graph)
    assert [i.values for i in again.items if i.kind == "malicious"] == [[]]


def test_brief_is_deterministic_and_serialisable() -> None:
    first = _brief("real_mermaid_escape.py", "python", "mermaid_escape")
    second = _brief("real_mermaid_escape.py", "python", "mermaid_escape")
    assert first == second
    payload = brief_as_dict(first)
    assert payload["items"][0] == {
        "id": "R1",
        "kind": "branch",
        "line": 10,
        "text": "for char in text",
        "detail": "true",
        "values": [],
        "finding_id": None,
    }
    assert payload["min_cases"] == 7 and payload["function"] == "mermaid_escape"
