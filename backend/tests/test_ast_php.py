"""PHP flow graphs and briefs (wave 2, phase 7a).

Three things are proven here, in this order:

1. every construct the PHP profile names produces the node it should — and
   in particular the three shapes with no wave-1 analogue: ``throw`` as an
   EXPRESSION, ``elseif`` as a chained clause, and a ``body`` field where
   Python and JavaScript say ``consequence``;
2. the plan's day-15 acceptance, applied to wave 2: briefs for three
   functions whose basis paths, counted BY HAND, match the platform's count;
3. the ``tree-sitter<0.26`` pin re-probed FOR THIS GRAMMAR. The 0.26.0 heap
   corruption was a core-binding fault, so it is not covered by the Python
   probe: a new grammar gets its own.

**Recorded deviation from wave 1** (tasks/phase7a-php.md): the wave-1
``real_*`` fixtures are verbatim copies of this repository's own functions.
This repository contains no PHP, so the three fixtures below were written for
the purpose in idiomatic Laravel-flavoured style. The hand count is still a
hand count — every number was counted on the listing before it was asserted —
but the "real project" half of the acceptance is met by the E1–E7 walk in the
task's Definition of Done, not here.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import app.db.registry  # noqa: F401 — configures the mappers before Analysis() is built
from app.analysis.models import Analysis
from app.workflow.ast.errors import FunctionNotFound, ParseFailed, TooDeep
from app.workflow.ast.extract import MAX_DEPTH, MAX_NODES, build_graph
from app.workflow.ast.source import language_for
from app.workflow.brief import Brief, build_brief

FIXTURES = Path(__file__).parent / "fixtures" / "ast"
SAMPLE = (FIXTURES / "sample.php").read_bytes()


def _brief(name: str, function: str) -> Brief:
    graph = build_graph((FIXTURES / name).read_bytes(), "php", function, None)
    return build_brief(Analysis(), name, graph)


def _kinds(graph: object) -> list[str]:
    return [node.kind for node in graph.nodes]  # type: ignore[attr-defined]


def test_php_files_route_to_the_php_profile() -> None:
    assert language_for("app/Http/Controllers/UserController.php") == "php"
    assert language_for("APP/MODELS/User.PHP") == "php"


def test_method_with_every_construct() -> None:
    graph = build_graph(SAMPLE, "php", "Account::check", 7)
    assert graph.name == "check" and graph.line == 7
    assert graph.params == ["int $age", "?string $name = null"]
    # 1 + if + && + elseif + foreach + while + catch + ?? + ternary = 9
    assert graph.complexity == 9
    kinds = _kinds(graph)
    assert kinds.count("decision") == 3  # if, elseif, try
    assert kinds.count("loop") == 2
    assert kinds.count("return") == 2 and kinds.count("throw") == 1
    assert kinds[0] == "start" and kinds[-1] == "end"
    end = graph.nodes[-1].id
    assert sum(1 for e in graph.edges if e.target == end) == 3  # 2 returns, 1 throw


def test_throw_is_an_expression_in_php_and_still_becomes_a_throw_node() -> None:
    """PHP 8 made ``throw`` an expression, so it arrives wrapped in a statement.

    Without the unwrap it would collapse into a process box and the brief
    would lose the error path — which is exactly the item E7 measures.
    """
    graph = build_graph(SAMPLE, "php", "Account::check", 7)
    throws = [node for node in graph.nodes if node.kind == "throw"]
    assert len(throws) == 1
    assert throws[0].label.startswith("throw new \\InvalidArgumentException")
    assert [item.detail for item in _brief("sample.php", "Account::check").items].count(
        "throw"
    ) == 1


def test_elseif_is_a_chained_decision_named_after_the_source_keyword() -> None:
    graph = build_graph(SAMPLE, "php", "Account::check", 7)
    labels = [node.label for node in graph.nodes if node.kind == "decision"]
    assert "elseif $age < 0" in labels  # not "elif": the diagram says what the source says
    decision = next(n.id for n in graph.nodes if n.label == "if $age >= 18 && $name !== null")
    chained = next(n.id for n in graph.nodes if n.label == "elseif $age < 0")
    assert (decision, chained, "false") in {(e.source, e.target, e.label) for e in graph.edges}


def test_an_ordinary_expression_statement_is_not_unwrapped() -> None:
    """Only a wrapper around a COMPOUND expression unwraps; assignments stay boxes."""
    graph = build_graph(SAMPLE, "php", "Account::check", 7)
    labels = [node.label for node in graph.nodes if node.kind == "process"]
    assert "$label = 'adult';" in labels and "$total = 0;" in labels


def test_switch_reads_its_subject_from_the_condition_field() -> None:
    """PHP names the subject `condition`, not `value`/`subject` as wave 1 does.

    The parentheses stay in the label: JavaScript's `value` field is a
    parenthesized expression too, so `switch ($total)` reads exactly like the
    `switch (data.kind)` wave 1 already draws. Stripping them here would have
    changed every existing JS diagram, which a wave-2 phase must not do.
    """
    graph = build_graph(SAMPLE, "php", "Account::suffix", 37)
    decision = next(n for n in graph.nodes if n.kind == "decision")
    assert decision.label == "switch ($total)"
    labels = {e.label for e in graph.edges if e.source == decision.id}
    assert labels == {"case 0", "default"}


# --- three functions, basis paths counted by hand --------------------------


def test_validar_cedula_hand_count() -> None:
    # 3 ifs (3) + `||` (1) + `||` (1) + `&&` (1) → 1 + 6 = 7 basis paths.
    brief = _brief("real_validar_cedula.php", "validarCedula")
    assert brief.complexity == 7
    assert brief.min_cases == 7  # no SAST finding inside → no malicious case
    assert brief.params == ["?string $cedula", "string $nacionalidad"]
    assert [i.id for i in brief.items] == [
        *("R1", "R2", "R3", "R4", "R5", "R6"),
        *("F1", "F2", "F3", "F4", "F5", "F6"),
        *("E1", "E2", "E3"),
    ]
    boundaries = [(i.text, i.values) for i in brief.items if i.kind == "boundary"]
    assert boundaries == [
        ("$cedula === ''", [""]),  # already the empty string: one value, not three
        ("strlen($limpia) < 6", ["5", "6", "7"]),
        ("strlen($limpia) > 8", ["7", "8", "9"]),
        ("$nacionalidad !== 'V'", ["V", ""]),
        ("$nacionalidad !== 'E'", ["E", ""]),
        ("(int) $limpia > 0", ["-1", "0", "1"]),
    ]
    # `$cedula === null` yields no boundary: null is not a literal value.
    assert all("null" not in text for text, _ in boundaries)
    assert [(i.line, i.detail) for i in brief.items if i.kind == "error"] == [
        (10, "early_return"),
        (15, "early_return"),
        (19, "early_return"),
    ]


def test_calcular_mora_hand_count() -> None:
    # foreach (1) + `??` (1) + if (1) + 2 match arms (2) + if (1) + if (1) → 1 + 7 = 8.
    # The `default =>` arm is NOT counted: it is the fall-through, like a
    # switch default.
    brief = _brief("real_calcular_mora.php", "calcularMora")
    assert brief.complexity == 8
    assert brief.min_cases == 8
    # Four decisions are DRAWN (the loop and three ifs) → eight branch items.
    # The match contributes two basis paths but no item: it is an expression,
    # so it never reaches the statement walker (tasks/phase7-survey.md §3.1).
    assert len([i for i in brief.items if i.kind == "branch"]) == 8
    assert [(i.text, i.values) for i in brief.items if i.kind == "boundary"] == [
        ("$atraso > 90", ["89", "90", "91"]),
        ("$total < 0", ["-1", "0", "1"]),
    ]
    assert [(i.line, i.detail) for i in brief.items if i.kind == "error"] == [(31, "throw")]


def test_resolver_estado_hand_count() -> None:
    # 3 `case` (3) + ternary (1) + 2 `catch` (2) → 1 + 6 = 7.
    # The `default:` label is not counted, like every other default.
    brief = _brief("real_resolver_estado.php", "resolverEstado")
    assert brief.complexity == 7
    assert brief.min_cases == 7
    assert [i.detail for i in brief.items if i.kind == "branch"] == [
        "case 'aprobar'",
        "case 'rechazar'",
        "case 'devolver'",
        "default",
    ]
    assert [i.detail for i in brief.items if i.kind == "error"] == [
        "throw",
        "handler",
        "early_return",
        "handler",
        "early_return",
    ]


# --- hostile source ---------------------------------------------------------


def test_missing_function_and_syntax_error_are_typed() -> None:
    with pytest.raises(FunctionNotFound):
        build_graph(SAMPLE, "php", "noSuchMethod", None)
    broken = b"<?php\nfunction f($a) {\n    if ($a > {\n}\n"
    with pytest.raises(ParseFailed):
        build_graph(broken, "php", "f", None)


def test_nesting_cap_is_exact() -> None:
    def source(depth: int) -> bytes:
        body = "".join("    " * (i + 1) + f"if ($x > {i}) {{\n" for i in range(depth))
        body += "    " * (depth + 1) + "$x = 1;\n"
        body += "".join("    " * (depth - i) + "}\n" for i in range(depth))
        return f"<?php\nfunction f($x) {{\n{body}}}\n".encode()

    build_graph(source(MAX_DEPTH - 3), "php", "f", None)
    with pytest.raises(TooDeep):
        build_graph(source(MAX_DEPTH + 5), "php", "f", None)


def test_node_cap_is_refused() -> None:
    body = "".join(f"    if ($x > {i}) {{ $x -= 1; }}\n" for i in range(MAX_NODES))
    with pytest.raises(Exception) as excinfo:  # noqa: B017 — the typed error is asserted below
        build_graph(f"<?php\nfunction f($x) {{\n{body}    return $x;\n}}\n".encode(), "php", "f", 1)
    assert excinfo.value.__class__.__module__.startswith("app.workflow.ast")


def test_graph_is_deterministic() -> None:
    from app.workflow.ast.extract import graph_as_dict

    first = graph_as_dict(build_graph(SAMPLE, "php", "Account::check", 7))
    second = graph_as_dict(build_graph(SAMPLE, "php", "Account::check", 7))
    assert first == second


def test_output_is_identical_across_processes_and_hash_seeds() -> None:
    """Graph, Mermaid and layout must not depend on set/dict ordering."""
    script = (
        "import hashlib, json, sys\n"
        "from app.workflow.ast.extract import build_graph, graph_as_dict\n"
        "from app.workflow.diagrams import layout, layout_as_dict, to_mermaid\n"
        "graph = build_graph(sys.stdin.buffer.read(), 'php', 'Account::check', 7)\n"
        "blob = json.dumps([graph_as_dict(graph), to_mermaid(graph), "
        "layout_as_dict(layout(graph))], sort_keys=False)\n"
        "print(hashlib.sha256(blob.encode()).hexdigest())\n"
    )
    digests = set()
    for seed in ("1", "4242", "random"):
        result = subprocess.run(  # noqa: S603 — our own interpreter, our own script
            [sys.executable, "-c", script],
            input=SAMPLE,
            capture_output=True,
            timeout=60,
            check=False,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        assert result.returncode == 0, result.stderr[-300:]
        digests.add(result.stdout.strip())
    assert len(digests) == 1


LARGE_SHAPES: dict[str, str] = {
    "while": "<?php\nfunction f($x) {\n"
    + "".join(f"    while ($x > {i}) {{ $x -= 1; }}\n" for i in range(150))
    + "    return $x;\n}\n",
    # One try with 150 handlers, mirroring the Python probe's 150 `except`
    # clauses: the same parse pressure with far fewer graph nodes, so the probe
    # measures the BINDING and not our own MAX_NODES cap.
    "catch": "<?php\nfunction f($x) {\n    try { $x += 1; }\n"
    + "".join(f"    catch (\\E{i} $e) {{}}\n" for i in range(150))
    + "    return $x;\n}\n",
    "if": "<?php\nfunction f($x) {\n"
    + "".join(f"    if ($x > {i}) {{ $x -= 1; }}\n" for i in range(120))
    + "    return $x;\n}\n",
}


@pytest.mark.parametrize("shape", sorted(LARGE_SHAPES))
def test_large_functions_do_not_crash_the_process(shape: str) -> None:
    """The ``tree-sitter<0.26`` pin, re-probed for the PHP grammar.

    py-tree-sitter 0.26.0 corrupted the heap (SIGSEGV) on ordinary shapes of
    this size. The graph is built in a child interpreter so a binding
    regression shows up as a failed assertion on the exit code, never as a
    dead test runner. Keep this test when lifting the pin.
    """
    script = (
        "import sys\n"
        "from app.workflow.ast.extract import build_graph\n"
        "graph = build_graph(sys.stdin.buffer.read(), 'php', 'f', 2)\n"
        "print(len(graph.nodes), graph.complexity)\n"
    )
    for _ in range(3):  # the corruption was heap-layout dependent: repeat
        result = subprocess.run(  # noqa: S603 — our own interpreter, our own script
            [sys.executable, "-c", script],
            input=LARGE_SHAPES[shape].encode(),
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, (shape, result.returncode, result.stderr[-300:])
        nodes, complexity = (int(value) for value in result.stdout.split())
        assert nodes > 100 and complexity > 100
