"""JavaScript / TypeScript flow graphs: arrow functions, methods, every construct."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.workflow.ast.errors import FunctionNotFound, ParseFailed
from app.workflow.ast.extract import build_graph

FIXTURES = Path(__file__).parent / "fixtures" / "ast"
SAMPLE_JS = (FIXTURES / "sample.js").read_bytes()
SAMPLE_TS = (FIXTURES / "sample.ts").read_bytes()


def test_arrow_function_with_every_construct() -> None:
    graph = build_graph(SAMPLE_JS, "javascript", "validateForm", 2)
    assert graph.name == "validateForm" and graph.params == ["data"]
    # 1 + if + else-if + || + for + if + 2 cases + catch + ternary = 10
    assert graph.complexity == 10
    kinds = [n.kind for n in graph.nodes]
    assert kinds.count("return") == 5 and kinds.count("throw") == 1
    assert kinds.count("loop") == 1
    switch = next(n for n in graph.nodes if n.label == "switch (data.kind)")
    branches = sorted(e.label for e in graph.edges if e.source == switch.id)
    assert branches == ["case 'a'", "case 'b'", "default"]
    try_node = next(n for n in graph.nodes if n.label == "try")
    handler = next(e for e in graph.edges if e.source == try_node.id and e.label == "except")
    assert graph.nodes[int(handler.target[1:])].label == "catch (e)"
    else_if = next(n for n in graph.nodes if n.label == "if data.age > 18 || data.admin")
    first_if = next(n for n in graph.nodes if n.label == "if !data")
    assert any(
        e.source == first_if.id and e.target == else_if.id and e.label == "false"
        for e in graph.edges
    )


def test_method_with_while_and_do_while() -> None:
    graph = build_graph(SAMPLE_JS, "javascript", "Billing::calculateDiscount", 17)
    assert graph.params == ["price", "code"]
    assert graph.complexity == 3
    loops = [n for n in graph.nodes if n.kind == "loop"]
    assert [n.label for n in loops] == ["while (price > 100)", "do"]


def test_nested_arrow_function_is_opaque() -> None:
    graph = build_graph(SAMPLE_JS, "javascript", "nested", 11)
    assert graph.complexity == 1
    assert [n.kind for n in graph.nodes] == ["start", "process", "return", "end"]


def test_typescript_with_types_and_nullish() -> None:
    graph = build_graph(SAMPLE_TS, "typescript", "score", 1)
    assert graph.params == ["items: number[]", "bonus?: number"]
    assert graph.complexity == 4  # 1 + for + if + ??
    assert [n.kind for n in graph.nodes].count("loop") == 1


def test_tsx_grammar_loads() -> None:
    source = (
        b"const View = (p: {ok: boolean}) => { if (p.ok) { return <b>yes</b>; } return null; };\n"
    )
    graph = build_graph(source, "tsx", "View", 1)
    assert graph.complexity == 2


def test_switch_without_default_gets_a_synthetic_default_branch() -> None:
    source = b"function f(k){ switch(k){ case 1: return 1; } return 0; }\n"
    graph = build_graph(source, "javascript", "f", 1)
    switch = next(n for n in graph.nodes if n.kind == "decision")
    assert sorted(e.label for e in graph.edges if e.source == switch.id) == ["case 1", "default"]


def test_broken_function_is_refused_but_others_still_parse() -> None:
    # The fixture ends with a syntax error; functions before it are intact.
    assert build_graph(SAMPLE_JS, "javascript", "nested", 11).complexity == 1
    with pytest.raises(FunctionNotFound):
        build_graph(SAMPLE_JS, "javascript", "broken", 25)
    with pytest.raises(ParseFailed):
        build_graph(b"function f(a) { if (a { return 1; } }\n", "javascript", "f", 1)
