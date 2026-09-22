"""Python flow graphs: hand-counted nodes, edges and complexity; hostile source refused."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.workflow.ast.errors import FunctionNotFound, ParseFailed, TooDeep
from app.workflow.ast.extract import MAX_DEPTH, MAX_NODES, build_graph

SAMPLE = (Path(__file__).parent / "fixtures" / "ast" / "sample.py").read_bytes()


def _kinds(graph: object) -> list[str]:
    return [node.kind for node in graph.nodes]  # type: ignore[attr-defined]


def test_method_with_every_construct() -> None:
    graph = build_graph(SAMPLE, "python", "Account::check", 5)
    assert graph.name == "check" and graph.line == 5
    assert graph.params == ["self", "age", "name=None"]
    # 1 + if + elif + and + for + except + while + ternary = 8 (our count;
    # Lizard says 9 because it also counts `finally`)
    assert graph.complexity == 8
    kinds = _kinds(graph)
    assert kinds.count("decision") == 3  # if, elif, try
    assert kinds.count("loop") == 2
    assert kinds.count("return") == 2 and kinds.count("throw") == 1
    assert kinds[0] == "start" and kinds[-1] == "end"
    labels = {node.id: node.label for node in graph.nodes}
    edge_set = {(e.source, e.target, e.label) for e in graph.edges}
    if_node = next(n.id for n in graph.nodes if n.label == "if age >= 18 and name")
    elif_node = next(n.id for n in graph.nodes if n.label == "elif age < 0")
    assert (if_node, elif_node, "false") in edge_set
    loop = next(n.id for n in graph.nodes if n.label == "for i in range(age)")
    body = next(n.id for n in graph.nodes if n.label == "total += i")
    assert (loop, body, "true") in edge_set and (body, loop, "loop") in edge_set
    end = graph.nodes[-1].id
    assert sum(1 for e in graph.edges if e.target == end) == 3  # 2 returns, 1 raise
    assert "elif age < 0" in labels.values() and list(labels.values()).count("elif age < 0") == 1


def test_plain_function_collapses_into_one_process_box() -> None:
    graph = build_graph(SAMPLE, "python", "plain", 25)
    assert graph.complexity == 1
    assert _kinds(graph) == ["start", "process", "return", "end"]
    process = graph.nodes[1]
    assert process.label == "y = x + 1 …" and process.line == 26


def test_nested_function_is_opaque_and_not_counted() -> None:
    graph = build_graph(SAMPLE, "python", "nested", 31)
    assert graph.complexity == 1
    assert _kinds(graph) == ["start", "process", "return", "end"]


def test_match_statement_is_a_decision_with_a_branch_per_case() -> None:
    graph = build_graph(SAMPLE, "python", "matcher", 40)
    assert graph.complexity == 4  # 1 + three case clauses
    decision = next(n for n in graph.nodes if n.kind == "decision")
    assert decision.label == "match cmd"
    branches = sorted(e.label for e in graph.edges if e.source == decision.id)
    assert branches == ['case "go"', 'case "stop"', "case _"]
    assert not any(e.label == "default" for e in graph.edges)  # `case _` IS the default


def test_line_disambiguates_same_name() -> None:
    source = b"def f():\n    return 1\n\n\ndef f():\n    if 1:\n        return 2\n    return 3\n"
    first = build_graph(source, "python", "f", 1)
    second = build_graph(source, "python", "f", 5)
    assert first.complexity == 1 and second.complexity == 2
    assert build_graph(source, "python", "f", None).line == 1


def test_missing_function_and_syntax_error_are_typed() -> None:
    with pytest.raises(FunctionNotFound):
        build_graph(SAMPLE, "python", "ghost", 1)
    broken = b"def f(x):\n    if x\n        return 1\n"
    with pytest.raises(ParseFailed):
        build_graph(broken, "python", "f", 1)


def _nested(depth: int) -> bytes:
    lines = ["def deep(x):"]
    for level in range(depth):
        lines.append("    " * (level + 1) + "if x:")
    lines.append("    " * (depth + 1) + "return 1")
    return "\n".join(lines).encode()


def test_nesting_cap_is_exact() -> None:
    assert build_graph(_nested(MAX_DEPTH - 1), "python", "deep", 1).complexity == MAX_DEPTH
    with pytest.raises(TooDeep):
        build_graph(_nested(MAX_DEPTH), "python", "deep", 1)
    with pytest.raises(TooDeep):
        build_graph(_nested(MAX_DEPTH + 5), "python", "deep", 1)


def _wide(blocks: int) -> bytes:
    body = "".join(f"    if x > {i}:\n        x -= 1\n" for i in range(blocks))
    return f"def wide(x):\n{body}    return x\n".encode()


def test_node_cap_is_exact() -> None:
    # start + 2 nodes per block + return + end: 198 blocks → 399 nodes, 199 → over the cap.
    graph = build_graph(_wide((MAX_NODES - 3) // 2), "python", "wide", 1)
    assert len(graph.nodes) == MAX_NODES - 1
    with pytest.raises(TooDeep):
        build_graph(_wide((MAX_NODES - 3) // 2 + 1), "python", "wide", 1)


def test_every_node_is_reachable_and_loop_exits_are_labelled() -> None:
    graph = build_graph(SAMPLE, "python", "Account::check", 5)
    incoming = {edge.target for edge in graph.edges}
    assert all(node.id in incoming for node in graph.nodes[1:])
    edge_set = {(e.source, e.target, e.label) for e in graph.edges}
    by_label = {node.label: node.id for node in graph.nodes}
    assert (by_label["for i in range(age)"], by_label["try"], "false") in edge_set
    assert (
        by_label["while total > 0"],
        by_label["return value if value else total"],
        "false",
    ) in edge_set
    # finally runs after the try body AND after the handler.
    finally_node = by_label["print(value)"]
    sources = {e.source for e in graph.edges if e.target == finally_node}
    assert sources == {by_label["value = int(name)"], by_label["value = 0"]}
    assert graph.nodes[0].label == "check"  # the start pill carries the bare name


def test_graph_is_deterministic() -> None:
    first = build_graph(SAMPLE, "python", "Account::check", 5)
    second = build_graph(SAMPLE, "python", "Account::check", 5)
    assert first == second


def test_output_is_identical_across_processes_and_hash_seeds() -> None:
    """Graph, Mermaid and layout must not depend on set/dict ordering of the process."""
    script = (
        "import hashlib, json, sys\n"
        "from app.workflow.ast.extract import build_graph, graph_as_dict\n"
        "from app.workflow.diagrams import layout, layout_as_dict, to_mermaid\n"
        "graph = build_graph(sys.stdin.buffer.read(), 'python', 'Account::check', 5)\n"
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
    "while": "def f(x):\n"
    + "".join(f"    while x > {i}:\n        x -= 1\n" for i in range(150))
    + "    return x\n",
    "except": "def f(x):\n    try:\n        pass\n"
    + "".join(f"    except E{i}:\n        pass\n" for i in range(150))
    + "    return x\n",
    "if": "def f(x):\n"
    + "".join(f"    if x > {i}:\n        x -= 1\n" for i in range(120))
    + "    return x\n",
}


@pytest.mark.parametrize("shape", sorted(LARGE_SHAPES))
def test_large_functions_do_not_crash_the_process(shape: str) -> None:
    """py-tree-sitter 0.26.0 corrupted the heap (SIGSEGV) on these ordinary shapes.

    The graph is built in a child interpreter so a binding regression shows up
    as a failed assertion on the exit code, never as a dead test runner. Keep
    this test when lifting the ``tree-sitter<0.26`` pin in pyproject.toml.
    """
    script = (
        "import sys\n"
        "from app.workflow.ast.extract import build_graph\n"
        "graph = build_graph(sys.stdin.buffer.read(), 'python', 'f', 1)\n"
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
        nodes, complexity = (int(v) for v in result.stdout.split())
        assert nodes > 100 and complexity > 100
