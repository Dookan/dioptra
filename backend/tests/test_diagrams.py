"""Mermaid text and layout: deterministic, escaped, every node placed."""

from __future__ import annotations

import re

from app.workflow.ast.extract import build_graph
from app.workflow.ast.graph import FlowEdge, FlowGraph, FlowNode
from app.workflow.diagrams import (
    COLUMN_GAP,
    MARGIN,
    NODE_WIDTH,
    layout,
    layout_as_dict,
    mermaid_escape,
    to_mermaid,
)

HOSTILE = 'x"]; click n0 call alert("<script>") #{'


def _hostile_graph() -> FlowGraph:
    return FlowGraph(
        name="f",
        language="javascript",
        line=1,
        params=[],
        complexity=2,
        nodes=[
            FlowNode("n0", "start", "f", 1),
            FlowNode("n1", "decision", HOSTILE, 2),
            FlowNode("n2", "process", "x = 1\nsecond line", 3),
            FlowNode("n3", "end", "", 4),
        ],
        edges=[
            FlowEdge("n0", "n1"),
            FlowEdge("n1", "n2", "true"),
            FlowEdge("n1", "n3", HOSTILE),
            FlowEdge("n2", "n1", "loop"),
            FlowEdge("n2", "n3"),
        ],
    )


def test_mermaid_escapes_every_breakout_character() -> None:
    text = to_mermaid(_hostile_graph())
    assert HOSTILE not in text
    assert '"' not in mermaid_escape(HOSTILE)
    escaped = mermaid_escape(HOSTILE)
    for char in "<>{}[]()|`\\":
        assert char not in escaped
    # '#' survives only as an entity prefix (`#35;` for a literal hash).
    assert "#35;" in escaped
    assert re.fullmatch(r"(?:[^#]|#(?:quot|\d+);)*", escaped)
    assert "\n" not in mermaid_escape("a\nb") and "\x00" not in mermaid_escape("a\x00b")
    assert text.startswith("flowchart TD\n")
    assert '    n1{"x#quot;#93;; click n0 call alert' in text
    assert '    n1 -->|"true"| n2' in text and "    n0 --> n1" in text
    assert text.endswith("\n")


def test_mermaid_shapes_follow_the_kind() -> None:
    text = to_mermaid(_hostile_graph())
    assert '    n0(["f"])' in text and '    n3(["End"])' in text


def test_layout_places_every_node_and_references_existing_ones() -> None:
    graph = _hostile_graph()
    placed = layout(graph)
    ids = {node.id for node in placed.nodes}
    assert ids == {node.id for node in graph.nodes}
    assert all(node.x >= 0 and node.y >= 0 for node in placed.nodes)
    assert placed.width > 0 and placed.height > 0
    assert all(node.x + node.width <= placed.width for node in placed.nodes)
    assert all(node.y + node.height <= placed.height for node in placed.nodes)
    for edge in placed.edges:
        assert edge.source in ids and edge.target in ids
        assert len(edge.points) >= 2
    back = next(edge for edge in placed.edges if edge.label == "loop")
    assert back.back is True
    forward = next(edge for edge in placed.edges if edge.source == "n0")
    assert forward.back is False
    # Labels are shipped as data, unescaped: the renderer escapes.
    assert next(node for node in placed.nodes if node.id == "n1").label == HOSTILE
    rows = sorted({node.y for node in placed.nodes})
    assert rows[0] == next(node.y for node in placed.nodes if node.kind == "start")
    assert rows[-1] == next(node.y for node in placed.nodes if node.kind == "end")


def test_end_node_sits_alone_on_the_last_row() -> None:
    graph = build_graph(b"def f(x):\n    while x:\n        x -= 1\n", "python", "f", 1)
    placed = layout(graph)
    end = next(node for node in placed.nodes if node.kind == "end")
    assert all(node.y < end.y for node in placed.nodes if node.kind != "end")


def test_rows_are_centred_and_back_edges_leave_from_the_side() -> None:
    source = (
        b"def f(a):\n    if a:\n        return 1\n    for x in a:\n        a -= 1\n    return 0\n"
    )
    placed = layout(build_graph(source, "python", "f", 1))
    by_id = {node.id: node for node in placed.nodes}
    rows: dict[int, list[str]] = {}
    for node in placed.nodes:
        rows.setdefault(node.y, []).append(node.id)
    for ids in rows.values():
        if len(ids) == 1:
            assert by_id[ids[0]].x == (placed.width - NODE_WIDTH) // 2
        else:
            assert {by_id[i].x for i in ids} == {MARGIN, MARGIN + NODE_WIDTH + COLUMN_GAP}
    back = next(edge for edge in placed.edges if edge.back)
    source_node, target_node = by_id[back.source], by_id[back.target]
    assert back.points[0] == (
        source_node.x + source_node.width,
        source_node.y + source_node.height // 2,
    )
    assert back.points[-1] == (
        target_node.x + target_node.width,
        target_node.y + target_node.height // 2,
    )
    forward = next(edge for edge in placed.edges if not edge.back)
    target = by_id[forward.target]
    assert forward.points[-1] == (target.x + target.width // 2, target.y)


def test_layout_and_text_are_deterministic_for_real_source() -> None:
    source = (
        b"def f(a):\n    if a:\n        return 1\n    for x in a:\n        a -= 1\n    return 0\n"
    )
    first = build_graph(source, "python", "f", 1)
    second = build_graph(source, "python", "f", 1)
    assert to_mermaid(first) == to_mermaid(second)
    assert layout_as_dict(layout(first)) == layout_as_dict(layout(second))
    dumped = layout_as_dict(layout(first))
    assert set(dumped) == {"width", "height", "nodes", "edges"}
    assert dumped["edges"][0]["points"][0] == [
        dumped["nodes"][0]["x"] + dumped["nodes"][0]["width"] // 2,
        dumped["nodes"][0]["y"] + dumped["nodes"][0]["height"],
    ]
