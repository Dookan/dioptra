"""Mermaid text and layout: deterministic, escaped, every node placed."""

from __future__ import annotations

import re

from app.workflow.ast.extract import build_graph
from app.workflow.ast.graph import FlowEdge, FlowGraph, FlowNode
from app.workflow.diagrams import (
    COLUMN_GAP,
    DIAMOND_KINDS,
    DIAMOND_OVERHANG,
    MARGIN,
    NODE_WIDTH,
    PlacedEdge,
    PlacedNode,
    edge_label_position,
    label_lines,
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

    def drawn_right(node: PlacedNode) -> int:
        # A diamond is drawn past its box; the edge meets what is drawn.
        return node.x + node.width + (DIAMOND_OVERHANG if node.kind in DIAMOND_KINDS else 0)

    assert back.points[0] == (drawn_right(source_node), source_node.y + source_node.height // 2)
    assert back.points[-1] == (drawn_right(target_node), target_node.y + target_node.height // 2)
    assert target_node.kind == "loop"  # so the overhang branch is the one exercised
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


def test_labels_wrap_by_word_and_are_cut_only_when_the_shape_is_full() -> None:
    assert label_lines("if not isinstance(edad, int)", "decision") == [
        "if not",
        "isinstance(edad, int)",
    ]
    assert label_lines("return 1", "return") == ["return 1"]
    # A word longer than a line is cut, never left to run out of the shape.
    assert label_lines("x" * 35, "process") == ["x" * 30, "x" * 5]
    # A diamond holds two lines; the rest is an ellipsis, the full text stays in `label`.
    assert label_lines("a " * 30, "decision") == ["a " * 10 + "a", "a " * 10 + "a…"]
    assert label_lines("", "process") == []


def test_every_placed_node_carries_its_wrapped_lines() -> None:
    source = b"def f(a):\n    if not isinstance(a, int):\n        return 1\n    return 0\n"
    placed = layout(build_graph(source, "python", "f", 1))
    for node in placed.nodes:
        assert node.lines == label_lines(node.label, node.kind)
        assert all(len(line) <= 30 for line in node.lines)
    assert "lines" in layout_as_dict(placed)["nodes"][0]


def test_the_two_branches_of_a_decision_never_share_a_label_position() -> None:
    source = (
        b"def f(a):\n    if a:\n        return 1\n    if a > 2:\n        return 2\n    return 0\n"
    )
    placed = layout(build_graph(source, "python", "f", 1))
    for node in placed.nodes:
        if node.kind != "decision":
            continue
        branches = [e for e in placed.edges if e.source == node.id and e.label]
        positions = {edge_label_position(e)[:2] for e in branches}
        assert len(branches) == 2 and len(positions) == 2


# --- Pinned by the precommit coverage adversary (2026-09-24): each test below
# kills a mutant the suite above let through.

BRANCHES = (
    b"def f(a):\n    if a:\n        return 1\n    if a > 2:\n        return 2\n    return 0\n"
)
LOOP = b"def g(a):\n    while a > 0:\n        a -= 1\n    return a\n"
NESTED = b"def h(a):\n    for x in a:\n        if x:\n            a.pop()\n    return a\n"


def _placed(source: bytes, name: str) -> tuple[dict[str, PlacedNode], list[PlacedEdge]]:
    placed = layout(build_graph(source, "python", name, 1))
    return {node.id: node for node in placed.nodes}, placed.edges


def test_a_turning_branch_is_labelled_above_its_own_run_and_a_straight_one_beside_it() -> None:
    _, edges = _placed(BRANCHES, "f")
    turning = [e for e in edges if e.label and not e.back and len(e.points) >= 3]
    straight = [e for e in edges if e.label and not e.back and len(e.points) == 2]
    assert turning and straight
    for edge in turning:
        (x1, y1), (x2, _) = edge.points[1], edge.points[2]
        assert edge_label_position(edge) == ((x1 + x2) / 2, y1 - 5, "middle")
    for edge in straight:
        (x0, y0), (x1, y1) = edge.points
        assert edge_label_position(edge) == ((x0 + x1) / 2 + 6, (y0 + y1) / 2 - 4, "start")


def test_a_back_edge_is_labelled_beside_its_first_segment() -> None:
    _, edges = _placed(LOOP, "g")
    back = [e for e in edges if e.back]
    assert back
    for edge in back:
        (x0, y0), (x1, y1) = edge.points[0], edge.points[1]
        assert edge_label_position(edge)[2] == "start"
        assert edge_label_position(edge)[:2] == ((x0 + x1) / 2 + 6, (y0 + y1) / 2 - 4)


def test_a_back_edge_re_enters_a_loop_past_its_twenty_pixel_overhang() -> None:
    nodes, edges = _placed(LOOP, "g")
    (back,) = [e for e in edges if e.back]
    loop = nodes[back.target]
    assert loop.kind == "loop"
    # Literal 20 on purpose: computing it from DIAMOND_OVERHANG would pass
    # whatever the constant, and whatever DIAMOND_KINDS holds.
    assert back.points[-1][0] == loop.x + loop.width + 20


def test_a_back_edge_leaving_a_decision_runs_outside_the_shape_not_its_overhang() -> None:
    nodes, edges = _placed(NESTED, "h")
    back = [e for e in edges if e.back]
    assert back
    for edge in back:
        source = nodes[edge.source]
        assert edge.points[1][0] == source.x + source.width + COLUMN_GAP // 2
    assert any(nodes[e.source].kind == "decision" for e in back)


def test_a_label_that_exactly_fills_a_line_is_not_wrapped() -> None:
    label = "ab " + "c" * 19  # 22 characters: a decision line holds exactly that
    assert label_lines(label, "decision") == [label]
