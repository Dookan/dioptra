"""Flow graph → Mermaid text, and flow graph → a deterministic layered layout.

Mermaid text is the interchange and editing format the plan names (day 14).
The picture the UI draws — and the SVG the P5 annex will embed — comes from
``layout()``: the same graph always gives the same coordinates, and the
renderer needs only class names, never an inline style (the app ships under
``style-src 'self'``; see tasks/phase3-survey.md §7).

Labels are hostile (they are the audited source). Mermaid gets them inside
quoted strings with its own entity escapes; the layout ships them as plain
data for the renderer to escape.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.workflow.ast.graph import FlowGraph

# Sized for a label of up to three lines (two in a diamond, whose usable
# width narrows away from its centre). At 190×46 a 60-character label ran
# out of its shape on one line (`mmarin`, 2026-09-24); the screen and the
# report annex now wrap it inside these bounds.
NODE_WIDTH = 220
NODE_HEIGHT = 60
COLUMN_GAP = 60
ROW_GAP = 60
MARGIN = 30
#: A decision is drawn wider than its box, by this much on each side: a diamond
#: loses width away from its centre, and at the box's own width a two-line
#: condition did not fit. The column gap and the margin leave room for it.
DIAMOND_OVERHANG = 20
DIAMOND_KINDS = frozenset({"decision", "loop"})

#: Characters per line and lines per shape, measured for the screen's 11px
#: monospace (~6.6px a character, the widest face either renderer uses; the
#: report's sans-serif is narrower, so what fits here fits there).
_FIT: dict[str, tuple[int, int]] = {
    "decision": (22, 2),
    "loop": (22, 2),
    "return": (27, 3),
    "throw": (27, 3),
}
_FIT_DEFAULT = (30, 3)

_SHAPES: dict[str, tuple[str, str]] = {
    "start": ("([", "])"),
    "end": ("([", "])"),
    "process": ("[", "]"),
    "decision": ("{", "}"),
    "loop": ("{{", "}}"),
    "return": ("[/", "/]"),
    "throw": ("[\\", "\\]"),
}


def mermaid_escape(text: str) -> str:
    """Safe inside a double-quoted Mermaid label: entities for what could break out."""
    out = []
    for char in text:
        code = ord(char)
        if char == '"':
            out.append("#quot;")
        elif char == "#":
            out.append("#35;")
        elif char in "<>{}[]()|`\\":
            out.append(f"#{code};")
        elif code < 32 or code == 127:
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def to_mermaid(graph: FlowGraph) -> str:
    """Deterministic ``flowchart TD`` text: nodes in id order, then edges in order."""
    lines = ["flowchart TD"]
    for node in graph.nodes:
        open_shape, close_shape = _SHAPES.get(node.kind, ("[", "]"))
        label = node.label or ("Start" if node.kind == "start" else "End")
        lines.append(f'    {node.id}{open_shape}"{mermaid_escape(label)}"{close_shape}')
    for edge in graph.edges:
        if edge.label:
            lines.append(f'    {edge.source} -->|"{mermaid_escape(edge.label)}"| {edge.target}')
        else:
            lines.append(f"    {edge.source} --> {edge.target}")
    return "\n".join(lines) + "\n"


def label_lines(label: str, kind: str) -> list[str]:
    """The label broken into the lines its shape can hold, ``…`` when it cannot.

    Deterministic, word-wise, and a word longer than a line is cut rather than
    left to run out of the shape. The full label stays in ``label`` (the screen
    shows it on hover) and in the Mermaid text.
    """
    per_line, max_lines = _FIT.get(kind, _FIT_DEFAULT)
    lines: list[str] = []
    current = ""
    for word in label.split():
        rest = word
        while rest:
            joined = f"{current} {rest}" if current else rest
            if len(joined) <= per_line:
                current, rest = joined, ""
            elif current:
                lines.append(current)
                current = ""
            else:
                lines.append(rest[:per_line])
                rest = rest[per_line:]
    if current:
        lines.append(current)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][: per_line - 1].rstrip() + "…"
    return lines


@dataclass(frozen=True)
class PlacedNode:
    id: str
    kind: str
    label: str
    line: int | None
    x: int
    y: int
    width: int
    height: int
    #: ``label`` wrapped to fit the shape (``label_lines``); what both renderers draw.
    lines: list[str]


@dataclass(frozen=True)
class PlacedEdge:
    source: str
    target: str
    label: str
    #: Polyline points from the source's bottom centre to the target's top centre
    #: (a back edge — loop — leaves from the side and re-enters from the side).
    points: list[tuple[int, int]]
    back: bool


@dataclass(frozen=True)
class Layout:
    width: int
    height: int
    nodes: list[PlacedNode]
    edges: list[PlacedEdge]


def _rows(graph: FlowGraph) -> dict[str, int]:
    """Longest-path depth from the start over forward edges; back edges ignored."""
    forward: dict[str, list[str]] = {node.id: [] for node in graph.nodes}
    order = {node.id: index for index, node in enumerate(graph.nodes)}
    for edge in graph.edges:
        # An edge to an earlier-created node is a loop back edge: it never lengthens a path.
        if order[edge.target] > order[edge.source]:
            forward[edge.source].append(edge.target)
    depth = dict.fromkeys(forward, 0)
    # Node creation order is a topological order of the forward edges (the
    # builder creates a node before anything that flows out of it).
    for node in graph.nodes:
        for target in forward[node.id]:
            depth[target] = max(depth[target], depth[node.id] + 1)
    # The end node sits below everything.
    if graph.nodes:
        last = graph.nodes[-1].id
        depth[last] = max(depth.values()) if len(graph.nodes) > 1 else 0
        if any(value == depth[last] for key, value in depth.items() if key != last):
            depth[last] += 1
    return depth


def edge_label_position(edge: PlacedEdge) -> tuple[float, float, str]:
    """Where an edge's label goes: ``(x, y, text-anchor)``.

    Both branches of a decision leave from the same point, so a label placed
    on the first segment drew "sí" and "no" on top of each other (2026-09-24).
    A branch that turns sideways carries its label on its OWN horizontal run,
    so the two sides of one decision can never meet.
    """
    (x0, y0) = edge.points[0]
    if not edge.back and len(edge.points) >= 3:
        (x1, y1), (x2, _) = edge.points[1], edge.points[2]
        if x2 != x1:
            return ((x1 + x2) / 2, y1 - 5, "middle")
    (x1, y1) = edge.points[1] if len(edge.points) > 1 else (x0, y0)
    return ((x0 + x1) / 2 + 6, (y0 + y1) / 2 - 4, "start")


def _right_edge(node: PlacedNode) -> int:
    overhang = DIAMOND_OVERHANG if node.kind in DIAMOND_KINDS else 0
    return node.x + node.width + overhang


def layout(graph: FlowGraph) -> Layout:
    depth = _rows(graph)
    by_row: dict[int, list[str]] = {}
    for node in graph.nodes:  # creation order keeps siblings in source order
        by_row.setdefault(depth[node.id], []).append(node.id)
    widest = max((len(ids) for ids in by_row.values()), default=1)
    total_width = MARGIN * 2 + widest * NODE_WIDTH + (widest - 1) * COLUMN_GAP
    placed: dict[str, PlacedNode] = {}
    for node in graph.nodes:
        row = depth[node.id]
        siblings = by_row[row]
        column = siblings.index(node.id)
        row_width = len(siblings) * NODE_WIDTH + (len(siblings) - 1) * COLUMN_GAP
        x = (total_width - row_width) // 2 + column * (NODE_WIDTH + COLUMN_GAP)
        y = MARGIN + row * (NODE_HEIGHT + ROW_GAP)
        placed[node.id] = PlacedNode(
            id=node.id,
            kind=node.kind,
            label=node.label,
            line=node.line,
            x=x,
            y=y,
            width=NODE_WIDTH,
            height=NODE_HEIGHT,
            lines=label_lines(node.label, node.kind),
        )
    edges: list[PlacedEdge] = []
    for edge in graph.edges:
        source, target = placed[edge.source], placed[edge.target]
        back = depth[edge.target] <= depth[edge.source]
        if back:
            # Leave and re-enter at the drawn edge of the shape, past a diamond's overhang.
            side = _right_edge(source)
            outside = source.x + source.width + COLUMN_GAP // 2
            points = [
                (side, source.y + source.height // 2),
                (outside, source.y + source.height // 2),
                (outside, target.y + target.height // 2),
                (_right_edge(target), target.y + target.height // 2),
            ]
        else:
            start = (source.x + source.width // 2, source.y + source.height)
            end = (target.x + target.width // 2, target.y)
            middle_y = start[1] + ROW_GAP // 2
            points = (
                [start, end]
                if start[0] == end[0]
                else [start, (start[0], middle_y), (end[0], middle_y), end]
            )
        edges.append(
            PlacedEdge(
                source=edge.source, target=edge.target, label=edge.label, points=points, back=back
            )
        )
    height = MARGIN * 2 + (max(depth.values(), default=0) + 1) * (NODE_HEIGHT + ROW_GAP) - ROW_GAP
    return Layout(width=total_width, height=height, nodes=list(placed.values()), edges=edges)


def layout_as_dict(placed: Layout) -> dict[str, Any]:
    return {
        "width": placed.width,
        "height": placed.height,
        "nodes": [asdict(node) for node in placed.nodes],
        "edges": [
            {**asdict(edge), "points": [list(point) for point in edge.points]}
            for edge in placed.edges
        ],
    }
