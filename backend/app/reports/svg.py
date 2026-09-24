"""Flow diagram → inline SVG for the report annex, produced SERVER-SIDE.

The P5 annex embeds the picture the E5 screen draws, but from the same
``diagrams.layout`` the API ships to the browser — never from anything the
browser sends back (docs/threat-model.md → Flow diagrams). Labels are the
audited source and go through ``markupsafe.escape``; styling is presentation
attributes only, so the SVG carries no stylesheet, no script, no reference
to anything outside the document.
"""

from __future__ import annotations

from markupsafe import Markup, escape

from app.reports.strings import report_strings
from app.workflow.diagrams import (
    DIAMOND_KINDS,
    DIAMOND_OVERHANG,
    Layout,
    PlacedEdge,
    PlacedNode,
    edge_label_position,
)

MAX_LABEL_CHARS = 28
#: The builder's own tokens (``true``, ``false``, ``Start`` …) read in the
#: institution's language in the annex, like the UI translates them; source
#: text is never touched. The Mermaid text stays English: it is interchange.
_TOKENS: dict[str, str] = report_strings()["diagram"]
_FILL = {
    "start": "#E7EDE8",
    "end": "#E7EDE8",
    "decision": "#FFF6DD",
    "loop": "#FFF6DD",
    "throw": "#FBE9E7",
    "return": "#F1F4F1",
    "process": "#FFFFFF",
}
_STROKE = {"throw": "#B3261E"}
#: Baseline to baseline of a wrapped label, for an 11px face.
LINE_HEIGHT = 12


def _label(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) > MAX_LABEL_CHARS:
        return collapsed[: MAX_LABEL_CHARS - 1] + "…"
    return collapsed


def _node(node: PlacedNode) -> str:
    x, y, w, h = node.x, node.y, node.width, node.height
    cx, cy = x + w / 2, y + h / 2
    fill = _FILL.get(node.kind, "#FFFFFF")
    stroke = _STROKE.get(node.kind, "#1C2420")
    common = f'fill="{fill}" stroke="{stroke}" stroke-width="1"'
    if node.kind in {"start", "end"}:
        shape = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h / 2}" {common}/>'
    elif node.kind in DIAMOND_KINDS:
        o = DIAMOND_OVERHANG
        points = f"{cx},{y} {x + w + o},{cy} {cx},{y + h} {x - o},{cy}"
        shape = f'<polygon points="{points}" {common}/>'
    elif node.kind in {"return", "throw"}:
        points = f"{x + 10},{y} {x + w},{y} {x + w - 10},{y + h} {x},{y + h}"
        shape = f'<polygon points="{points}" {common}/>'
    else:
        shape = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" {common}/>'
    if node.kind in {"start", "end"}:
        lines = [
            _label(node.label or (_TOKENS["start"] if node.kind == "start" else _TOKENS["end"]))
        ]
    else:
        lines = node.lines or [_label(node.label)]
    # The block of lines is centred on the shape; each line is its own tspan.
    first = cy + 4 - (len(lines) - 1) * LINE_HEIGHT / 2
    spans = "".join(
        f'<tspan x="{cx}" y="{first + index * LINE_HEIGHT}">{escape(line)}</tspan>'
        for index, line in enumerate(lines)
    )
    text = (
        '<text text-anchor="middle" font-family="Liberation Sans, Arial, '
        f'sans-serif" font-size="11" fill="#1C2420">{spans}</text>'
    )
    return shape + text


def _edge(edge: PlacedEdge) -> str:
    path = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}" for i, (x, y) in enumerate(edge.points))
    dash = ' stroke-dasharray="4 3"' if edge.back else ""
    line = (
        f'<path d="{path}" fill="none" stroke="#5C6B62" stroke-width="1.2"{dash} '
        'marker-end="url(#fd-arrow)"/>'
    )
    if not edge.label:
        return line
    lx, ly, anchor = edge_label_position(edge)
    label = escape(_label(_TOKENS.get(edge.label, edge.label)))
    text = (
        f'<text x="{lx}" y="{ly}" text-anchor="{anchor}" font-family="Liberation Sans, '
        f'Arial, sans-serif" font-size="10" fill="#5C6B62">{label}</text>'
    )
    return line + text


def layout_svg(placed: Layout, *, title: str) -> Markup:
    """The whole diagram as one inline ``<svg>``; the result is final markup."""
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {placed.width} {placed.height}" '
        f'width="{placed.width}" height="{placed.height}" role="img" class="flow">',
        f"<title>{escape(_label(title))}</title>",
        '<defs><marker id="fd-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" '
        'orient="auto"><path d="M0 0 L8 4 L0 8z" fill="#5C6B62"/></marker></defs>',
    ]
    parts.extend(_edge(edge) for edge in placed.edges)
    parts.extend(_node(node) for node in placed.nodes)
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 — every dynamic value above went through escape()
