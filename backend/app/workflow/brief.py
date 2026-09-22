"""Stage E5 (day 15): the test brief ("consigna") of one planned function.

Deterministic, computed from the flow graph and the analysis' findings —
never from anything the developer can edit, and never with AI
(docs/workflow-gates.md → Test brief). The same source and the same
findings always produce the same items in the same order with the same ids,
because P4's scaffold and the E7 re-audit refer to items by id.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from decimal import Decimal
from typing import Any

from app.analysis.models import Analysis, ToolCategory
from app.workflow.ast.graph import Comparison, FlowGraph, clip

#: Item kinds and their id prefixes (source order within each kind).
KIND_BRANCH = "branch"
KIND_BOUNDARY = "boundary"
KIND_ERROR = "error"
KIND_MALICIOUS = "malicious"
_PREFIX = {KIND_BRANCH: "R", KIND_BOUNDARY: "F", KIND_ERROR: "E", KIND_MALICIOUS: "M"}

_EQUALITY = frozenset({"==", "!=", "===", "!=="})


@dataclass(frozen=True)
class BriefItem:
    id: str
    kind: str
    line: int | None
    #: Source text (a condition, a comparison, a throw) — hostile, rendered as text.
    text: str
    #: branch: the edge label to take; error: throw / handler / early_return;
    #: malicious: the finding's rule id.
    detail: str
    values: list[str] = field(default_factory=list)
    finding_id: str | None = None


@dataclass(frozen=True)
class Brief:
    function: str
    path: str
    line: int
    language: str
    params: list[str]
    complexity: int
    #: Basis paths plus one case per associated SAST finding.
    min_cases: int
    items: list[BriefItem]


def boundary_values(literal: int | float | str, operator: str) -> list[str]:
    """The three values around a literal comparison (``age >= 18`` → 17, 18, 19).

    Floats step by their last decimal (``0.5`` → 0.4, 0.5, 0.6); a string
    literal under an equality gives the literal and the empty string. The
    extractor never yields a ``bool`` (it parses numbers and strings only), so
    ``True`` would be treated as the integer 1 — give it a branch here if a
    language profile ever maps boolean literals.
    """
    if isinstance(literal, int):
        return [str(literal - 1), str(literal), str(literal + 1)]
    if isinstance(literal, float):
        if math.isnan(literal) or math.isinf(literal):
            return []
        exact = Decimal(repr(literal))
        if exact == exact.to_integral_value():
            return boundary_values(int(exact), operator)
        exponent = exact.as_tuple().exponent
        step = Decimal(1).scaleb(exponent) if isinstance(exponent, int) else Decimal(1)
        return [_fmt(exact - step), _fmt(exact), _fmt(exact + step)]
    if operator in _EQUALITY and literal != "":
        return [clip(literal), ""]
    return [clip(literal)]


def _fmt(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _branch_items(graph: FlowGraph) -> list[BriefItem]:
    items: list[BriefItem] = []
    labels_by_node: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.label and edge.label != "loop" and edge.label != "except":
            labels_by_node.setdefault(edge.source, []).append(edge.label)
    for node in graph.nodes:
        if node.kind not in ("decision", "loop"):
            continue
        for label in labels_by_node.get(node.id, []):
            items.append(
                BriefItem(
                    id="",
                    kind=KIND_BRANCH,
                    line=node.line,
                    text=node.label,
                    detail=label,
                )
            )
    return items


def _boundary_items(comparisons: list[Comparison]) -> list[BriefItem]:
    seen: set[tuple[int, str]] = set()
    items: list[BriefItem] = []
    for comparison in comparisons:
        key = (comparison.line, comparison.text)
        if key in seen:
            continue
        seen.add(key)
        items.append(
            BriefItem(
                id="",
                kind=KIND_BOUNDARY,
                line=comparison.line,
                text=comparison.text,
                detail=comparison.operator,
                values=boundary_values(comparison.literal, comparison.operator),
            )
        )
    return items


def _error_items(graph: FlowGraph) -> list[BriefItem]:
    items: list[BriefItem] = []
    handlers = {edge.target for edge in graph.edges if edge.label == "except"}
    for node in graph.nodes:
        if node.kind == "throw":
            items.append(
                BriefItem(id="", kind=KIND_ERROR, line=node.line, text=node.label, detail="throw")
            )
        elif node.id in handlers:
            items.append(
                BriefItem(id="", kind=KIND_ERROR, line=node.line, text=node.label, detail="handler")
            )
        elif node.kind == "return" and node.line is not None and node.line < graph.end_line:
            items.append(
                BriefItem(
                    id="", kind=KIND_ERROR, line=node.line, text=node.label, detail="early_return"
                )
            )
    return items


def _end_line(graph: FlowGraph) -> int:
    end = graph.nodes[-1] if graph.nodes else None
    return end.line if end is not None and end.line is not None else graph.end_line


def _malicious_items(analysis: Analysis, path: str, graph: FlowGraph) -> list[BriefItem]:
    """One mandatory malicious-input case per SAST finding inside the function."""
    last_line = _end_line(graph)
    items: list[BriefItem] = []
    for finding in analysis.findings:
        if finding.category is not ToolCategory.SAST or not finding.in_report:
            continue
        if finding.path != path or finding.line is None:
            continue
        if not graph.line <= finding.line <= last_line:
            continue
        items.append(
            BriefItem(
                id="",
                kind=KIND_MALICIOUS,
                line=finding.line,
                text=finding.title,
                detail=finding.rule_id,
                values=[f"CWE-{finding.cwe}"] if finding.cwe is not None else [],
                finding_id=str(finding.id),
            )
        )
    return items


def _numbered(items: list[BriefItem]) -> list[BriefItem]:
    counters: dict[str, int] = {}
    out: list[BriefItem] = []
    for item in items:
        counters[item.kind] = counters.get(item.kind, 0) + 1
        out.append(
            BriefItem(
                id=f"{_PREFIX[item.kind]}{counters[item.kind]}",
                kind=item.kind,
                line=item.line,
                text=item.text,
                detail=item.detail,
                values=list(item.values),
                finding_id=item.finding_id,
            )
        )
    return out


def build_brief(analysis: Analysis, path: str, graph: FlowGraph) -> Brief:
    items = _numbered(
        _branch_items(graph)
        + _boundary_items(graph.comparisons)
        + _error_items(graph)
        + _malicious_items(analysis, path, graph)
    )
    malicious = sum(1 for item in items if item.kind == KIND_MALICIOUS)
    return Brief(
        function=graph.name,
        path=path,
        line=graph.line,
        language=graph.language,
        params=list(graph.params),
        complexity=graph.complexity,
        min_cases=graph.complexity + malicious,
        items=items,
    )


def brief_as_dict(brief: Brief) -> dict[str, Any]:
    return asdict(brief)  # recurses into the items
