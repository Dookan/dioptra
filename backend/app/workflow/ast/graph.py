"""The language-independent flow graph every extractor produces.

Node kinds mirror what a developer draws by hand: a start, an end, boxes of
plain statements, diamonds for decisions and loops, and the exits (return,
throw). Labels are DATA taken from the audited source — hostile until
rendered; nothing here escapes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_LABEL_CHARS = 60


@dataclass(frozen=True)
class FlowNode:
    id: str
    #: start | end | process | decision | loop | return | throw
    kind: str
    label: str
    line: int | None


@dataclass(frozen=True)
class FlowEdge:
    source: str
    target: str
    #: "" | true | false | loop | except | done
    label: str = ""


@dataclass
class FlowGraph:
    name: str
    language: str
    line: int
    params: list[str]
    complexity: int
    nodes: list[FlowNode] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)


def clip(text: str) -> str:
    """One line, bounded: labels come from source code the developer wrote."""
    flat = " ".join(text.split())
    return flat if len(flat) <= MAX_LABEL_CHARS else flat[: MAX_LABEL_CHARS - 1] + "…"
