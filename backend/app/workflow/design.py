"""Stage E5 (day 14): the flow diagram of one planned function.

The graph is computed from the source every time — deterministic, never
stored. What is stored is the developer's own Mermaid text, as text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit import service as audit
from app.auth.models import User
from app.workflow.ast.errors import FunctionNotInPlan
from app.workflow.ast.extract import build_graph, graph_as_dict
from app.workflow.ast.graph import FlowGraph
from app.workflow.ast.source import language_for, load_source
from app.workflow.diagrams import layout, layout_as_dict, to_mermaid
from app.workflow.errors import StageLocked, StageNotReached
from app.workflow.models import CaseDesign
from app.workflow.triage import strip_control_chars

MAX_DIAGRAM_TEXT_CHARS = 20_000


@dataclass(frozen=True)
class FunctionRef:
    path: str
    function: str
    line: int | None


def planned_function(analysis: Analysis, ref: FunctionRef) -> dict[str, Any]:
    """The plan's row for ``ref``; diagrams exist only for what E4 chose."""
    plan = analysis.test_plan
    rows = plan.functions if plan is not None else []
    for row in rows:
        if (
            str(row.get("path")) == ref.path
            and str(row.get("function")) == ref.function
            and row.get("line") == ref.line
        ):
            return row
    raise FunctionNotInPlan(f"{ref.path}:{ref.line} {ref.function}"[:200])


def flow_graph(analysis: Analysis, ref: FunctionRef) -> FlowGraph:
    planned_function(analysis, ref)
    language = language_for(ref.path)
    source = load_source(analysis, ref.path)
    return build_graph(source, language, ref.function, ref.line)


def get_design(db: Session, analysis: Analysis, ref: FunctionRef) -> CaseDesign | None:
    statement = select(CaseDesign).where(
        CaseDesign.analysis_id == analysis.id,
        CaseDesign.path == ref.path,
        CaseDesign.function == ref.function,
        CaseDesign.line == ref.line,
    )
    return db.scalars(statement).first()


def diagram_payload(db: Session, analysis: Analysis, ref: FunctionRef) -> dict[str, Any]:
    graph = flow_graph(analysis, ref)
    design = get_design(db, analysis, ref)
    return {
        "path": ref.path,
        "function": ref.function,
        "line": ref.line,
        "language": graph.language,
        "complexity": graph.complexity,
        "mermaid": to_mermaid(graph),
        "graph": graph_as_dict(graph),
        "layout": layout_as_dict(layout(graph)),
        "edited_text": design.diagram_text if design is not None else None,
        "edited_by_username": design.created_by_username if design is not None else None,
        "edited_at": design.updated_at if design is not None else None,
    }


def save_diagram_text(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    ref: FunctionRef,
    text: str,
    source_ip: str | None,
) -> CaseDesign:
    """Store the developer's Mermaid text (only AT E5; empty text clears it)."""
    if analysis.stage is Stage.DESIGN:
        pass
    elif analysis.stage in (Stage.REGISTER, Stage.CODE, Stage.ANALYSIS, Stage.PLAN):
        raise StageNotReached(f"analysis {analysis.id} is at {analysis.stage.value}")
    else:
        raise StageLocked(f"analysis {analysis.id} is at {analysis.stage.value}")
    planned_function(analysis, ref)
    cleaned = strip_control_chars(text.replace("\r\n", "\n")).strip()[:MAX_DIAGRAM_TEXT_CHARS]
    design = get_design(db, analysis, ref)
    if design is None:
        design = CaseDesign(
            analysis_id=analysis.id,
            path=ref.path,
            function=ref.function,
            line=ref.line,
            created_by_username=actor.username,
        )
        db.add(design)
    design.diagram_text = cleaned or None
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="design.diagram.edit",
        target=f"analysis:{analysis.id}:{ref.path}:{ref.line}:{ref.function}"[:255],
        source_ip=source_ip,
    )
    db.flush()
    return design
