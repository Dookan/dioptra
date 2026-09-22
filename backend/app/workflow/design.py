"""Stage E5: the flow diagram (day 14), the brief and the cases (day 15) of one planned function.

The graph and the brief are computed from the source every time —
deterministic, never stored until approval snapshots the brief. What is
stored is the developer's own work: the Mermaid text, the cases in their
words and which brief items each case declares to cover.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit import service as audit
from app.auth.models import User
from app.core.clock import utc_now
from app.workflow.ast.errors import FunctionNotInPlan
from app.workflow.ast.extract import build_graph, graph_as_dict
from app.workflow.ast.graph import FlowGraph
from app.workflow.ast.source import language_for, load_source
from app.workflow.brief import Brief, brief_as_dict, build_brief
from app.workflow.diagrams import layout, layout_as_dict, to_mermaid
from app.workflow.errors import (
    BriefNotCovered,
    CaseItemUnknown,
    CasesInvalid,
    CasesTooFew,
    StageLocked,
    StageNotReached,
)
from app.workflow.models import MAX_CASES, CaseDesign
from app.workflow.triage import strip_control_chars

MAX_DIAGRAM_TEXT_CHARS = 20_000
MIN_CASE_TITLE_CHARS = 3
MAX_CASE_TITLE_CHARS = 500


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


def brief_for(analysis: Analysis, ref: FunctionRef) -> Brief:
    return build_brief(analysis, ref.path, flow_graph(analysis, ref))


def brief_payload(db: Session, analysis: Analysis, ref: FunctionRef) -> dict[str, Any]:
    """The live brief plus what the developer has written and whether it is approved."""
    brief = brief_for(analysis, ref)
    design = get_design(db, analysis, ref)
    return {
        "brief": brief_as_dict(brief),
        "cases": list(design.cases) if design is not None else [],
        "approved_at": design.approved_at if design is not None else None,
        "approved_by_username": design.approved_by_username if design is not None else None,
    }


def design_states(analysis: Analysis) -> list[dict[str, Any]]:
    """Per planned function: how many cases and whether they are approved — no parsing.

    The screen uses it to show the gate's state (every function approved);
    the gate itself is ``gates.leave_design`` over the same rows.
    """
    plan = analysis.test_plan
    rows = plan.functions if plan is not None else []
    by_key = {(d.path, d.function, d.line): d for d in analysis.case_designs}
    states: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row.get("path")), str(row.get("function")), row.get("line"))
        design = by_key.get(key)
        states.append(
            {
                "path": key[0],
                "function": key[1],
                "line": key[2],
                "cases": len(design.cases) if design is not None else 0,
                "approved_at": design.approved_at if design is not None else None,
                "approved_by_username": design.approved_by_username if design is not None else None,
            }
        )
    return states


def _require_design_stage(analysis: Analysis) -> None:
    """E5 deliverables are written only AT E5: before it, not reached; after it, locked."""
    if analysis.stage is Stage.DESIGN:
        return
    if analysis.stage in (Stage.REGISTER, Stage.CODE, Stage.ANALYSIS, Stage.PLAN):
        raise StageNotReached(f"analysis {analysis.id} is at {analysis.stage.value}")
    raise StageLocked(f"analysis {analysis.id} is at {analysis.stage.value}")


def _design_row(db: Session, analysis: Analysis, actor: User, ref: FunctionRef) -> CaseDesign:
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
    return design


def _audit(
    db: Session, actor: User, action: str, analysis: Analysis, ref: FunctionRef, ip: str | None
) -> None:
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action=action,
        target=f"analysis:{analysis.id}:{ref.path}:{ref.line}:{ref.function}"[:255],
        source_ip=ip,
    )


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
    _require_design_stage(analysis)
    planned_function(analysis, ref)
    cleaned = strip_control_chars(text.replace("\r\n", "\n")).strip()[:MAX_DIAGRAM_TEXT_CHARS]
    design = _design_row(db, analysis, actor, ref)
    design.diagram_text = cleaned or None
    _audit(db, actor, "design.diagram.edit", analysis, ref, source_ip)
    db.flush()
    return design


def clean_cases(raw: list[dict[str, Any]], brief: Brief) -> list[dict[str, Any]]:
    """Normalize the cases: titles as bounded text, ``covers`` restricted to the brief's ids."""
    if len(raw) > MAX_CASES:
        raise CasesInvalid(f"more than {MAX_CASES} cases")
    known = {item.id for item in brief.items}
    cleaned: list[dict[str, Any]] = []
    for case in raw:
        title = " ".join(strip_control_chars(str(case.get("title", ""))).split())
        if not MIN_CASE_TITLE_CHARS <= len(title) <= MAX_CASE_TITLE_CHARS:
            raise CasesInvalid("case title length")
        covers: list[str] = []
        for item_id in case.get("covers") or []:
            if not isinstance(item_id, str) or item_id not in known:
                raise CaseItemUnknown(str(item_id)[:40])
            if item_id not in covers:
                covers.append(item_id)
        cleaned.append({"title": title, "covers": covers})
    return cleaned


def save_cases(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    ref: FunctionRef,
    cases: list[dict[str, Any]],
    source_ip: str | None,
) -> CaseDesign:
    """Store the developer's cases (only AT E5).

    Any earlier approval is cleared: it attested a different text.
    """
    _require_design_stage(analysis)
    brief = brief_for(analysis, ref)
    cleaned = clean_cases(cases, brief)
    design = _design_row(db, analysis, actor, ref)
    design.cases = cleaned
    design.brief = None
    design.approved_at = None
    design.approved_by_username = None
    _audit(db, actor, "design.cases.save", analysis, ref, source_ip)
    db.flush()
    return design


def uncovered_items(brief: Brief, cases: list[dict[str, Any]]) -> list[str]:
    covered = {item_id for case in cases for item_id in case.get("covers") or []}
    return [item.id for item in brief.items if item.id not in covered]


def approve_cases(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    ref: FunctionRef,
    source_ip: str | None,
) -> CaseDesign:
    """Record the approval: every brief item covered and at least ``min_cases`` cases.

    The brief is recomputed from the source NOW, so the approval attests the
    cases against the live brief; the snapshot stored here is what P4 names
    the scaffold's cases from. ``gates.leave_design`` only needs the record.
    """
    _require_design_stage(analysis)
    brief = brief_for(analysis, ref)
    design = get_design(db, analysis, ref)
    cases = list(design.cases) if design is not None else []
    missing = uncovered_items(brief, cases)
    if missing:
        raise BriefNotCovered(", ".join(missing)[:200])
    if len(cases) < brief.min_cases:
        raise CasesTooFew(f"{len(cases)} < {brief.min_cases}")
    design = _design_row(db, analysis, actor, ref)
    design.brief = brief_as_dict(brief)
    design.approved_at = utc_now()
    design.approved_by_username = actor.username
    _audit(db, actor, "design.cases.approve", analysis, ref, source_ip)
    db.flush()
    return design
