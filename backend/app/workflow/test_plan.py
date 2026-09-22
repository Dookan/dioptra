"""E4 test plan: what to test, how exigently, and why — in the developer's words."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit import service as audit
from app.auth.models import User
from app.workflow.ast.errors import AstError
from app.workflow.ast.extract import build_graph
from app.workflow.ast.source import language_for, load_source
from app.workflow.brief import build_brief
from app.workflow.errors import (
    StageLocked,
    StageNotReached,
    TestPlanEmpty,
    TestPlanFunctionTooComplex,
    TestPlanFunctionUnbriefable,
    TestPlanFunctionUnknown,
    TestPlanNotFound,
)
from app.workflow.models import MAX_CASES, CoverageCriterion, TestPlan
from app.workflow.stages import is_past
from app.workflow.triage import clean_justification

MAX_FUNCTIONS = 200


def get_test_plan(analysis: Analysis) -> TestPlan:
    if analysis.test_plan is None:
        raise TestPlanNotFound(str(analysis.id))
    return analysis.test_plan


FunctionKey = tuple[str, str, int | None]


def _key(item: dict[str, object]) -> FunctionKey:
    line = item.get("line")
    return (
        str(item.get("path")),
        str(item.get("function")),
        line if isinstance(line, int) else None,
    )


def _measured(analysis: Analysis) -> dict[FunctionKey, dict[str, object]]:
    metrics = analysis.metrics
    rows = metrics.functions if metrics is not None else []
    return {_key(row): row for row in rows}


def check_briefable(analysis: Analysis, key: FunctionKey) -> None:
    """Refuse, at E4, a function E5 could never approve.

    Parsing here costs what ``GET …/brief`` costs, once per chosen function,
    at the only moment the set is still editable; without it a function the
    AST layer refuses, or one with more basis paths than ``MAX_CASES``, would
    leave the analysis stuck at E5 with no way back (the plan is locked and
    the stages are monotonic).
    """
    path, function, line = key
    try:
        graph = build_graph(load_source(analysis, path), language_for(path), function, line)
    except AstError as error:
        raise TestPlanFunctionUnbriefable(path, function, line, error.code) from error
    # The number approval will demand — basis paths plus one case per SAST
    # finding inside the function (frozen with E3) — not the bare complexity.
    minimum = build_brief(analysis, path, graph).min_cases
    if minimum > MAX_CASES:
        raise TestPlanFunctionTooComplex(path, function, line, f"min_cases {minimum}")


def save_test_plan(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    criterion: CoverageCriterion,
    rationale: str,
    functions: list[dict[str, object]],
    source_ip: str | None,
) -> TestPlan:
    """Create or replace the plan — only while the analysis IS at E4.

    Before: the plan is E4's deliverable and the ranking still moves with
    triage. After: E5 computes the brief against a fixed plan.
    """
    if is_past(analysis, Stage.PLAN):
        raise StageLocked(f"analysis {analysis.id} is at {analysis.stage.value}")
    if analysis.stage is not Stage.PLAN:
        raise StageNotReached(f"analysis {analysis.id} is at {analysis.stage.value}")
    text = clean_justification(rationale)
    if not functions:
        raise TestPlanEmpty(str(analysis.id))
    measured = _measured(analysis)
    selected: list[dict[str, object]] = []
    seen: set[FunctionKey] = set()
    for item in functions[:MAX_FUNCTIONS]:
        key = _key(item)
        row = measured.get(key)
        if row is None:
            # Client-controlled strings end up in the server log: repr-escaped, bounded.
            raise TestPlanFunctionUnknown(repr(f"{key[0]}:{key[2]} {key[1]}")[:200])
        if key in seen:
            continue
        seen.add(key)
        check_briefable(analysis, key)
        selected.append(
            {"path": key[0], "function": key[1], "line": key[2], "ccn": row.get("ccn", 1)}
        )
    plan = analysis.test_plan
    if plan is None:
        plan = TestPlan(analysis_id=analysis.id, created_by_username=actor.username)
        db.add(plan)
        analysis.test_plan = plan
    plan.criterion = criterion
    plan.rationale = text
    plan.functions = selected
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="testplan.save",
        target=f"analysis:{analysis.id}",
        justification=text,
        source_ip=source_ip,
    )
    db.flush()
    return plan
