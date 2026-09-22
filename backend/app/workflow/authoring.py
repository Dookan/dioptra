"""Stage E6 (day 16): the developer writes the tests over the scaffold.

The platform's whole contribution is the scaffold (``workflow/scaffold/``):
names, imports and the brief items each case must demonstrate. Everything
else in the stored file is the developer's, and the gate only asks whether
they wrote it — never whether it is "good", which is E7's measurement.

Writing is allowed AT E6, and at E7 for a function the verification loop
reopened (``CaseDesign.reopened_at``), so a rejected test can be fixed
without moving the stage machine backwards.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit import service as audit
from app.auth.models import User
from app.workflow.ast.errors import AstError
from app.workflow.design import FunctionRef, get_design, planned_function
from app.workflow.errors import (
    DesignNotApproved,
    OversizedTests,
    StageLocked,
    StageNotReached,
    UnparsableTests,
)
from app.workflow.models import MAX_TEST_FILE_CHARS, CaseDesign, TestFile
from app.workflow.scaffold import ScaffoldFile, build_scaffold
from app.workflow.scaffold.inspect import CaseBody, inspect_cases
from app.workflow.triage import strip_control_chars

_BEFORE_TESTS = (Stage.REGISTER, Stage.CODE, Stage.ANALYSIS, Stage.PLAN, Stage.DESIGN)


def get_test_file(db: Session, analysis: Analysis, ref: FunctionRef) -> TestFile | None:
    statement = select(TestFile).where(
        TestFile.analysis_id == analysis.id,
        TestFile.path == ref.path,
        TestFile.function == ref.function,
        TestFile.line == ref.line,
    )
    return db.scalars(statement).first()


def _require_writable(analysis: Analysis, design: CaseDesign | None) -> None:
    """E6 deliverables are written AT E6 — or at E7 for a reopened function."""
    if analysis.stage is Stage.TESTS:
        return
    if analysis.stage in _BEFORE_TESTS:
        raise StageNotReached(f"analysis {analysis.id} is at {analysis.stage.value}")
    if analysis.stage is Stage.VERIFICATION and design is not None and design.reopened_at:
        return
    raise StageLocked(f"analysis {analysis.id} is at {analysis.stage.value}")


def scaffold_of(db: Session, analysis: Analysis, ref: FunctionRef) -> ScaffoldFile:
    """The deterministic scaffold for one planned, approved function."""
    planned_function(analysis, ref)
    design = get_design(db, analysis, ref)
    if design is None:
        raise DesignNotApproved(f"{ref.path}:{ref.line} {ref.function}"[:200])
    return build_scaffold(design)


def bodies_of(scaffold: ScaffoldFile, content: str, path: str) -> list[CaseBody]:
    """Which approved cases the stored text actually has a body for."""
    if not content.strip():
        return [CaseBody(id=case.id, present=False, statements=0) for case in scaffold.cases]
    return inspect_cases(content, path, scaffold.cases)


def scaffold_payload(db: Session, analysis: Analysis, ref: FunctionRef) -> dict[str, Any]:
    scaffold = scaffold_of(db, analysis, ref)
    stored = get_test_file(db, analysis, ref)
    content = stored.content if stored is not None else ""
    try:
        bodies = bodies_of(scaffold, content, ref.path)
        parse_error = False
    except (UnparsableTests, AstError):
        bodies = [CaseBody(id=case.id, present=False, statements=0) for case in scaffold.cases]
        parse_error = True
    return {
        "path": ref.path,
        "function": ref.function,
        "line": ref.line,
        "language": scaffold.language,
        "runner": scaffold.runner,
        "filename": scaffold.filename,
        "scaffold": scaffold.content,
        "content": content,
        "stored_at": stored.updated_at if stored is not None else None,
        "stored_by_username": stored.created_by_username if stored is not None else None,
        "parse_error": parse_error,
        "cases": [
            {
                "id": case.id,
                "title": case.title,
                "covers": list(case.covers),
                "written": body.written,
            }
            for case, body in zip(scaffold.cases, bodies, strict=True)
        ],
    }


def save_tests(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    ref: FunctionRef,
    content: str,
    source_ip: str | None,
) -> TestFile:
    """Store the developer's test file as TEXT; it is never executed here."""
    design = get_design(db, analysis, ref)
    _require_writable(analysis, design)
    scaffold = scaffold_of(db, analysis, ref)
    cleaned = strip_control_chars(content.replace("\r\n", "\n"))
    if len(cleaned) > MAX_TEST_FILE_CHARS:
        raise OversizedTests(f"{len(cleaned)} > {MAX_TEST_FILE_CHARS}")
    stored = get_test_file(db, analysis, ref)
    if stored is None:
        stored = TestFile(
            analysis_id=analysis.id,
            path=ref.path,
            function=ref.function,
            line=ref.line,
            filename=scaffold.filename,
            created_by_username=actor.username,
        )
        db.add(stored)
    stored.filename = scaffold.filename
    stored.content = cleaned
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="tests.save",
        target=f"analysis:{analysis.id}:{ref.path}:{ref.line}:{ref.function}"[:255],
        source_ip=source_ip,
    )
    db.flush()
    return stored


def writing_states(db: Session, analysis: Analysis) -> list[dict[str, Any]]:
    """Per planned function: how many approved cases have a body.

    Drives the E6 screen and the "next step" banner; the gate reads the same
    rows through ``gates.leave_tests``.
    """
    plan = analysis.test_plan
    rows = plan.functions if plan is not None else []
    states: list[dict[str, Any]] = []
    for row in rows:
        ref = FunctionRef(
            path=str(row.get("path")), function=str(row.get("function")), line=row.get("line")
        )
        state: dict[str, Any] = {
            "path": ref.path,
            "function": ref.function,
            "line": ref.line,
            "cases": 0,
            "written": 0,
            "parse_error": False,
        }
        try:
            payload = scaffold_payload(db, analysis, ref)
        except (DesignNotApproved, AstError):
            states.append(state)
            continue
        state["cases"] = len(payload["cases"])
        state["written"] = sum(1 for case in payload["cases"] if case["written"])
        state["parse_error"] = bool(payload["parse_error"])
        states.append(state)
    return states
