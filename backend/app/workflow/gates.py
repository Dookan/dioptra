"""Gate predicates: the server-side precondition for LEAVING each stage.

Pure functions over the analysis, no I/O, so the stage machine and the tests
share one definition (docs/workflow-gates.md). A gate that is not built yet
is CLOSED, never open: phase discipline says the later stages are unreachable
until their phase lands, and the gate-skip suite proves it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.models import Analysis, AnalysisStatus, Stage
from app.workflow.ast.errors import AstError
from app.workflow.errors import WorkflowError
from app.workflow.scaffold import build_scaffold
from app.workflow.scaffold.inspect import inspect_cases
from app.workflow.triage import triage_status

REASON_ANALYSIS_NOT_DONE = "analysis_not_done"
REASON_TRIAGE_PENDING = "triage_pending"
REASON_TEST_PLAN_MISSING = "test_plan_missing"
REASON_NOT_BUILT = "gate_not_built"
REASON_CASES_NOT_APPROVED = "cases_not_approved"
REASON_TESTS_NOT_WRITTEN = "tests_not_written"


@dataclass(frozen=True)
class GateResult:
    open: bool
    #: Reason code when closed (``app.workflow.errors.GATE_MESSAGE_KEYS``).
    reason: str | None = None


OPEN = GateResult(open=True)


def _closed(reason: str) -> GateResult:
    return GateResult(open=False, reason=reason)


def leave_code(analysis: Analysis) -> GateResult:
    """E2 → E3: the pipeline finished without a fatal error."""
    if analysis.status is not AnalysisStatus.DONE:
        return _closed(REASON_ANALYSIS_NOT_DONE)
    return OPEN


def leave_analysis(analysis: Analysis) -> GateResult:
    """E3 → E4: EVERY finding confirmed or discarded with a justification."""
    if not triage_status(analysis).complete:
        return _closed(REASON_TRIAGE_PENDING)
    return OPEN


def leave_plan(analysis: Analysis) -> GateResult:
    """E4 → E5: at least one function, a criterion and a written rationale."""
    plan = analysis.test_plan
    if plan is None or not plan.functions or not plan.rationale.strip():
        return _closed(REASON_TEST_PLAN_MISSING)
    return OPEN


def leave_design(analysis: Analysis) -> GateResult:
    """E5 → E6: every planned function has its cases approved.

    Approval (``design.approve_cases``) is where the cases are checked against
    the brief computed from the live source; the gate only needs the record,
    so it stays a pure predicate. Saving cases again clears the approval.
    """
    plan = analysis.test_plan
    if plan is None or not plan.functions:
        return _closed(REASON_TEST_PLAN_MISSING)
    approved = {
        (design.path, design.function, design.line)
        for design in analysis.case_designs
        if design.approved_at is not None
    }
    for row in plan.functions:
        key = (str(row.get("path")), str(row.get("function")), row.get("line"))
        if key not in approved:
            return _closed(REASON_CASES_NOT_APPROVED)
    return OPEN


def leave_tests(analysis: Analysis) -> GateResult:
    """E6 → E7: every approved case has a body the developer wrote.

    Read, never run: the stored text is parsed with the same tree-sitter layer
    the briefs use, and a case counts only when it holds a statement of its
    own — not a comment, not the title string, not ``pass``, and not a skipped
    case. Whether the test PROVES anything is E7's measurement, not this
    gate's opinion; a file that does not parse simply leaves its cases
    unwritten, because the gate may not raise.
    """
    plan = analysis.test_plan
    if plan is None or not plan.functions:
        return _closed(REASON_TEST_PLAN_MISSING)
    designs = {(d.path, d.function, d.line): d for d in analysis.case_designs}
    files = {(f.path, f.function, f.line): f for f in analysis.test_files}
    for row in plan.functions:
        key = (str(row.get("path")), str(row.get("function")), row.get("line"))
        design = designs.get(key)
        if design is None or design.approved_at is None:
            return _closed(REASON_CASES_NOT_APPROVED)
        stored = files.get(key)
        if stored is None or not stored.content.strip():
            return _closed(REASON_TESTS_NOT_WRITTEN)
        try:
            scaffold = build_scaffold(design)
            bodies = inspect_cases(stored.content, design.path, scaffold.cases)
        except (WorkflowError, AstError):
            return _closed(REASON_TESTS_NOT_WRITTEN)
        if not scaffold.cases or not all(body.written for body in bodies):
            return _closed(REASON_TESTS_NOT_WRITTEN)
    return OPEN


def not_built(_analysis: Analysis) -> GateResult:
    """Placeholder for a gate whose phase has not landed: always closed."""
    return _closed(REASON_NOT_BUILT)


# TODO(phase4): VERIFICATION ("coverage meets the criterion, zero surviving
# mutants, no assertion-less test") lands with day 17.
GATES: dict[Stage, object] = {
    Stage.CODE: leave_code,
    Stage.ANALYSIS: leave_analysis,
    Stage.PLAN: leave_plan,
    Stage.DESIGN: leave_design,
    Stage.TESTS: leave_tests,
    Stage.VERIFICATION: not_built,
}


def check(stage: Stage, analysis: Analysis) -> GateResult:
    """The gate for leaving ``stage``. REGISTER is the project's (always open); REPORT is final."""
    if stage is Stage.REGISTER:
        return OPEN
    gate = GATES.get(stage)
    if gate is None:
        return _closed(REASON_NOT_BUILT)
    result: GateResult = gate(analysis)  # type: ignore[operator]
    return result
