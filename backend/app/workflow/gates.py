"""Gate predicates: the server-side precondition for LEAVING each stage.

Pure functions over the analysis, no I/O, so the stage machine and the tests
share one definition (docs/workflow-gates.md). A gate that is not built yet
is CLOSED, never open: phase discipline says the later stages are unreachable
until their phase lands, and the gate-skip suite proves it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.models import Analysis, AnalysisStatus, Stage
from app.workflow.triage import triage_status

REASON_ANALYSIS_NOT_DONE = "analysis_not_done"
REASON_TRIAGE_PENDING = "triage_pending"
REASON_TEST_PLAN_MISSING = "test_plan_missing"
REASON_NOT_BUILT = "gate_not_built"
REASON_CASES_NOT_APPROVED = "cases_not_approved"


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


def not_built(_analysis: Analysis) -> GateResult:
    """Placeholder for a gate whose phase has not landed: always closed."""
    return _closed(REASON_NOT_BUILT)


# TODO(phase4): TESTS ("all planned cases have non-empty bodies") and
# VERIFICATION ("coverage meets the criterion, zero surviving mutants, no
# assertion-less test").
GATES: dict[Stage, object] = {
    Stage.CODE: leave_code,
    Stage.ANALYSIS: leave_analysis,
    Stage.PLAN: leave_plan,
    Stage.DESIGN: leave_design,
    Stage.TESTS: not_built,
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
