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
from app.workflow.models import VerificationRun, VerificationStatus
from app.workflow.scaffold import build_scaffold
from app.workflow.scaffold.inspect import inspect_cases
from app.workflow.triage import triage_status

REASON_ANALYSIS_NOT_DONE = "analysis_not_done"
REASON_TRIAGE_PENDING = "triage_pending"
REASON_TEST_PLAN_MISSING = "test_plan_missing"
#: Returned for a stage with no entry in ``GATES`` — the default is CLOSED.
#: Every stage E2→E7 has a gate since P4 day 17; E8 is final and has none.
REASON_NOT_BUILT = "gate_not_built"
REASON_CASES_NOT_APPROVED = "cases_not_approved"
REASON_TESTS_NOT_WRITTEN = "tests_not_written"
REASON_NOT_VERIFIED = "not_verified"
REASON_VERIFICATION_FAILED = "verification_failed"


def planned_keys(plan: object) -> list[tuple[str, str, int | None]]:
    """The ``(path, function, line)`` of every planned function.

    ``test_plan.save_test_plan`` rebuilds each row server-side, so a row that
    is not a dict means the column was corrupted underneath us. A gate may not
    raise on that (it would turn a stage transition into a 500), and skipping
    the row would OPEN the gate for a function nobody checked — so a malformed
    row keeps a key that can never match a design, a file or a run.
    """
    rows = getattr(plan, "functions", None)
    if not isinstance(rows, list):
        # Not a list at all: there is no plan to check against, and every
        # caller must read that as "missing", never as "nothing to check".
        return []
    keys: list[tuple[str, str, int | None]] = []
    for row in rows:
        if not isinstance(row, dict):
            keys.append(("", "", None))
            continue
        line = row.get("line")
        keys.append(
            (
                str(row.get("path")),
                str(row.get("function")),
                line if isinstance(line, int) else None,
            )
        )
    return keys


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
    """E3 → E4: every finding OF THE QUEUE confirmed or discarded, with a reason.

    The queue is not every finding: `triage_status` drops the ones in
    dependency directories, which the analyst may not adjudicate at all
    (`app/analysis/third_party.py`, `mmarin` 2026-09-23). They stay stored,
    shown and printed — this gate simply never waits for them.
    """
    if not triage_status(analysis).complete:
        return _closed(REASON_TRIAGE_PENDING)
    return OPEN


def leave_plan(analysis: Analysis) -> GateResult:
    """E4 → E5: at least one function, a criterion and a written rationale."""
    plan = analysis.test_plan
    if plan is None or not planned_keys(plan) or not str(plan.rationale).strip():
        return _closed(REASON_TEST_PLAN_MISSING)
    return OPEN


def leave_design(analysis: Analysis) -> GateResult:
    """E5 → E6: every planned function has its cases approved.

    Approval (``design.approve_cases``) is where the cases are checked against
    the brief computed from the live source; the gate only needs the record,
    so it stays a pure predicate. Saving cases again clears the approval.
    """
    plan = analysis.test_plan
    keys = planned_keys(plan)
    if plan is None or not keys:
        return _closed(REASON_TEST_PLAN_MISSING)
    approved = {
        (design.path, design.function, design.line)
        for design in analysis.case_designs
        if design.approved_at is not None
    }
    for key in keys:
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
    keys = planned_keys(plan)
    if plan is None or not keys:
        return _closed(REASON_TEST_PLAN_MISSING)
    designs = {(d.path, d.function, d.line): d for d in analysis.case_designs}
    files = {(f.path, f.function, f.line): f for f in analysis.test_files}
    for key in keys:
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


def leave_verification(analysis: Analysis) -> GateResult:
    """E7 → E8: the latest run of EVERY planned function passed.

    A pure row predicate again — and a TOTAL one: `planned_keys` keeps a
    malformed plan row from raising here. `verify.run_verification` did the
    measuring in the worker and wrote the verdict down. "Passed" means the tests ran green,
    every case asserted something, the coverage met the E4 criterion, every
    brief item's line ran with its branch complete, and no mutant survived.
    A function whose cases were reopened by the E7 → E5 loop has no passing
    latest run, so the gate stays closed until it is verified again.
    """
    plan = analysis.test_plan
    keys = planned_keys(plan)
    if plan is None or not keys:
        return _closed(REASON_TEST_PLAN_MISSING)
    latest: dict[tuple[str, str, int | None], VerificationRun] = {}
    for run in analysis.verification_runs:
        latest[(run.path, run.function, run.line)] = run
    for key in keys:
        newest = latest.get(key)
        if newest is None:
            return _closed(REASON_NOT_VERIFIED)
        if newest.status is not VerificationStatus.PASSED:
            return _closed(REASON_VERIFICATION_FAILED)
    return OPEN


GATES: dict[Stage, object] = {
    Stage.CODE: leave_code,
    Stage.ANALYSIS: leave_analysis,
    Stage.PLAN: leave_plan,
    Stage.DESIGN: leave_design,
    Stage.TESTS: leave_tests,
    Stage.VERIFICATION: leave_verification,
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
