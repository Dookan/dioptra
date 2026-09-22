"""Typed workflow errors."""

from __future__ import annotations

from app.core.errors import AppError


class WorkflowError(AppError):
    """Base class for everything the workflow surface rejects."""

    status_code = 422
    code = "workflow_failed"
    message_key = "errors.workflow.failed"


class FindingNotFound(WorkflowError):
    status_code = 404
    code = "finding_not_found"
    message_key = "errors.findings.notFound"


class JustificationRequired(WorkflowError):
    """A sensitive action arrived without a usable written justification."""

    code = "justification_required"
    message_key = "errors.workflow.justificationRequired"


#: Gate reason code → i18n key the UI resolves. Every reason a gate can
#: return MUST be listed here (the locale-parity test mirrors the values).
GATE_MESSAGE_KEYS: dict[str, str] = {
    "analysis_not_done": "errors.workflow.gate.analysisNotDone",
    "triage_pending": "errors.workflow.gate.triagePending",
    "test_plan_missing": "errors.workflow.gate.testPlanMissing",
    "gate_not_built": "errors.workflow.gate.notBuilt",
    "cases_not_approved": "errors.workflow.gate.casesNotApproved",
}


class GateClosed(WorkflowError):
    """The current stage's gate is not satisfied; ``reason`` names which condition."""

    status_code = 409
    code = "gate_closed"
    message_key = "errors.workflow.gate.closed"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.message_key = GATE_MESSAGE_KEYS.get(reason, GateClosed.message_key)


class StageIsFinal(WorkflowError):
    status_code = 409
    code = "stage_final"
    message_key = "errors.workflow.stageFinal"


class StageLocked(WorkflowError):
    """The deliverable of a stage already left cannot change any more."""

    status_code = 409
    code = "stage_locked"
    message_key = "errors.workflow.stageLocked"


class StageNotReached(WorkflowError):
    """The deliverable of a stage cannot be written before the analysis gets there."""

    status_code = 409
    code = "stage_not_reached"
    message_key = "errors.workflow.stageNotReached"


class TestPlanNotFound(WorkflowError):
    status_code = 404
    code = "test_plan_not_found"
    message_key = "errors.workflow.testPlanNotFound"


class TestPlanEmpty(WorkflowError):
    code = "test_plan_empty"
    message_key = "errors.workflow.testPlanEmpty"


class TestPlanFunctionUnknown(WorkflowError):
    """A selected function is not one the metrics measured."""

    code = "test_plan_function_unknown"
    message_key = "errors.workflow.testPlanFunctionUnknown"


class TestPlanFunctionRefused(WorkflowError):
    """Base: a selected function cannot get a brief, so it cannot enter the plan.

    Refused at E4, while the set is still editable — otherwise E5 could never
    close (survey §8, addendum). ``context`` names the function for the UI.
    """

    def __init__(self, path: str, function: str, line: int | None, detail: str) -> None:
        super().__init__(
            repr(f"{path}:{line} {function} {detail}")[:200],
            context={"path": path[:1024], "function": function[:200], "line": str(line or "")},
        )


class TestPlanFunctionUnbriefable(TestPlanFunctionRefused):
    """The AST layer refused the function (language, size, syntax, nesting, not found)."""

    code = "test_plan_function_unbriefable"
    message_key = "errors.workflow.testPlanFunctionUnbriefable"


class TestPlanFunctionTooComplex(TestPlanFunctionRefused):
    """More basis paths than cases a design may hold (``MAX_CASES``)."""

    code = "test_plan_function_too_complex"
    message_key = "errors.workflow.testPlanFunctionTooComplex"


class CaseItemUnknown(WorkflowError):
    """A case declares a brief item id that the current brief does not contain."""

    code = "case_item_unknown"
    message_key = "errors.workflow.caseItemUnknown"


class CasesInvalid(WorkflowError):
    """A case title is empty, too short or too long, or there are too many cases."""

    code = "cases_invalid"
    message_key = "errors.workflow.casesInvalid"


class BriefNotCovered(WorkflowError):
    """Approval refused: at least one brief item is covered by no case."""

    code = "brief_not_covered"
    message_key = "errors.workflow.briefNotCovered"


class CasesTooFew(WorkflowError):
    """Approval refused: fewer cases than basis paths (+ malicious cases)."""

    code = "cases_too_few"
    message_key = "errors.workflow.casesTooFew"
