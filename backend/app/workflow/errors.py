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
