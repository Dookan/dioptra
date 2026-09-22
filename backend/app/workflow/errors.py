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
