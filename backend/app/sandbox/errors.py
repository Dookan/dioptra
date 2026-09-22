"""Typed sandbox errors.

None of these reaches a client as a stack trace: `verify.py` turns them into a
recorded run with a reason, because "the sandbox could not run" is a result
the developer must be able to see, not a 500.
"""

from __future__ import annotations

from app.core.errors import AppError


class SandboxError(AppError):
    """Base: the verification attempt could not be carried out."""

    status_code = 503
    code = "sandbox_failed"
    message_key = "errors.sandbox.failed"


class SandboxUnavailable(SandboxError):
    """No Docker, or the sandbox image is not installed on this host."""

    code = "sandbox_unavailable"
    message_key = "errors.sandbox.unavailable"


class SandboxTimedOut(SandboxError):
    """The attempt exceeded ``sandbox_timeout_seconds`` and its container was killed."""

    code = "sandbox_timeout"
    message_key = "errors.sandbox.timeout"


class ResultsUnreadable(SandboxError):
    """The declared result files are missing or are not the documents they claim."""

    code = "sandbox_results_unreadable"
    message_key = "errors.sandbox.resultsUnreadable"
