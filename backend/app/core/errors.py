"""Typed domain errors and their HTTP contract.

Raw exceptions MUST NOT reach an HTTP response (CLAUDE.md → Code Conventions).
Every module raises its own subclass of :class:`AppError`; a single handler in
``app.main`` renders ``{"code": ..., "message_key": ...}`` — a stable i18n key,
never a server-authored Spanish/English sentence and never a stack trace. An
error MAY carry ``context``: short strings the UI interpolates into the
translated message (which function, which line); they are data, never copy.
"""

from __future__ import annotations


class AppError(Exception):
    """Base class for every error that is allowed to become an HTTP response."""

    status_code: int = 500
    code: str = "internal_error"
    #: i18n key the frontend resolves; the backend never ships display copy.
    message_key: str = "errors.internal"

    def __init__(self, detail: str | None = None, *, context: dict[str, str] | None = None) -> None:
        # ``detail`` is for the server log only. It is never serialized.
        super().__init__(detail or self.code)
        self.detail = detail
        #: Serialized as ``context`` when present; values are bounded strings
        #: the client renders as text (they may come from the audited tree).
        self.context = context

    def headers(self) -> dict[str, str]:
        """Extra response headers (e.g. ``Retry-After``). Empty by default."""
        return {}


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_failed"
    message_key = "errors.validation"


class JustificationRequired(AppError):
    """A sensitive action arrived without a usable written justification.

    Lives here, not in ``app.workflow.errors``, because the auth surface
    enforces the same floor (phase 6); the workflow module re-exports it, and
    its code and key are unchanged.
    """

    status_code = 422
    code = "justification_required"
    message_key = "errors.workflow.justificationRequired"
