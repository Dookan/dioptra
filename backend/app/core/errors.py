"""Typed domain errors and their HTTP contract.

Raw exceptions MUST NOT reach an HTTP response (CLAUDE.md → Code Conventions).
Every module raises its own subclass of :class:`AppError`; a single handler in
``app.main`` renders ``{"code": ..., "message_key": ...}`` — a stable i18n key,
never a server-authored Spanish/English sentence and never a stack trace.
"""

from __future__ import annotations


class AppError(Exception):
    """Base class for every error that is allowed to become an HTTP response."""

    status_code: int = 500
    code: str = "internal_error"
    #: i18n key the frontend resolves; the backend never ships display copy.
    message_key: str = "errors.internal"

    def __init__(self, detail: str | None = None) -> None:
        # ``detail`` is for the server log only. It is never serialized.
        super().__init__(detail or self.code)
        self.detail = detail

    def headers(self) -> dict[str, str]:
        """Extra response headers (e.g. ``Retry-After``). Empty by default."""
        return {}


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_failed"
    message_key = "errors.validation"
