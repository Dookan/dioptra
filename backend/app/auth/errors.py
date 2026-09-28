"""Authentication and authorization errors.

Client-visible messages MUST NOT distinguish "unknown user" from "wrong
password" — both raise :class:`InvalidCredentials` with the same key.
"""

from __future__ import annotations

from app.core.errors import AppError


class AuthError(AppError):
    """Base class for everything this module rejects."""


class InvalidCredentials(AuthError):
    status_code = 401
    code = "invalid_credentials"
    message_key = "errors.auth.invalidCredentials"


class AccountLocked(AuthError):
    status_code = 423
    code = "account_locked"
    message_key = "errors.auth.accountLocked"

    def __init__(self, retry_after_seconds: int, detail: str | None = None) -> None:
        super().__init__(detail)
        self.retry_after_seconds = max(retry_after_seconds, 1)

    def headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after_seconds)}


class AccountDisabled(AuthError):
    status_code = 403
    code = "account_disabled"
    message_key = "errors.auth.accountDisabled"


class InvalidToken(AuthError):
    status_code = 401
    code = "invalid_token"
    message_key = "errors.auth.invalidToken"


class TokenReuseDetected(AuthError):
    """A spent refresh token came back: the family is revoked on sight."""

    status_code = 401
    code = "token_reuse_detected"
    message_key = "errors.auth.sessionRevoked"


class PasswordChangeRequired(AuthError):
    status_code = 409
    code = "password_change_required"
    message_key = "errors.auth.passwordChangeRequired"


class WeakPassword(AuthError):
    status_code = 422
    code = "weak_password"
    message_key = "errors.auth.weakPassword"


class InvalidUsername(AuthError):
    """The username does not match the factory convention (initial + lastname)."""

    status_code = 422
    code = "invalid_username"
    message_key = "errors.auth.invalidUsername"


class Forbidden(AuthError):
    status_code = 403
    code = "forbidden"
    message_key = "errors.auth.forbidden"


class UserNotFound(AuthError):
    status_code = 404
    code = "user_not_found"
    message_key = "errors.auth.userNotFound"


class UsernameTaken(AuthError):
    status_code = 409
    code = "username_taken"
    message_key = "errors.auth.usernameTaken"


class EmailTaken(AuthError):
    status_code = 409
    code = "email_taken"
    message_key = "errors.auth.emailTaken"


class CannotAdministerSelf(AuthError):
    """An admin acting on their own account: role, status or password.

    One's own password goes through ``POST /api/v1/auth/password``, which asks
    for the current one; the admin path does not.
    """

    status_code = 422
    code = "cannot_administer_self"
    message_key = "errors.auth.cannotAdministerSelf"


class RoleUnchanged(AuthError):
    status_code = 422
    code = "role_unchanged"
    message_key = "errors.auth.roleUnchanged"


class StatusUnchanged(AuthError):
    status_code = 422
    code = "status_unchanged"
    message_key = "errors.auth.statusUnchanged"
