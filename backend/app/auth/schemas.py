"""Request and response models for the auth API.

Responses never carry the password hash, the refresh token digest, or any
counter an attacker could use to probe the lockout state.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.auth.models import Role
from app.auth.passwords import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class UserProfile(BaseModel):
    """The identity the frontend renders in the appbar."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    display_name: str
    role: Role
    must_change_password: bool


class SessionResponse(BaseModel):
    """The access token lives in memory only; the refresh token is a cookie."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105 - an auth scheme name, not a secret
    expires_in: int
    user: UserProfile


class ErrorResponse(BaseModel):
    """The single error shape every endpoint returns."""

    code: str
    message_key: str


# --- Account administration (phase 6, admin only) ---------------------------
# Caps are the COLUMNS' widths (users.display_name 120, users.email 254): a
# longer value would pass validation and reach the driver as a 500
# (tasks/phase6-survey.md §1). The justification's own floor and ceiling are
# app.core.text's; here only a transport bound.

_JUSTIFICATION_TRANSPORT_MAX = 8000


class UserAdminOut(BaseModel):
    """One account as the admin sees it. No hash, no failure counter: the exact
    count is the lockout's business, "bloqueada hasta …" is what an admin acts on."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    display_name: str
    email: str | None
    role: Role
    disabled: bool
    must_change_password: bool
    last_login_at: datetime | None
    locked_until: datetime | None
    created_at: datetime


class UserCreateIn(BaseModel):
    """No justification: creation is the Hard Rule's one recorded exception."""

    username: str = Field(min_length=1, max_length=32)
    display_name: str = Field(min_length=1, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    role: Role
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class RoleChangeIn(BaseModel):
    role: Role
    justification: str = Field(max_length=_JUSTIFICATION_TRANSPORT_MAX)


class StatusChangeIn(BaseModel):
    disabled: bool
    justification: str = Field(max_length=_JUSTIFICATION_TRANSPORT_MAX)


class PasswordResetIn(BaseModel):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    justification: str = Field(max_length=_JUSTIFICATION_TRANSPORT_MAX)
