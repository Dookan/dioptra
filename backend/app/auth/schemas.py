"""Request and response models for the auth API.

Responses never carry the password hash, the refresh token digest, or any
counter an attacker could use to probe the lockout state.
"""

from __future__ import annotations

import uuid

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
