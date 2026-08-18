"""Access tokens (JWT) and refresh tokens (opaque, hashed at rest)."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from app.auth.errors import InvalidToken
from app.auth.models import Role
from app.core.clock import utc_now
from app.core.config import get_settings

REFRESH_TOKEN_BYTES = 32


@dataclass(frozen=True, slots=True)
class AccessClaims:
    """The subset of JWT claims the application trusts."""

    subject: uuid.UUID
    username: str
    role: Role
    token_id: uuid.UUID
    #: Issue time, UTC. Compared against ``User.password_changed_at`` so a
    #: credential change can invalidate tokens minted before it.
    issued_at: datetime


def issue_access_token(*, user_id: uuid.UUID, username: str, role: Role) -> tuple[str, int]:
    """Return ``(token, expires_in_seconds)``."""
    settings = get_settings()
    now = utc_now()
    expires_at = now + timedelta(seconds=settings.access_token_ttl_seconds)
    payload = {
        "sub": str(user_id),
        "preferred_username": username,
        "role": role.value,
        "iss": settings.jwt_issuer,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return token, settings.access_token_ttl_seconds


def decode_access_token(token: str) -> AccessClaims:
    """Validate signature, issuer and expiry, then narrow the claims.

    The algorithm is pinned to the configured one: accepting whatever the
    header states is the classic JWT forgery path.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            options={"require": ["sub", "exp", "iat", "iss", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidToken(str(exc)) from exc

    try:
        return AccessClaims(
            subject=uuid.UUID(str(payload["sub"])),
            username=str(payload["preferred_username"]),
            role=Role(str(payload["role"])),
            token_id=uuid.UUID(str(payload["jti"])),
            issued_at=datetime.fromtimestamp(int(payload["iat"]), tz=UTC),
        )
    except (KeyError, ValueError) as exc:
        raise InvalidToken("malformed claims") from exc


def generate_refresh_token() -> str:
    """A high-entropy opaque token. Never derived from user data."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(raw_token: str) -> str:
    """SHA-256 of the token: only the digest is stored.

    A plain digest (no salt, no cost) is correct here — the input already has
    256 bits of entropy, so there is nothing to brute-force.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
