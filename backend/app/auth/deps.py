"""FastAPI dependencies for authentication and authorization.

Deny by default: a route without an explicit role dependency is unreachable by
convention, and every role check that fails is written to the audit log.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.audit.models import AuditOutcome
from app.auth.errors import AccountDisabled, Forbidden, InvalidToken, PasswordChangeRequired
from app.auth.models import Role, User
from app.auth.service import get_user_by_id
from app.auth.tokens import decode_access_token
from app.db.session import get_db

BEARER_PREFIX = "bearer "


def client_ip(request: Request) -> str | None:
    """Best-effort source address for the audit trail.

    Deliberately ignores ``X-Forwarded-For``: the platform is deployed on
    premise behind a reverse proxy we control, and trusting a client-supplied
    header would let anyone forge the trail. Revisit if a proxy chain is added.
    """
    return request.client.host if request.client else None


def _token_cutoff(password_changed_at: datetime) -> datetime:
    """The instant from which an access token is still trusted.

    JWT ``iat`` has ONE-SECOND resolution, so a token minted in the same second
    as a password change is indistinguishable from one minted just before it.
    We round the cutoff UP to the next whole second and reject anything below
    it: the ambiguous second falls on the INVALID side, so no token that could
    predate the change survives. The cost is that a re-login inside that same
    second is refused and must be retried — it fails closed, and a human typing
    a password takes far longer than the window.
    """
    return password_changed_at.replace(microsecond=0) + timedelta(seconds=1)


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Resolve the bearer token to a live account, or raise :class:`InvalidToken`."""
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith(BEARER_PREFIX):
        raise InvalidToken("missing bearer token")

    claims = decode_access_token(header[len(BEARER_PREFIX) :].strip())
    user = get_user_by_id(db, claims.subject)
    if user is None:
        raise InvalidToken("subject no longer exists")
    if user.disabled:
        raise AccountDisabled("account disabled")
    if user.role is not claims.role:
        # The role changed after the token was issued: the token is stale and
        # MUST NOT keep its old privileges until expiry.
        raise InvalidToken("role drift")
    if user.password_changed_at is not None and claims.issued_at < _token_cutoff(
        user.password_changed_at
    ):
        # Revoking refresh tokens does not touch an access token already in the
        # wild. Without this check, changing a password because it leaked leaves
        # the thief authenticated for up to the full 15-minute token lifetime.
        raise InvalidToken("password changed after this token was issued")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_active_user(user: CurrentUser) -> User:
    """A user who may use the application beyond the password-change endpoint."""
    if user.must_change_password:
        raise PasswordChangeRequired("password change required")
    return user


ActiveUser = Annotated[User, Depends(get_active_user)]


def require_roles(*allowed: Role) -> Callable[..., User]:
    """Build a dependency that admits only the listed roles."""

    def dependency(
        request: Request,
        user: ActiveUser,
        db: Annotated[Session, Depends(get_db)],
    ) -> User:
        if user.role not in allowed:
            audit.record(
                db,
                actor_username=user.username,
                actor_id=user.id,
                actor_role=user.role.value,
                action="authz.denied",
                outcome=AuditOutcome.DENIED,
                target=f"{request.method} {request.url.path}",
                source_ip=client_ip(request),
            )
            # The request is about to fail, and a failing request rolls its
            # session back — the denial record must be committed first.
            db.commit()
            raise Forbidden(f"role {user.role} not allowed on {request.url.path}")
        return user

    return dependency


AdminUser = Annotated[User, Depends(require_roles(Role.ADMIN))]
AnalystUser = Annotated[User, Depends(require_roles(Role.ANALYST))]
DeveloperUser = Annotated[User, Depends(require_roles(Role.DEVELOPER))]
