"""Authentication use cases.

Implements the pseudocode signed off in tasks/phase0-survey.md §4. Every path
that changes security state also appends to the audit log.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.audit.models import AuditOutcome
from app.auth.errors import (
    AccountDisabled,
    AccountLocked,
    InvalidCredentials,
    InvalidToken,
    InvalidUsername,
    TokenReuseDetected,
)
from app.auth.models import USERNAME_PATTERN, RefreshToken, Role, User
from app.auth.passwords import (
    hash_password,
    needs_rehash,
    spend_dummy_verification,
    validate_password_policy,
    verify_password,
)
from app.auth.tokens import generate_refresh_token, hash_refresh_token, issue_access_token
from app.core.clock import utc_now
from app.core.config import get_settings


def _persist_security_state(session: Session) -> None:
    """Commit before raising on a rejection path.

    A denied request still ends in an exception, and the request-scoped session
    rolls back on exceptions — which would silently discard the failure counter,
    the revocation and the audit entry that justify the rejection. Durability of
    those three is not optional, so rejection paths commit explicitly first.
    """
    session.commit()


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """What a successful login or refresh hands back to the transport layer."""

    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    user: User


def get_user_by_username(session: Session, username: str) -> User | None:
    return session.scalars(select(User).where(User.username == username.strip().lower())).first()


def get_user_by_id(session: Session, user_id: uuid.UUID) -> User | None:
    return session.get(User, user_id)


def create_user(
    session: Session,
    *,
    username: str,
    display_name: str,
    role: Role,
    password: str,
    email: str | None = None,
    must_change_password: bool = True,
) -> User:
    """Create an account. Callers MUST have already checked admin authorization."""
    validate_password_policy(password)
    normalised = username.strip().lower()
    # USERNAME_PATTERN existed but was referenced nowhere, so the Hard Rule
    # "usernames are initial + lastname, lowercase, no dots" had zero runtime
    # enforcement. This is the only account-creation path; wiring it here closes
    # the hole before P1 exposes an admin endpoint on top of it.
    if re.fullmatch(USERNAME_PATTERN, normalised) is None:
        raise InvalidUsername(f"username {normalised!r} does not match the convention")
    user = User(
        username=normalised,
        display_name=display_name,
        role=role,
        email=email,
        password_hash=hash_password(password),
        must_change_password=must_change_password,
    )
    session.add(user)
    session.flush()
    return user


def authenticate(
    session: Session, *, username: str, password: str, source_ip: str | None = None
) -> IssuedSession:
    """Verify credentials and open a session, or raise a typed AuthError."""
    settings = get_settings()
    now = utc_now()
    normalized = username.strip().lower()
    user = get_user_by_username(session, normalized)

    if user is None:
        # Same work as a real verification: no enumeration by response time.
        spend_dummy_verification(password)
        audit.record(
            session,
            actor_username=normalized,
            action="auth.login",
            outcome=AuditOutcome.DENIED,
            target="unknown_user",
            source_ip=source_ip,
        )
        _persist_security_state(session)
        raise InvalidCredentials("unknown username")

    if user.disabled:
        spend_dummy_verification(password)
        audit.record(
            session,
            actor_username=user.username,
            actor_id=user.id,
            actor_role=user.role.value,
            action="auth.login",
            outcome=AuditOutcome.DENIED,
            target="disabled_account",
            source_ip=source_ip,
        )
        _persist_security_state(session)
        # Deliberately InvalidCredentials, NOT AccountDisabled: this caller is
        # unauthenticated, so answering "that account exists but is disabled" to
        # any password hands out free username enumeration and contradicts the
        # invariant stated at the top of auth/errors.py. The audit row above
        # still records the real reason — the TRAIL distinguishes, the RESPONSE
        # must not. deps.py keeps the explicit 403 because its caller has
        # already proven identity.
        raise InvalidCredentials("account disabled")

    if user.locked_until is not None and user.locked_until > now:
        remaining = int((user.locked_until - now).total_seconds())
        audit.record(
            session,
            actor_username=user.username,
            actor_id=user.id,
            actor_role=user.role.value,
            action="auth.login",
            outcome=AuditOutcome.DENIED,
            target="locked_account",
            source_ip=source_ip,
        )
        _persist_security_state(session)
        raise AccountLocked(remaining, "account locked")

    if not verify_password(user.password_hash, password):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.lockout_threshold:
            user.locked_until = now + timedelta(seconds=settings.backoff_for(user.failed_attempts))
        audit.record(
            session,
            actor_username=user.username,
            actor_id=user.id,
            actor_role=user.role.value,
            action="auth.login",
            outcome=AuditOutcome.DENIED,
            target="bad_password",
            source_ip=source_ip,
        )
        _persist_security_state(session)
        raise InvalidCredentials("bad password")

    if needs_rehash(user.password_hash):
        # Cost parameters were raised since this password was last set.
        user.password_hash = hash_password(password)

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now

    issued = _issue_session(session, user=user, family_id=uuid.uuid4())
    audit.record(
        session,
        actor_username=user.username,
        actor_id=user.id,
        actor_role=user.role.value,
        action="auth.login",
        outcome=AuditOutcome.OK,
        source_ip=source_ip,
    )
    session.flush()
    return issued


def refresh_session(
    session: Session, *, raw_refresh_token: str, source_ip: str | None = None
) -> IssuedSession:
    """Rotate a refresh token. Reuse of a spent token kills its whole family."""
    now = utc_now()
    stored = session.scalars(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw_refresh_token))
    ).first()

    if stored is None:
        raise InvalidToken("unknown refresh token")

    if stored.used_at is not None or stored.revoked_at is not None:
        # Either replay of a rotated token or use of a revoked one: assume theft.
        revoke_family(session, stored.family_id, now=now)
        audit.record(
            session,
            actor_username=stored.user.username,
            actor_id=stored.user_id,
            actor_role=stored.user.role.value,
            action="auth.refresh",
            outcome=AuditOutcome.DENIED,
            target="token_reuse",
            source_ip=source_ip,
        )
        _persist_security_state(session)
        raise TokenReuseDetected("refresh token replayed")

    if stored.expires_at <= now:
        raise InvalidToken("expired refresh token")

    user = stored.user
    if user.disabled:
        revoke_family(session, stored.family_id, now=now)
        _persist_security_state(session)
        raise AccountDisabled("account disabled")

    stored.used_at = now
    issued = _issue_session(session, user=user, family_id=stored.family_id)
    audit.record(
        session,
        actor_username=user.username,
        actor_id=user.id,
        actor_role=user.role.value,
        action="auth.refresh",
        outcome=AuditOutcome.OK,
        source_ip=source_ip,
    )
    session.flush()
    return issued


def logout(session: Session, *, raw_refresh_token: str, source_ip: str | None = None) -> None:
    """Revoke the presented token's family. Unknown tokens are a silent no-op."""
    now = utc_now()
    stored = session.scalars(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw_refresh_token))
    ).first()
    if stored is None:
        return
    revoke_family(session, stored.family_id, now=now)
    audit.record(
        session,
        actor_username=stored.user.username,
        actor_id=stored.user_id,
        actor_role=stored.user.role.value,
        action="auth.logout",
        outcome=AuditOutcome.OK,
        source_ip=source_ip,
    )
    session.flush()


def change_password(
    session: Session,
    *,
    user: User,
    current_password: str,
    new_password: str,
    source_ip: str | None = None,
) -> None:
    """Change one's own password and revoke every other open session."""
    if not verify_password(user.password_hash, current_password):
        audit.record(
            session,
            actor_username=user.username,
            actor_id=user.id,
            actor_role=user.role.value,
            action="auth.password_change",
            outcome=AuditOutcome.DENIED,
            source_ip=source_ip,
        )
        _persist_security_state(session)
        raise InvalidCredentials("current password mismatch")

    validate_password_policy(new_password)
    changed_at = utc_now()
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    # Stamp BEFORE revoking so no window exists where the refresh family is gone
    # but outstanding access tokens are still honoured.
    user.password_changed_at = changed_at
    revoke_all_sessions(session, user_id=user.id, now=changed_at)
    audit.record(
        session,
        actor_username=user.username,
        actor_id=user.id,
        actor_role=user.role.value,
        action="auth.password_change",
        outcome=AuditOutcome.OK,
        source_ip=source_ip,
    )
    session.flush()


def revoke_family(session: Session, family_id: uuid.UUID, *, now: datetime | None = None) -> None:
    """Revoke every still-live token of one login family."""
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or utc_now())
        # "fetch" keeps already-loaded RefreshToken instances consistent with
        # the rows we just rewrote; without it, callers read stale state.
        .execution_options(synchronize_session="fetch")
    )


def revoke_all_sessions(
    session: Session, *, user_id: uuid.UUID, now: datetime | None = None
) -> None:
    """Revoke every live token of a user, across all login families."""
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or utc_now())
        .execution_options(synchronize_session="fetch")
    )


def _issue_session(session: Session, *, user: User, family_id: uuid.UUID) -> IssuedSession:
    settings = get_settings()
    now = utc_now()
    access_token, expires_in = issue_access_token(
        user_id=user.id, username=user.username, role=user.role
    )
    raw_refresh = generate_refresh_token()
    session.add(
        RefreshToken(
            token_hash=hash_refresh_token(raw_refresh),
            family_id=family_id,
            user_id=user.id,
            issued_at=now,
            expires_at=now + timedelta(seconds=settings.refresh_token_ttl_seconds),
        )
    )
    return IssuedSession(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=raw_refresh,
        refresh_expires_in=settings.refresh_token_ttl_seconds,
        user=user,
    )
