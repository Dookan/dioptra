"""Account administration: the admin's half of the permission matrix.

Design: ``tasks/phase6-survey.md``. Every mutation writes exactly ONE audit
row and none of them ever logs, stores or returns a password. Every mutation
but ``create_account`` carries a written justification (CLAUDE.md → Hard
Rules → Auth, and its one exception for account creation).

No account is ever deleted: the audit log names actors by username, and a
deletion would orphan the trail. Disabling is the only removal.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.audit.models import AuditOutcome
from app.auth.errors import (
    CannotAdministerSelf,
    EmailTaken,
    Forbidden,
    RoleUnchanged,
    StatusUnchanged,
    UsernameTaken,
    UserNotFound,
)
from app.auth.models import Role, User
from app.auth.passwords import hash_password
from app.auth.service import create_user, get_user_by_username, revoke_all_sessions
from app.core.clock import utc_now
from app.core.text import clean_justification, strip_control_chars


def list_accounts(db: Session) -> Sequence[User]:
    return db.scalars(select(User).order_by(User.username)).all()


def _normalise_email(email: str | None) -> str | None:
    """One mailbox, one row: the unique constraint is case-sensitive, mail is not."""
    if email is None:
        return None
    cleaned = strip_control_chars(email).strip().lower()
    return cleaned or None


def _record(
    db: Session,
    *,
    actor: User,
    action: str,
    target: str,
    justification: str | None,
    source_ip: str | None,
    outcome: AuditOutcome = AuditOutcome.OK,
) -> None:
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action=action,
        outcome=outcome,
        target=target,
        justification=justification,
        source_ip=source_ip,
    )


def create_account(
    db: Session,
    *,
    actor: User,
    username: str,
    display_name: str,
    role: Role,
    password: str,
    email: str | None,
    source_ip: str | None,
) -> User:
    """Create an account that must change its password at first login.

    No written justification, by ``mmarin``'s recorded exception: the row states
    who created which username with which role.
    """
    normalised = username.strip().lower()
    name = " ".join(strip_control_chars(display_name).split())
    address = _normalise_email(email)
    # Read first for a typed answer; the IntegrityError below covers the race
    # of two admins creating the same account at once.
    if get_user_by_username(db, normalised) is not None:
        raise UsernameTaken(f"username {normalised!r} exists")
    if address is not None and db.scalar(select(User.id).where(User.email == address)):
        raise EmailTaken("email exists")
    try:
        user = create_user(
            db,
            username=normalised,
            display_name=name,
            role=role,
            password=password,
            email=address,
            must_change_password=True,
        )
    except IntegrityError as error:
        # Nothing else was written in this request before the insert, so a
        # rollback loses nothing; the re-read then says which one collided.
        db.rollback()
        if get_user_by_username(db, normalised) is not None:
            raise UsernameTaken(f"username {normalised!r} exists") from error
        raise EmailTaken("email exists") from error
    _record(
        db,
        actor=actor,
        action="user.create",
        target=f"{user.username} role={user.role.value}",
        justification=None,
        source_ip=source_ip,
    )
    return user


def _target(db: Session, *, actor: User, user_id: uuid.UUID) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise UserNotFound(str(user_id))
    if target.id == actor.id:
        raise CannotAdministerSelf("an admin may not administer their own account")
    return target


def _guard_admins(db: Session, *, actor: User, target: User, source_ip: str | None) -> None:
    """Refuse a change that could leave the factory with no enabled admin.

    Sequentially this cannot fire — the actor is an enabled admin and may not
    act on themselves — so its real job is the RACE of two admins acting on
    each other at once (survey §2). Every enabled admin row is locked in id
    order, and the actor is re-checked: the request that lost the race finds
    its actor no longer an admin and is refused. ``populate_existing`` matters:
    without it a locking SELECT does not refresh objects already in the
    session, and the checks would read values from before the wait.
    """
    admins = db.scalars(
        select(User)
        .where(User.role == Role.ADMIN, User.disabled.is_(False))
        .order_by(User.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).all()
    db.refresh(target, with_for_update=True)
    if actor.id not in {admin.id for admin in admins}:
        # A privileged action refused mid-flight is the event the trail exists
        # for; recorded and committed before raising, as require_roles does.
        _record(
            db,
            actor=actor,
            action="authz.denied",
            target=f"user {target.username}: actor no longer an enabled admin",
            justification=None,
            source_ip=source_ip,
            outcome=AuditOutcome.DENIED,
        )
        db.commit()
        raise Forbidden("the actor lost the admin role while the request waited")
    # No separate "last admin" count: the actor is an enabled admin (just
    # re-checked under the lock) and is never the target, so the actor always
    # remains. A count here could never fire — the re-check above IS the
    # last-admin guard (found while writing its test; survey §2 addendum).


def change_role(
    db: Session,
    *,
    actor: User,
    user_id: uuid.UUID,
    role: Role,
    justification: str,
    source_ip: str | None,
) -> User:
    """Change a role. The target's refresh tokens are kept on purpose: their
    next access token is refused for role drift, and the refresh mints one with
    the new role (survey §3)."""
    reason = clean_justification(justification)
    target = _target(db, actor=actor, user_id=user_id)
    if target.role is Role.ADMIN and not target.disabled:
        _guard_admins(db, actor=actor, target=target, source_ip=source_ip)
    if target.role is role:
        raise RoleUnchanged(f"{target.username} already has role {role.value}")
    old = target.role
    target.role = role
    _record(
        db,
        actor=actor,
        action="user.role.change",
        target=f"{target.username} {old.value}→{role.value}",
        justification=reason,
        source_ip=source_ip,
    )
    db.flush()
    return target


def set_disabled(
    db: Session,
    *,
    actor: User,
    user_id: uuid.UUID,
    disabled: bool,
    justification: str,
    source_ip: str | None,
) -> User:
    """Disable (every session revoked) or enable an account."""
    reason = clean_justification(justification)
    target = _target(db, actor=actor, user_id=user_id)
    if disabled and target.role is Role.ADMIN and not target.disabled:
        _guard_admins(db, actor=actor, target=target, source_ip=source_ip)
    if target.disabled is disabled:
        raise StatusUnchanged(f"{target.username} already disabled={disabled}")
    target.disabled = disabled
    if disabled:
        revoke_all_sessions(db, user_id=target.id)
    _record(
        db,
        actor=actor,
        action="user.disable" if disabled else "user.enable",
        target=target.username,
        justification=reason,
        source_ip=source_ip,
    )
    db.flush()
    return target


def reset_password(
    db: Session,
    *,
    actor: User,
    user_id: uuid.UUID,
    password: str,
    justification: str,
    source_ip: str | None,
) -> User:
    """Set a new password the account must change at its next login.

    Also clears the lockout: the row shows "bloqueada hasta …" and a reset is
    the admin's only lever on it, so leaving the lock would make the new
    password unusable until the backoff ran out (survey §6.5).
    """
    reason = clean_justification(justification)
    target = _target(db, actor=actor, user_id=user_id)
    now = utc_now()
    target.password_hash = hash_password(password)
    target.must_change_password = True
    # Stamped BEFORE revoking, as change_password does: no window in which the
    # refresh family is gone but an outstanding access token is still honoured.
    target.password_changed_at = now
    target.failed_attempts = 0
    target.locked_until = None
    revoke_all_sessions(db, user_id=target.id, now=now)
    _record(
        db,
        actor=actor,
        action="user.password.reset",
        target=target.username,
        justification=reason,
        source_ip=source_ip,
    )
    db.flush()
    return target


def enabled_admin_count(db: Session) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.ADMIN, User.disabled.is_(False))
        )
        or 0
    )
