"""Create the FIRST admin of an installation — the one account no admin can create.

    DIOPTRA_BOOTSTRAP_PASSWORD=... python -m app.auth.bootstrap <username> "<display name>"

Every account-administration endpoint requires an admin, and ``app.seed``
refuses production, so before this command the only way to start a real
deployment was a Python snippet that wrote no audit row
(``tasks/phase6-survey.md`` §6.1). It:

- refuses when any ENABLED admin exists — it is the way in, and the way back
  if every admin was ever disabled, never a second door beside the platform;
- works under ``DIOPTRA_ENV=prod``, which is its point;
- takes the password from the environment only, never an argument (argv is
  visible in ``ps``) — the operator guide says to unset it afterwards;
- creates the account with ``must_change_password = True`` and writes
  ``user.create`` with the platform's own actor, ``system``, which no account
  may be called (``RESERVED_USERNAMES``).
"""

from __future__ import annotations

import logging
import os
import sys

from sqlalchemy.orm import Session

from app.audit import service as audit
from app.auth.admin import enabled_admin_count
from app.auth.errors import AuthError
from app.auth.models import SYSTEM_ACTOR, Role
from app.auth.service import create_user, get_user_by_username
from app.core.text import strip_control_chars
from app.db.session import get_session_factory

logger = logging.getLogger("dioptra.bootstrap")

PASSWORD_VARIABLE = "DIOPTRA_BOOTSTRAP_PASSWORD"  # noqa: S105 - a variable NAME


class BootstrapRefused(RuntimeError):
    """The installation already has an admin, or the input is unusable."""


def bootstrap(session: Session, *, username: str, display_name: str, password: str) -> str:
    """Create the first admin and return its username, or raise."""
    if enabled_admin_count(session) > 0:
        message = "an enabled admin already exists; create accounts from the platform"
        raise BootstrapRefused(message)
    normalised = username.strip().lower()
    if get_user_by_username(session, normalised) is not None:
        # A disabled account under that name: re-enabling it is another admin's
        # decision to take on the record, not something this command guesses.
        message = f"an account named {normalised!r} already exists; choose another username"
        raise BootstrapRefused(message)
    user = create_user(
        session,
        username=normalised,
        display_name=" ".join(strip_control_chars(display_name).split())[:120],
        role=Role.ADMIN,
        password=password,
        must_change_password=True,
    )
    audit.record(
        session,
        actor_username=SYSTEM_ACTOR,
        action="user.create",
        target=f"{user.username} role={Role.ADMIN.value} (bootstrap)",
    )
    session.commit()
    return user.username


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:  # noqa: PLR2004 - username and display name
        logger.error('usage: python -m app.auth.bootstrap <username> "<display name>"')
        return 2
    password = os.environ.get(PASSWORD_VARIABLE, "")
    if not password:
        logger.error("%s is not set; refusing to invent a password", PASSWORD_VARIABLE)
        return 1
    session = get_session_factory()()
    try:
        created = bootstrap(session, username=args[0], display_name=args[1], password=password)
    except (BootstrapRefused, AuthError) as error:
        session.rollback()
        # AuthError's detail names the rule (convention, length), never the password.
        logger.error("bootstrap refused: %s", error)
        return 1
    finally:
        session.close()
    logger.info("created admin %s; it must change its password at first login", created)
    logger.info("unset %s now", PASSWORD_VARIABLE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
