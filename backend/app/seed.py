"""Seed the three demo accounts.

Development convenience only. It refuses to run against a production
configuration, takes every password from the environment (no defaults, ever),
and marks each account so the operator MUST change the password on first login.

    DIOPTRA_ENV=dev DIOPTRA_SEED_PASSWORD_AMEDINA=... uv run python -m app.seed
"""

from __future__ import annotations

import logging
import os
import sys

from sqlalchemy.orm import Session

from app.auth.models import Role
from app.auth.service import create_user, get_user_by_username
from app.core.config import get_settings
from app.db.session import get_session_factory

logger = logging.getLogger("dioptra.seed")

SEED_ACCOUNTS = (
    ("amedina", "Ana Medina", Role.ADMIN),
    ("mmarin", "Moises Marin", Role.ANALYST),
    ("cperez", "Carla Perez", Role.DEVELOPER),
)


class SeedRefused(RuntimeError):
    """The environment does not allow seeding."""


def seed(session: Session) -> list[str]:
    """Create any missing seed account. Returns the usernames created."""
    settings = get_settings()
    if settings.env == "prod":
        message = "seeding is disabled in production; create the first admin manually"
        raise SeedRefused(message)

    created: list[str] = []
    for username, display_name, role in SEED_ACCOUNTS:
        if get_user_by_username(session, username) is not None:
            continue
        password = os.environ.get(f"DIOPTRA_SEED_PASSWORD_{username.upper()}")
        if not password:
            message = f"DIOPTRA_SEED_PASSWORD_{username.upper()} is not set; refusing to invent one"
            raise SeedRefused(message)
        create_user(
            session,
            username=username,
            display_name=display_name,
            role=role,
            password=password,
            must_change_password=True,
        )
        created.append(username)
    session.commit()
    return created


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    session = get_session_factory()()
    try:
        created = seed(session)
    except SeedRefused as exc:
        logger.error("seed refused: %s", exc)
        return 1
    finally:
        session.close()

    logger.info("created: %s", ", ".join(created) if created else "nothing (already seeded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
