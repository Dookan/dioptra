"""Engine and request-scoped session.

Sessions are synchronous on purpose: Argon2id verification is CPU-bound and
FastAPI already runs ``def`` endpoints in a worker thread, so an async driver
would buy nothing and cost strictness.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Process-wide engine."""
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,  # a recycled Postgres connection must not surface as a 500
        future=True,
    )


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding one transactional session per request."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
