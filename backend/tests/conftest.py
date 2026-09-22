"""Test harness.

The suite runs against SQLite in memory with foreign keys and the append-only
triggers enabled, so the invariants exercised here are the ones the database
enforces in production too.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("DIOPTRA_ENV", "test")
os.environ.setdefault("DIOPTRA_JWT_SECRET", "test-secret-please-do-not-use-in-production")
os.environ.setdefault("DIOPTRA_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("DIOPTRA_REFRESH_COOKIE_SECURE", "false")
# Phase 1: jobs run inline, tools on the host (none installed → coverage gaps),
# jails under a throwaway directory. No broker, no daemon, no network.
os.environ.setdefault("DIOPTRA_QUEUE_INLINE", "true")
os.environ.setdefault("DIOPTRA_RUNNER_MODE", "local")
os.environ.setdefault("DIOPTRA_WORKSPACE_ROOT", tempfile.mkdtemp(prefix="dioptra-test-ws-"))
# Our own rules live in the repository; an empty OSV directory makes the
# runner "available" so its (fixture or absent) execution is exercised.
os.environ.setdefault("DIOPTRA_RULES_DIR", str(Path(__file__).resolve().parents[2] / "rules"))
os.environ.setdefault("DIOPTRA_OSV_DB_DIR", tempfile.mkdtemp(prefix="dioptra-test-osv-"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Engine, create_engine, event  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.auth.models import Role, User  # noqa: E402
from app.auth.service import create_user  # noqa: E402
from app.db.registry import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import create_app  # noqa: E402

SEED_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def engine() -> Iterator[Engine]:
    """One in-memory database per test, shared by every session in that test."""
    test_engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )

    @event.listens_for(test_engine, "connect")
    def _enable_sqlite_constraints(dbapi_connection: Any, _record: Any) -> None:
        # SQLite ignores foreign keys unless asked; without this, cascade and
        # integrity tests would pass for the wrong reason.
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(test_engine)
    yield test_engine
    test_engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def db(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def app(session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    application = create_app()
    # The inline pipeline opens its own session, exactly like the worker does.
    monkeypatch.setattr("app.analysis.pipeline.get_session_factory", lambda: session_factory)

    def override_get_db() -> Iterator[Session]:
        session = session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    application.dependency_overrides[get_db] = override_get_db
    return application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def analyst(db: Session) -> User:
    user = create_user(
        db,
        username="mmarin",
        display_name="Moises Marin",
        role=Role.ANALYST,
        password=SEED_PASSWORD,
        must_change_password=False,
    )
    db.commit()
    return user


@pytest.fixture
def developer(db: Session) -> User:
    user = create_user(
        db,
        username="cperez",
        display_name="Carla Perez",
        role=Role.DEVELOPER,
        password=SEED_PASSWORD,
        must_change_password=False,
    )
    db.commit()
    return user


@pytest.fixture
def admin(db: Session) -> User:
    user = create_user(
        db,
        username="amedina",
        display_name="Ana Medina",
        role=Role.ADMIN,
        password=SEED_PASSWORD,
        must_change_password=False,
    )
    db.commit()
    return user
