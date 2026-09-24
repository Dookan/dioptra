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
# P4: the E7 attempt directories. A real sandbox run is opt-in (marker
# `sandbox`); everything else uses a fake executor and never starts a container.
os.environ.setdefault("DIOPTRA_SANDBOX_RUNS_ROOT", tempfile.mkdtemp(prefix="dioptra-test-runs-"))
# P5: where an uploaded vulnerability dump waits for the (inline) import job.
# The sync job itself never reaches the network here: every test that runs it
# replaces `app.inventory.sync.download` with a fixture writer.
os.environ.setdefault("DIOPTRA_VULNDB_SPOOL_DIR", tempfile.mkdtemp(prefix="dioptra-test-vulndb-"))
# Phase 8: where a finished PDF waits for its requester.
os.environ.setdefault("DIOPTRA_REPORT_SPOOL_DIR", tempfile.mkdtemp(prefix="dioptra-test-reports-"))

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
    # The E7 verification job opens its own session too, like the worker does.
    monkeypatch.setattr("app.workflow.verify_job.get_session_factory", lambda: session_factory)
    # The inventory's sync and import jobs do the same (P5).
    monkeypatch.setattr("app.inventory.sync.get_session_factory", lambda: session_factory)
    # And the asynchronous PDF export (phase 8).
    monkeypatch.setattr("app.reports.jobs.get_session_factory", lambda: session_factory)
    # The start-up sweep imports the factory lazily from its home module.
    monkeypatch.setattr("app.db.session.get_session_factory", lambda: session_factory)

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


def _image_built(image: str) -> bool:
    import shutil
    import subprocess

    if shutil.which("docker") is None:
        return False
    docker = shutil.which("docker") or "docker"
    probe = subprocess.run(  # noqa: S603 — fixed argv, resolved binary
        [docker, "image", "inspect", image],
        capture_output=True,
        check=False,
        timeout=60,
    )
    return probe.returncode == 0


@pytest.fixture
def sandbox_available() -> bool:
    """Whether a real E7 run can happen here: Docker present and the image built."""
    from app.core.config import get_settings

    return _image_built(get_settings().sandbox_image)


@pytest.fixture
def php_sandbox_available() -> bool:
    """The same question for the PHP image — one image per language (phase 7a)."""
    from app.core.config import get_settings

    return _image_built(get_settings().sandbox_image_php)
