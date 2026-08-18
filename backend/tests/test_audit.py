"""The audit trail is append-only and records every security-relevant action."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth.models import User
from tests.conftest import SEED_PASSWORD


def test_record_appends_an_entry(db: Session, analyst: User) -> None:
    entry = audit.record(
        db,
        actor_username=analyst.username,
        actor_id=analyst.id,
        actor_role=analyst.role.value,
        action="report.sign",
        target="report:42",
        justification="Revisado y conforme",
    )
    db.commit()

    stored = db.get(AuditLogEntry, entry.id)
    assert stored is not None
    assert stored.outcome is AuditOutcome.OK
    assert stored.justification == "Revisado y conforme"
    assert stored.occurred_at.tzinfo is not None


def test_fit_truncates_to_the_column_width_and_preserves_none() -> None:
    assert audit._fit(None, 255) is None
    assert audit._fit("short", 255) == "short"
    assert len(audit._fit("x" * 300, 255) or "") == 255


def test_an_over_long_target_is_truncated_rather_than_lost(db: Session, analyst: User) -> None:
    """A hostile request path must not be able to break the trail.

    `deps.py` writes "<METHOD> <path>" into `target`, so the length is attacker
    controlled. Un-truncated, the driver raises a DataError inside the dependency:
    the 403 denial becomes a 500 AND the row recording that denial is lost.

    Asserted directly on the returned entry, not via a round-trip — the suite runs
    on in-memory SQLite, which ignores VARCHAR(n), so a stored-then-read check
    would pass just as happily with no truncation at all.
    """
    entry = audit.record(
        db,
        actor_username="a" * 100,
        actor_role="analyst-with-an-absurdly-long-role-name",
        action="x" * 200,
        target="GET /api/v1/" + "p" * 400,
        source_ip="s" * 80,
    )
    db.commit()

    assert len(entry.actor_username) == 64
    assert len(entry.action) == 64
    assert entry.target is not None and len(entry.target) == 255
    assert entry.actor_role is not None and len(entry.actor_role) == 16
    assert entry.source_ip is not None and len(entry.source_ip) == 45
    # Truncation keeps the front of the value, where the useful signal is.
    assert entry.target.startswith("GET /api/v1/")


def test_entries_cannot_be_updated(db: Session, analyst: User) -> None:
    entry = audit.record(db, actor_username=analyst.username, action="report.sign")
    db.commit()

    with pytest.raises(DatabaseError):
        db.execute(
            update(AuditLogEntry).where(AuditLogEntry.id == entry.id).values(action="report.unsign")
        )
    db.rollback()
    assert db.get(AuditLogEntry, entry.id) is not None


def test_entries_cannot_be_deleted(db: Session, analyst: User) -> None:
    entry = audit.record(db, actor_username=analyst.username, action="report.sign")
    db.commit()

    with pytest.raises(DatabaseError):
        db.execute(delete(AuditLogEntry).where(AuditLogEntry.id == entry.id))
    db.rollback()
    assert db.get(AuditLogEntry, entry.id) is not None


def test_the_module_exposes_no_way_to_rewrite_history() -> None:
    """A future contributor must not find a convenient update/delete helper."""
    exported = {name for name in dir(audit) if not name.startswith("_")}
    assert not {name for name in exported if "delete" in name or "update" in name}


def test_a_successful_login_is_recorded(client: TestClient, db: Session, analyst: User) -> None:
    client.post("/api/v1/auth/login", json={"username": "mmarin", "password": SEED_PASSWORD})

    entry = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "auth.login")).one()
    assert entry.outcome is AuditOutcome.OK
    assert entry.actor_username == "mmarin"
    assert entry.actor_role == "analyst"


def test_a_failed_login_is_recorded_with_the_attempted_username(
    client: TestClient, db: Session
) -> None:
    client.post("/api/v1/auth/login", json={"username": "intruder", "password": "guessing"})

    entry = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "auth.login")).one()
    assert entry.outcome is AuditOutcome.DENIED
    assert entry.actor_username == "intruder"
    assert entry.target == "unknown_user"


def test_a_disabled_account_login_records_the_real_reason(
    client: TestClient, db: Session, analyst: User
) -> None:
    """The response is flattened to invalid_credentials; the TRAIL is not.

    Hiding the reason from an unauthenticated caller must not hide it from the
    auditor — otherwise the anti-enumeration fix would have cost us the ability
    to see that someone is probing a disabled account.
    """
    analyst.disabled = True
    db.commit()

    response = client.post(
        "/api/v1/auth/login", json={"username": "mmarin", "password": SEED_PASSWORD}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"

    entries = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "auth.login")).all()
    assert [entry.target for entry in entries] == ["disabled_account"]
    assert entries[0].outcome is AuditOutcome.DENIED


def test_the_trail_never_stores_the_submitted_password(
    client: TestClient, db: Session, analyst: User
) -> None:
    client.post("/api/v1/auth/login", json={"username": "mmarin", "password": "a-secret-guess"})

    for entry in db.scalars(select(AuditLogEntry)):
        assert "a-secret-guess" not in str(entry.__dict__.values())


def test_reading_back_one_actors_trail(db: Session, analyst: User) -> None:
    audit.record(db, actor_username="mmarin", action="auth.login")
    audit.record(db, actor_username="cperez", action="auth.login")
    db.commit()

    entries = audit.entries_for_actor(db, "mmarin")

    assert [entry.actor_username for entry in entries] == ["mmarin"]
