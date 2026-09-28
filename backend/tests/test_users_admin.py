"""Account administration (phase 6): ``/api/v1/users`` and ``app.auth.admin``.

Every authorization rule here is proven against the API directly, with no UI
in the loop (tasks/phase6-user-administration.md → Constraints).
"""

from __future__ import annotations

import logging
import socket
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth import admin as admin_service
from app.auth import bootstrap as bootstrap_module
from app.auth.errors import Forbidden, InvalidUsername, RoleUnchanged, UsernameTaken
from app.auth.models import RESERVED_USERNAMES, Role, User
from app.auth.service import create_user
from app.core.clock import utc_now
from app.core.config import Settings
from app.inventory import sync
from app.notify.mailer import NullMailer, get_mailer
from tests.conftest import SEED_PASSWORD

REASON = "Cambio pedido por la jefatura del proyecto"
NEW_PASSWORD = "otra-clave-bastante-larga"


def _login(client: TestClient, username: str, password: str = SEED_PASSWORD) -> str:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    token: str = response.json()["access_token"]
    return token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _rows(db: Session, action: str) -> list[AuditLogEntry]:
    db.expire_all()
    return list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == action)))


def _user(db: Session, username: str) -> User:
    db.expire_all()
    found = db.scalar(select(User).where(User.username == username))
    assert found is not None
    return found


@pytest.fixture
def second_admin(db: Session) -> User:
    user = create_user(
        db,
        username="srosales",
        display_name="Saile Rosales",
        role=Role.ADMIN,
        password=SEED_PASSWORD,
        must_change_password=False,
    )
    db.commit()
    return user


@pytest.fixture
def admin_token(client: TestClient, admin: User) -> str:
    return _login(client, admin.username)


@pytest.fixture
def other_client(app: FastAPI) -> Iterator[TestClient]:
    """A second browser: its own cookie jar, so the target keeps its own session."""
    with TestClient(app, raise_server_exceptions=False) as second:
        yield second


# --- deny by default ---------------------------------------------------------


def _endpoints(target_id: str) -> list[tuple[str, str, dict[str, Any] | None]]:
    return [
        ("GET", "/api/v1/users", None),
        (
            "POST",
            "/api/v1/users",
            {
                "username": "jrivas",
                "display_name": "J R",
                "role": "analyst",
                "password": NEW_PASSWORD,
            },
        ),
        ("PATCH", f"/api/v1/users/{target_id}/role", {"role": "analyst", "justification": REASON}),
        ("PATCH", f"/api/v1/users/{target_id}/status", {"disabled": True, "justification": REASON}),
        (
            "POST",
            f"/api/v1/users/{target_id}/password-reset",
            {"password": NEW_PASSWORD, "justification": REASON},
        ),
    ]


@pytest.mark.parametrize("index", range(5))
@pytest.mark.parametrize("role_fixture", ["analyst", "developer"])
def test_every_endpoint_refuses_a_non_admin_and_records_it(
    client: TestClient,
    db: Session,
    admin: User,
    role_fixture: str,
    index: int,
    request: pytest.FixtureRequest,
) -> None:
    caller: User = request.getfixturevalue(role_fixture)
    token = _login(client, caller.username)
    method, path, body = _endpoints(str(admin.id))[index]
    response = client.request(method, path, json=body, headers=_auth(token))
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"
    denied = _rows(db, "authz.denied")
    assert [(row.actor_username, row.target) for row in denied] == [
        (caller.username, f"{method} {path}")
    ]
    # Nothing moved: the admin is still an enabled admin, no account was created.
    assert _user(db, admin.username).role is Role.ADMIN
    assert not _user(db, admin.username).disabled
    assert db.scalar(select(User).where(User.username == "jrivas")) is None


@pytest.mark.parametrize("index", range(5))
def test_every_endpoint_refuses_an_anonymous_caller(
    client: TestClient, admin: User, index: int
) -> None:
    method, path, body = _endpoints(str(admin.id))[index]
    response = client.request(method, path, json=body)
    assert response.status_code == 401


def test_an_admin_with_a_pending_password_change_is_refused(
    client: TestClient, db: Session, admin: User
) -> None:
    token = _login(client, admin.username)
    admin.must_change_password = True
    db.commit()
    response = client.get("/api/v1/users", headers=_auth(token))
    assert response.status_code == 409
    assert response.json()["code"] == "password_change_required"


# --- list ---------------------------------------------------------------------


def test_the_list_is_ordered_and_carries_no_secret(
    client: TestClient, admin_token: str, analyst: User, developer: User
) -> None:
    response = client.get("/api/v1/users", headers=_auth(admin_token))
    assert response.status_code == 200
    body = response.json()
    assert [row["username"] for row in body] == ["amedina", "cperez", "mmarin"]
    for row in body:
        assert set(row) == {
            "id",
            "username",
            "display_name",
            "email",
            "role",
            "disabled",
            "must_change_password",
            "last_login_at",
            "locked_until",
            "created_at",
        }
    assert "password_hash" not in response.text
    assert "$argon2" not in response.text
    assert "failed_attempts" not in response.text


# --- create ---------------------------------------------------------------------


def test_an_account_is_created_with_a_forced_password_change(
    client: TestClient, other_client: TestClient, db: Session, admin: User, admin_token: str
) -> None:
    response = client.post(
        "/api/v1/users",
        json={
            "username": " JRivas ",
            "display_name": "Juan\x07  Rivas",
            "email": " J.Rivas@Example.ORG ",
            "role": "analyst",
            "password": NEW_PASSWORD,
        },
        headers=_auth(admin_token),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["username"] == "jrivas"
    assert body["display_name"] == "Juan Rivas"
    assert body["email"] == "j.rivas@example.org"
    assert body["role"] == "analyst"
    assert body["must_change_password"] is True
    assert body["last_login_at"] is None
    assert NEW_PASSWORD not in response.text

    (row,) = _rows(db, "user.create")
    assert row.actor_username == admin.username
    assert row.actor_id == admin.id
    assert row.actor_role == "admin"
    assert row.target == "jrivas role=analyst"
    assert row.source_ip == "testclient"
    assert row.justification is None  # the Hard Rule's recorded exception
    assert row.outcome is AuditOutcome.OK

    # The new account logs in and can reach nothing until it changes the password.
    token = _login(other_client, "jrivas", NEW_PASSWORD)
    blocked = other_client.get("/api/v1/projects", headers=_auth(token))
    assert blocked.status_code == 409
    assert blocked.json()["code"] == "password_change_required"


@pytest.mark.parametrize("username", ["M.Marin", "am", "2marin", "system", "SYSTEM"])
def test_a_username_outside_the_convention_or_reserved_is_refused(
    client: TestClient, db: Session, admin_token: str, username: str
) -> None:
    response = client.post(
        "/api/v1/users",
        json={
            "username": username,
            "display_name": "X",
            "role": "analyst",
            "password": NEW_PASSWORD,
        },
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "invalid_username"
    assert _rows(db, "user.create") == []


@pytest.mark.parametrize("raw", ["system", " SYSTEM "])
def test_the_platform_actor_is_a_reserved_username(db: Session, raw: str) -> None:
    """Pinned on the service itself, not only on its callers that lower-case."""
    assert sync.SYSTEM_ACTOR in RESERVED_USERNAMES
    with pytest.raises(InvalidUsername):
        create_user(db, username=raw, display_name="S", role=Role.ADMIN, password=NEW_PASSWORD)


@pytest.mark.parametrize("role", ["admin", "analyst", "developer"])
def test_the_account_is_created_with_the_role_asked_for(
    client: TestClient, db: Session, admin_token: str, role: str
) -> None:
    response = client.post(
        "/api/v1/users",
        json={"username": "jrivas", "display_name": "J", "role": role, "password": NEW_PASSWORD},
        headers=_auth(admin_token),
    )
    assert response.status_code == 201
    assert response.json()["role"] == role
    assert _user(db, "jrivas").role is Role(role)


def test_the_justification_error_is_one_class_wherever_it_is_imported() -> None:
    from app.core import errors as core_errors  # noqa: PLC0415
    from app.workflow import errors as workflow_errors  # noqa: PLC0415

    assert workflow_errors.JustificationRequired is core_errors.JustificationRequired


def test_a_short_password_is_refused(client: TestClient, admin_token: str) -> None:
    response = client.post(
        "/api/v1/users",
        json={"username": "jrivas", "display_name": "J", "role": "analyst", "password": "corta"},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "weak_password"


def test_a_taken_username_is_a_conflict(
    client: TestClient, db: Session, admin_token: str, analyst: User
) -> None:
    response = client.post(
        "/api/v1/users",
        json={
            "username": "MMarin",
            "display_name": "Otro",
            "role": "developer",
            "password": NEW_PASSWORD,
        },
        headers=_auth(admin_token),
    )
    assert response.status_code == 409
    assert response.json()["code"] == "username_taken"
    assert _user(db, "mmarin").role is Role.ANALYST


def test_a_taken_email_is_a_conflict_whatever_its_case(
    client: TestClient, db: Session, admin_token: str
) -> None:
    first = client.post(
        "/api/v1/users",
        json={
            "username": "jrivas",
            "display_name": "J",
            "email": "rivas@example.org",
            "role": "analyst",
            "password": NEW_PASSWORD,
        },
        headers=_auth(admin_token),
    )
    assert first.status_code == 201
    second = client.post(
        "/api/v1/users",
        json={
            "username": "lrivas",
            "display_name": "L",
            "email": "RIVAS@example.org",
            "role": "analyst",
            "password": NEW_PASSWORD,
        },
        headers=_auth(admin_token),
    )
    assert second.status_code == 409
    assert second.json()["code"] == "email_taken"
    assert db.scalar(select(User).where(User.username == "lrivas")) is None


def test_two_different_emails_are_two_accounts(client: TestClient, admin_token: str) -> None:
    for username, email in (("jrivas", "rivas@example.org"), ("lrivas", "lrivas@example.org")):
        response = client.post(
            "/api/v1/users",
            json={
                "username": username,
                "display_name": "R",
                "email": email,
                "role": "analyst",
                "password": NEW_PASSWORD,
            },
            headers=_auth(admin_token),
        )
        assert response.status_code == 201, response.text


def test_the_integrity_race_still_answers_with_a_typed_conflict(
    db: Session, admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Another admin created the same username between the read and the insert.
    monkeypatch.setattr(admin_service, "get_user_by_username", _first_none_then_real())
    create_user(db, username="jrivas", display_name="J", role=Role.ANALYST, password=NEW_PASSWORD)
    db.commit()
    with pytest.raises(UsernameTaken):
        admin_service.create_account(
            db,
            actor=admin,
            username="jrivas",
            display_name="J",
            role=Role.ANALYST,
            password=NEW_PASSWORD,
            email=None,
            source_ip=None,
        )


def _first_none_then_real() -> Any:
    from app.auth.service import get_user_by_username

    calls = {"n": 0}

    def fake(session: Session, username: str) -> User | None:
        calls["n"] += 1
        return None if calls["n"] == 1 else get_user_by_username(session, username)

    return fake


def test_a_display_name_longer_than_its_column_is_a_validation_error_not_a_500(
    client: TestClient, admin_token: str
) -> None:
    response = client.post(
        "/api/v1/users",
        json={
            "username": "jrivas",
            "display_name": "x" * 121,
            "role": "analyst",
            "password": NEW_PASSWORD,
        },
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"


def test_a_password_in_a_refused_body_never_comes_back_nor_reaches_the_log(
    client: TestClient, admin_token: str, caplog: pytest.LogCaptureFixture
) -> None:
    marker = "MARKER-" + "p" * 300
    caplog.set_level(logging.DEBUG)
    response = client.post(
        "/api/v1/users",
        json={"username": "jrivas", "display_name": "J", "role": "analyst", "password": marker},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert "MARKER" not in response.text
    assert "MARKER" not in caplog.text


# --- role change ---------------------------------------------------------------


def test_a_role_change_is_recorded_and_the_old_token_stops_working(
    client: TestClient,
    other_client: TestClient,
    db: Session,
    admin: User,
    admin_token: str,
    developer: User,
) -> None:
    target_token = _login(other_client, developer.username)
    response = client.patch(
        f"/api/v1/users/{developer.id}/role",
        json={"role": "analyst", "justification": f"  {REASON}  "},
        headers=_auth(admin_token),
    )
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "analyst"

    (row,) = _rows(db, "user.role.change")
    assert row.actor_username == admin.username
    assert row.target == "cperez developer→analyst"
    assert row.justification == REASON
    assert row.source_ip == "testclient"

    # The token minted before the change is refused (role drift) ...
    stale = other_client.get("/api/v1/auth/session-check", headers=_auth(target_token))
    assert stale.status_code == 401
    # ... but the session survives: the refresh mints a token with the new role.
    refreshed = other_client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["user"]["role"] == "analyst"


def test_an_admin_cannot_change_their_own_role(
    client: TestClient, db: Session, admin: User, admin_token: str, second_admin: User
) -> None:
    response = client.patch(
        f"/api/v1/users/{admin.id}/role",
        json={"role": "analyst", "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "cannot_administer_self"
    assert _user(db, admin.username).role is Role.ADMIN


def test_the_same_role_is_refused_as_a_no_op(
    client: TestClient, db: Session, admin_token: str, analyst: User
) -> None:
    response = client.patch(
        f"/api/v1/users/{analyst.id}/role",
        json={"role": "analyst", "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "role_unchanged"
    assert _rows(db, "user.role.change") == []


def test_another_admin_can_be_demoted_while_one_remains(
    client: TestClient, db: Session, admin_token: str, second_admin: User
) -> None:
    response = client.patch(
        f"/api/v1/users/{second_admin.id}/role",
        json={"role": "developer", "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 200
    assert _user(db, "srosales").role is Role.DEVELOPER
    (row,) = _rows(db, "user.role.change")
    assert row.target == "srosales admin→developer"


def test_an_unknown_account_is_not_found(client: TestClient, admin_token: str) -> None:
    response = client.patch(
        "/api/v1/users/00000000-0000-0000-0000-000000000000/role",
        json={"role": "analyst", "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 404
    assert response.json()["code"] == "user_not_found"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("role", {"role": "admin", "justification": "corto"}),
        ("status", {"disabled": True, "justification": "  corto    "}),
        ("password-reset", {"password": NEW_PASSWORD, "justification": "\x00\x01 ok \x02"}),
    ],
)
def test_a_short_justification_is_refused_before_anything_is_written(
    client: TestClient,
    db: Session,
    admin_token: str,
    analyst: User,
    path: str,
    body: dict[str, Any],
) -> None:
    method = "POST" if path == "password-reset" else "PATCH"
    response = client.request(
        method, f"/api/v1/users/{analyst.id}/{path}", json=body, headers=_auth(admin_token)
    )
    assert response.status_code == 422
    assert response.json()["code"] == "justification_required"
    target = _user(db, "mmarin")
    assert target.role is Role.ANALYST
    assert not target.disabled
    assert not target.must_change_password
    assert db.scalars(select(AuditLogEntry).where(AuditLogEntry.action.like("user.%"))).all() == []


# --- disable / enable --------------------------------------------------------------


def test_disabling_ends_every_session_and_enabling_restores_login(
    client: TestClient,
    other_client: TestClient,
    db: Session,
    admin: User,
    admin_token: str,
    analyst: User,
) -> None:
    target_token = _login(other_client, analyst.username)
    response = client.patch(
        f"/api/v1/users/{analyst.id}/status",
        json={"disabled": True, "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 200
    assert response.json()["disabled"] is True

    live = other_client.get("/api/v1/auth/session-check", headers=_auth(target_token))
    assert live.status_code == 403
    assert live.json()["code"] == "account_disabled"
    assert other_client.post("/api/v1/auth/refresh").status_code in (401, 403)
    assert (
        other_client.post(
            "/api/v1/auth/login", json={"username": "mmarin", "password": SEED_PASSWORD}
        ).status_code
        == 401
    )

    (row,) = _rows(db, "user.disable")
    assert (row.actor_username, row.target, row.justification) == (admin.username, "mmarin", REASON)
    assert row.source_ip == "testclient"

    again = client.patch(
        f"/api/v1/users/{analyst.id}/status",
        json={"disabled": False, "justification": REASON},
        headers=_auth(admin_token),
    )
    assert again.status_code == 200
    assert again.json()["disabled"] is False
    assert len(_rows(db, "user.enable")) == 1
    # Re-enabling does not bring the old session back: disabling REVOKED it
    # (a disabled account's refresh is refused anyway; this is what shows it).
    assert other_client.post("/api/v1/auth/refresh").status_code == 401
    _login(other_client, analyst.username)


def test_the_same_status_is_refused_as_a_no_op(
    client: TestClient, db: Session, admin_token: str, analyst: User
) -> None:
    response = client.patch(
        f"/api/v1/users/{analyst.id}/status",
        json={"disabled": False, "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "status_unchanged"
    assert _rows(db, "user.enable") == []


def test_an_admin_cannot_disable_themselves(
    client: TestClient, db: Session, admin: User, admin_token: str
) -> None:
    response = client.patch(
        f"/api/v1/users/{admin.id}/status",
        json={"disabled": True, "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "cannot_administer_self"
    assert not _user(db, admin.username).disabled


# --- the last admin: the race of two admins acting on each other ---------------------


@pytest.mark.parametrize("lost", ["disabled", "demoted"])
@pytest.mark.parametrize("action", ["disable", "demote"])
def test_an_actor_who_lost_admin_while_waiting_is_refused_and_recorded(
    db: Session,
    session_factory: sessionmaker[Session],
    admin: User,
    second_admin: User,
    action: str,
    lost: str,
) -> None:
    """Two admins act on each other at once. The request that won committed
    first: the actor of the other one is no longer an admin. Its request must
    be refused, or the factory ends with no admin at all (survey §2)."""
    # The actor object is the one the request's dependency loaded, BEFORE the wait.
    actor = db.get(User, admin.id)
    assert actor is not None and actor.role is Role.ADMIN
    # The winning request, on another connection: it disabled the actor.
    with session_factory() as winner:
        loaded = winner.get(User, admin.id)
        assert loaded is not None
        # Disabled, or demoted and still ENABLED: the guard must look at the
        # role too, not only at the flag.
        if lost == "disabled":
            loaded.disabled = True
        else:
            loaded.role = Role.ANALYST
        winner.commit()

    with pytest.raises(Forbidden):
        if action == "disable":
            admin_service.set_disabled(
                db,
                actor=actor,
                user_id=second_admin.id,
                disabled=True,
                justification=REASON,
                source_ip="10.0.0.9",
            )
        else:
            admin_service.change_role(
                db,
                actor=actor,
                user_id=second_admin.id,
                role=Role.ANALYST,
                justification=REASON,
                source_ip="10.0.0.9",
            )
    db.rollback()
    target = _user(db, "srosales")
    assert target.role is Role.ADMIN and not target.disabled  # one admin is left
    (denied,) = _rows(db, "authz.denied")  # committed before the refusal
    assert denied.actor_username == admin.username
    assert denied.outcome is AuditOutcome.DENIED
    assert denied.target == "user srosales: actor no longer an enabled admin"
    assert denied.source_ip == "10.0.0.9"
    assert db.scalars(select(AuditLogEntry).where(AuditLogEntry.action.like("user.%"))).all() == []


def test_the_target_is_read_again_under_the_lock(
    db: Session, session_factory: sessionmaker[Session], admin: User, second_admin: User
) -> None:
    """The target was loaded before the wait; another admin demoted it
    meanwhile. The no-op check and the trail must see the fresh role."""
    actor = db.get(User, admin.id)
    stale = db.get(User, second_admin.id)
    assert actor is not None and stale is not None and stale.role is Role.ADMIN
    with session_factory() as winner:
        loaded = winner.get(User, second_admin.id)
        assert loaded is not None
        loaded.role = Role.ANALYST
        winner.commit()
    with pytest.raises(RoleUnchanged):
        admin_service.change_role(
            db,
            actor=actor,
            user_id=second_admin.id,
            role=Role.ANALYST,
            justification=REASON,
            source_ip=None,
        )


def test_the_last_admin_cannot_be_removed_by_anyone(
    client: TestClient, db: Session, admin: User, admin_token: str
) -> None:
    """With one admin, the only admin is the actor, who may not act on
    themselves; there is no other admin to do it."""
    for path, body in (
        ("status", {"disabled": True, "justification": REASON}),
        ("role", {"role": "analyst", "justification": REASON}),
    ):
        response = client.patch(
            f"/api/v1/users/{admin.id}/{path}", json=body, headers=_auth(admin_token)
        )
        assert response.json()["code"] == "cannot_administer_self"
    assert admin_service.enabled_admin_count(db) == 1


# --- password reset ------------------------------------------------------------------


def test_a_reset_forces_a_change_revokes_everything_and_clears_the_lockout(
    client: TestClient,
    other_client: TestClient,
    db: Session,
    admin: User,
    admin_token: str,
    analyst: User,
    caplog: pytest.LogCaptureFixture,
) -> None:
    target_token = _login(other_client, analyst.username)
    locked = _user(db, "mmarin")
    locked.failed_attempts = 7
    locked.locked_until = utc_now() + timedelta(hours=1)
    db.commit()

    caplog.set_level(logging.DEBUG)
    response = client.post(
        f"/api/v1/users/{analyst.id}/password-reset",
        json={"password": NEW_PASSWORD, "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 200, response.text
    assert response.json()["must_change_password"] is True
    assert response.json()["locked_until"] is None
    assert NEW_PASSWORD not in response.text

    target = _user(db, "mmarin")
    assert target.failed_attempts == 0
    assert target.locked_until is None
    # Every session is gone: the old access token and the refresh cookie.
    assert (
        other_client.get("/api/v1/auth/session-check", headers=_auth(target_token)).status_code
        == 401
    )
    assert other_client.post("/api/v1/auth/refresh").status_code == 401
    # The old password no longer works; the new one does, at once, and forces a change.
    assert (
        other_client.post(
            "/api/v1/auth/login", json={"username": "mmarin", "password": SEED_PASSWORD}
        ).status_code
        == 401
    )
    # A re-login in the same second as the change is refused on purpose (the
    # cutoff rounds UP, auth/deps.py); a person takes longer, so move it back.
    moved = _user(db, "mmarin")
    assert moved.password_changed_at is not None
    moved.password_changed_at -= timedelta(seconds=2)
    db.commit()
    fresh = _login(other_client, "mmarin", NEW_PASSWORD)
    assert other_client.get("/api/v1/projects", headers=_auth(fresh)).status_code == 409

    (row,) = _rows(db, "user.password.reset")
    assert (row.actor_username, row.target, row.justification) == (admin.username, "mmarin", REASON)
    assert row.source_ip == "testclient"
    every_row = " ".join(
        f"{entry.target} {entry.justification}" for entry in db.scalars(select(AuditLogEntry))
    )
    assert NEW_PASSWORD not in every_row
    assert NEW_PASSWORD not in caplog.text


def test_an_admin_cannot_reset_their_own_password_here(
    client: TestClient, db: Session, admin: User, admin_token: str
) -> None:
    response = client.post(
        f"/api/v1/users/{admin.id}/password-reset",
        json={"password": NEW_PASSWORD, "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "cannot_administer_self"
    assert not _user(db, admin.username).must_change_password


def test_a_reset_to_a_weak_password_changes_nothing(
    client: TestClient, db: Session, admin_token: str, analyst: User
) -> None:
    response = client.post(
        f"/api/v1/users/{analyst.id}/password-reset",
        json={"password": "corta", "justification": REASON},
        headers=_auth(admin_token),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "weak_password"
    assert not _user(db, "mmarin").must_change_password
    assert _rows(db, "user.password.reset") == []


# --- bootstrap ---------------------------------------------------------------------------


def test_bootstrap_creates_the_first_admin_with_a_system_row(db: Session) -> None:
    created = bootstrap_module.bootstrap(
        db, username=" SRosales ", display_name="Saile\x1b Rosales", password=NEW_PASSWORD
    )
    assert created == "srosales"
    user = _user(db, "srosales")
    assert user.role is Role.ADMIN
    assert user.must_change_password is True
    assert user.display_name == "Saile Rosales"
    (row,) = _rows(db, "user.create")
    assert row.actor_username == "system"
    assert row.actor_id is None
    assert row.target == "srosales role=admin (bootstrap)"


def test_bootstrap_refuses_when_an_enabled_admin_exists(db: Session, admin: User) -> None:
    with pytest.raises(bootstrap_module.BootstrapRefused):
        bootstrap_module.bootstrap(db, username="srosales", display_name="S", password=NEW_PASSWORD)
    assert db.scalar(select(User).where(User.username == "srosales")) is None


def test_bootstrap_counts_only_admins(db: Session, analyst: User, developer: User) -> None:
    assert (
        bootstrap_module.bootstrap(
            db, username="srosales", display_name="x" * 130, password=NEW_PASSWORD
        )
        == "srosales"
    )
    assert _user(db, "srosales").display_name == "x" * 120  # the column's width


def test_bootstrap_is_the_way_back_when_every_admin_is_disabled(db: Session, admin: User) -> None:
    admin.disabled = True
    db.commit()
    assert (
        bootstrap_module.bootstrap(db, username="srosales", display_name="S", password=NEW_PASSWORD)
        == "srosales"
    )


def test_bootstrap_never_reuses_an_existing_account(db: Session, admin: User) -> None:
    admin.disabled = True
    db.commit()
    with pytest.raises(bootstrap_module.BootstrapRefused):
        bootstrap_module.bootstrap(db, username="amedina", display_name="A", password=NEW_PASSWORD)


def test_bootstrap_main_reads_the_password_from_the_environment_only(
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(bootstrap_module, "get_session_factory", lambda: session_factory)
    monkeypatch.delenv(bootstrap_module.PASSWORD_VARIABLE, raising=False)
    caplog.set_level(logging.DEBUG)
    assert bootstrap_module.main(["srosales", "Saile Rosales"]) == 1
    assert f"{bootstrap_module.PASSWORD_VARIABLE} is not set" in caplog.text
    assert bootstrap_module.main(["srosales"]) == 2
    # With no explicit argv it reads the command line, past the program name.
    # (two arguments after it: past the usage check, stopped by the missing password)
    monkeypatch.setattr("sys.argv", ["bootstrap", "srosales", "Saile Rosales"])
    assert bootstrap_module.main() == 1

    monkeypatch.setenv(bootstrap_module.PASSWORD_VARIABLE, NEW_PASSWORD)
    assert bootstrap_module.main(["srosales", "Saile Rosales"]) == 0
    assert "created admin srosales" in caplog.text
    assert NEW_PASSWORD not in caplog.text
    # A second run finds the admin it just created and refuses.
    assert bootstrap_module.main(["lrivas", "L"]) == 1
    # A convention breach is refused with the rule, not a traceback.
    monkeypatch.setattr(bootstrap_module, "enabled_admin_count", lambda _db: 0)
    assert bootstrap_module.main(["L.Rivas", "L"]) == 1


# --- mail stays off ------------------------------------------------------------------------


def test_mail_cannot_be_switched_on_in_this_version() -> None:
    with pytest.raises(ValidationError, match="DIOPTRA_MAIL_ENABLED"):
        Settings(jwt_secret="x" * 40, mail_enabled=True)  # type: ignore[arg-type]


def test_no_admin_action_opens_a_connection(
    client: TestClient,
    admin_token: str,
    analyst: User,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The air-gapped factory is the baseline: with mail off (the only option)
    every admin action works and nothing leaves the host."""

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        message = "an outbound connection was attempted"
        raise AssertionError(message)

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    headers = _auth(admin_token)
    assert (
        client.post(
            "/api/v1/users",
            json={
                "username": "jrivas",
                "display_name": "J",
                "role": "developer",
                "password": NEW_PASSWORD,
            },
            headers=headers,
        ).status_code
        == 201
    )
    assert (
        client.patch(
            f"/api/v1/users/{analyst.id}/status",
            json={"disabled": True, "justification": REASON},
            headers=headers,
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/users/{analyst.id}/password-reset",
            json={"password": NEW_PASSWORD, "justification": REASON},
            headers=headers,
        ).status_code
        == 200
    )

    caplog.set_level(logging.INFO)
    mailer = get_mailer()
    assert isinstance(mailer, NullMailer)
    mailer.send(to="rivas@example.org", subject="Recuperación", body="token-secreto")
    assert "rivas@example.org" not in caplog.text
    assert "token-secreto" not in caplog.text
    assert "Recuperación" in caplog.text
    # The subject is capped too: it is the only part that reaches a log.
    mailer.send(to="a@b.c", subject="x" * 500, body="b")
    assert "x" * 120 in caplog.text
    assert "x" * 121 not in caplog.text
