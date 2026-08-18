"""Authorization: deny by default, one role per route, no privilege drift."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth.deps import AdminUser, AnalystUser, DeveloperUser
from app.auth.errors import InvalidUsername
from app.auth.models import USERNAME_PATTERN, Role, User
from app.auth.service import create_user
from app.auth.tokens import issue_access_token
from tests.conftest import SEED_PASSWORD

ROUTES = {
    Role.ADMIN: "/test/admin-only",
    Role.ANALYST: "/test/analyst-only",
    Role.DEVELOPER: "/test/developer-only",
}


@pytest.fixture
def guarded_client(app: FastAPI) -> Iterator[TestClient]:
    """The app plus one route per role, mirroring the permission matrix."""

    @app.get(ROUTES[Role.ADMIN])
    def admin_only(user: AdminUser) -> dict[str, str]:
        return {"seen": user.username}

    @app.get(ROUTES[Role.ANALYST])
    def analyst_only(user: AnalystUser) -> dict[str, str]:
        return {"seen": user.username}

    @app.get(ROUTES[Role.DEVELOPER])
    def developer_only(user: DeveloperUser) -> dict[str, str]:
        return {"seen": user.username}

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def _token_for(client: TestClient, username: str) -> str:
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": SEED_PASSWORD}
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])


def test_each_role_reaches_only_its_own_route(
    guarded_client: TestClient, admin: User, analyst: User, developer: User
) -> None:
    tokens = {
        Role.ADMIN: _token_for(guarded_client, "amedina"),
        Role.ANALYST: _token_for(guarded_client, "mmarin"),
        Role.DEVELOPER: _token_for(guarded_client, "cperez"),
    }

    for holder, token in tokens.items():
        for guarded_role, path in ROUTES.items():
            response = guarded_client.get(path, headers={"Authorization": f"Bearer {token}"})
            expected = 200 if holder is guarded_role else 403
            assert response.status_code == expected, f"{holder} on {path}"


def test_a_developer_denied_on_an_analyst_route_is_recorded(
    guarded_client: TestClient, db: Session, developer: User
) -> None:
    token = _token_for(guarded_client, "cperez")

    response = guarded_client.get(
        ROUTES[Role.ANALYST], headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"
    denial = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")).one()
    assert denial.actor_username == "cperez"
    assert denial.outcome is AuditOutcome.DENIED
    assert denial.target == f"GET {ROUTES[Role.ANALYST]}"


def test_no_token_is_rejected(guarded_client: TestClient, analyst: User) -> None:
    response = guarded_client.get(ROUTES[Role.ANALYST])

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Token abc", "Basic bW1hcmluOnNlY3JldA==", "Bearer not.a.jwt"],
)
def test_malformed_authorization_headers_are_rejected(
    guarded_client: TestClient, analyst: User, header: str
) -> None:
    response = guarded_client.get(ROUTES[Role.ANALYST], headers={"Authorization": header})

    assert response.status_code == 401


def test_a_token_whose_role_no_longer_matches_the_account_is_rejected(
    guarded_client: TestClient, db: Session, analyst: User
) -> None:
    """An admin demoting a user must not leave a valid admin token in the wild."""
    stale_token, _ = issue_access_token(
        user_id=analyst.id, username=analyst.username, role=Role.ADMIN
    )

    response = guarded_client.get(
        ROUTES[Role.ADMIN], headers={"Authorization": f"Bearer {stale_token}"}
    )

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_a_token_for_a_deleted_account_is_rejected(guarded_client: TestClient) -> None:
    import uuid

    orphan_token, _ = issue_access_token(user_id=uuid.uuid4(), username="ghost", role=Role.ANALYST)

    response = guarded_client.get(
        ROUTES[Role.ANALYST], headers={"Authorization": f"Bearer {orphan_token}"}
    )

    assert response.status_code == 401


def test_a_disabled_account_loses_access_immediately(
    guarded_client: TestClient, db: Session, analyst: User
) -> None:
    token = _token_for(guarded_client, "mmarin")
    analyst.disabled = True
    db.commit()

    response = guarded_client.get(
        ROUTES[Role.ANALYST], headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403
    assert response.json()["code"] == "account_disabled"


def test_me_returns_the_caller_identity_only(guarded_client: TestClient, analyst: User) -> None:
    token = _token_for(guarded_client, "mmarin")

    response = guarded_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {
        "id": str(analyst.id),
        "username": "mmarin",
        "display_name": "Moises Marin",
        "role": "analyst",
        "must_change_password": False,
    }


@pytest.mark.parametrize(
    "username",
    ["m.marin", "mm", "moises marin", "1marin", "m-marin", "mmarin!", "x" * 33, ""],
)
def test_create_user_rejects_usernames_outside_the_convention(db: Session, username: str) -> None:
    """USERNAME_PATTERN must be ENFORCED, not merely declared.

    CLAUDE.md -> Hard Rules: initial + lastname, lowercase, no dots. The constant
    existed from the start but nothing referenced it, so the rule had zero runtime
    effect; P1's admin endpoint would have inherited a hole that looked closed.
    """
    with pytest.raises(InvalidUsername):
        create_user(
            db,
            username=username,
            display_name="Someone",
            role=Role.ANALYST,
            password="a-perfectly-fine-password",
        )


def test_create_user_accepts_the_factory_convention(db: Session) -> None:
    """The accept side: the rule must not reject the names we actually use."""
    user = create_user(
        db,
        username="  CPerez ",  # normalised before validation
        display_name="Carlos Perez",
        role=Role.DEVELOPER,
        password="a-perfectly-fine-password",
    )

    assert user.username == "cperez"


def test_username_pattern_stays_fully_anchored() -> None:
    """The guard uses `re.fullmatch`, so the anchors look redundant — they are not.

    If anyone drops `^`/`$` (e.g. to reuse this constant as a Pydantic `pattern=`,
    which applies SEARCH semantics), `create_user` would start accepting anything
    merely CONTAINING a valid username. No behavioural test can catch that, so
    assert the shape of the constant itself.
    """
    assert USERNAME_PATTERN.startswith("^")
    assert USERNAME_PATTERN.endswith("$")
