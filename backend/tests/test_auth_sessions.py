"""Refresh rotation, reuse detection, logout and password change."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.models import RefreshToken, User
from app.core.clock import utc_now
from app.core.config import get_settings
from tests.conftest import SEED_PASSWORD

COOKIE = get_settings().refresh_cookie_name


def _login(client: TestClient, password: str = SEED_PASSWORD) -> str:
    response = client.post("/api/v1/auth/login", json={"username": "mmarin", "password": password})
    assert response.status_code == 200
    return str(response.json()["access_token"])


def test_refresh_rotates_the_cookie_and_mints_a_new_access_token(
    client: TestClient, analyst: User
) -> None:
    first_access = _login(client)
    first_refresh = client.cookies[COOKIE]

    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 200
    assert response.json()["access_token"] != first_access
    assert client.cookies[COOKIE] != first_refresh


def test_replaying_a_rotated_refresh_token_revokes_the_whole_family(
    client: TestClient, db: Session, analyst: User
) -> None:
    _login(client)
    stolen = client.cookies[COOKIE]
    assert client.post("/api/v1/auth/refresh").status_code == 200

    client.cookies.set(COOKIE, stolen, path="/api/v1/auth")
    replay = client.post("/api/v1/auth/refresh")

    assert replay.status_code == 401
    assert replay.json()["code"] == "token_reuse_detected"
    live_tokens = db.scalars(select(RefreshToken).where(RefreshToken.user_id == analyst.id)).all()
    assert live_tokens, "the family must exist to prove it was revoked"
    assert all(token.revoked_at is not None for token in live_tokens)


def test_refresh_without_a_cookie_is_rejected(client: TestClient, analyst: User) -> None:
    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_an_unknown_refresh_token_is_rejected(client: TestClient, analyst: User) -> None:
    client.cookies.set(COOKIE, "a-token-that-was-never-issued", path="/api/v1/auth")

    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_an_expired_refresh_token_is_rejected(
    client: TestClient, db: Session, analyst: User
) -> None:
    _login(client)
    stored = db.scalars(select(RefreshToken).where(RefreshToken.user_id == analyst.id)).one()
    stored.expires_at = utc_now() - timedelta(seconds=1)
    db.commit()

    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_logout_revokes_the_family_and_clears_the_cookie(
    client: TestClient, db: Session, analyst: User
) -> None:
    _login(client)

    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 204
    tokens = db.scalars(select(RefreshToken).where(RefreshToken.user_id == analyst.id)).all()
    assert all(token.revoked_at is not None for token in tokens)
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_logout_without_a_session_still_succeeds(client: TestClient) -> None:
    assert client.post("/api/v1/auth/logout").status_code == 204


def test_a_disabled_account_cannot_refresh(client: TestClient, db: Session, analyst: User) -> None:
    _login(client)
    analyst.disabled = True
    db.commit()

    response = client.post("/api/v1/auth/refresh")

    assert response.status_code == 403
    assert response.json()["code"] == "account_disabled"


def test_password_change_requires_the_current_password(client: TestClient, analyst: User) -> None:
    access = _login(client)

    response = client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {access}"},
        json={"current_password": "not-it", "new_password": "a-brand-new-password"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"


def test_password_change_rejects_a_password_below_the_policy(
    client: TestClient, analyst: User
) -> None:
    access = _login(client)

    response = client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {access}"},
        json={"current_password": SEED_PASSWORD, "new_password": "short"},
    )

    assert response.status_code == 422


@pytest.mark.parametrize("new_password", ["a-brand-new-password-2026"])
def test_password_change_revokes_every_open_session(
    client: TestClient, db: Session, analyst: User, new_password: str
) -> None:
    access = _login(client)

    response = client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {access}"},
        json={"current_password": SEED_PASSWORD, "new_password": new_password},
    )

    assert response.status_code == 204
    tokens = db.scalars(select(RefreshToken).where(RefreshToken.user_id == analyst.id)).all()
    assert all(token.revoked_at is not None for token in tokens)
    assert _login(client, new_password)


def test_password_change_kills_the_outstanding_access_token(
    client: TestClient, analyst: User
) -> None:
    """Revoking the refresh family is not enough.

    An access token already in the wild keeps working until it expires, so a
    password changed BECAUSE it leaked would leave the thief authenticated for
    up to the full 15-minute lifetime. `password_changed_at` closes that window
    immediately (ASVS V3.3).
    """
    new_password = "a-brand-new-password-2026"
    access = _login(client)
    headers = {"Authorization": f"Bearer {access}"}
    # The token works right up to the moment of the change.
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    changed = client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={"current_password": SEED_PASSWORD, "new_password": new_password},
    )
    assert changed.status_code == 204

    # Same token, same 15-minute expiry, now refused.
    rejected = client.get("/api/v1/auth/me", headers=headers)
    assert rejected.status_code == 401
    assert rejected.json()["code"] == "invalid_token"


def test_a_token_issued_after_the_change_is_accepted(
    client: TestClient, db: Session, analyst: User
) -> None:
    """The other side of the boundary: invalidation must not be permanent.

    Without this case, `_token_cutoff` could be widened to reject everything and
    the suite would still pass — locking every user out of their own account
    after a password change.
    """
    new_password = "a-brand-new-password-2026"
    access = _login(client)
    client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {access}"},
        json={"current_password": SEED_PASSWORD, "new_password": new_password},
    )

    # Simulate the ambiguous second having elapsed. Deterministic on purpose: a
    # real sleep would make this test flaky for the sake of one second.
    db.refresh(analyst)
    analyst.password_changed_at = utc_now() - timedelta(seconds=5)
    db.commit()

    fresh = _login(client, new_password)
    profile = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {fresh}"})

    assert profile.status_code == 200


def test_a_pending_password_change_blocks_the_application_but_not_the_change(
    client: TestClient, db: Session, analyst: User
) -> None:
    analyst.must_change_password = True
    db.commit()
    access = _login(client)

    blocked = client.get(
        "/api/v1/auth/session-check", headers={"Authorization": f"Bearer {access}"}
    )
    assert blocked.status_code == 409
    assert blocked.json()["code"] == "password_change_required"

    allowed = client.post(
        "/api/v1/auth/password",
        headers={"Authorization": f"Bearer {access}"},
        json={"current_password": SEED_PASSWORD, "new_password": "a-brand-new-password-2026"},
    )
    assert allowed.status_code == 204
    db.refresh(analyst)
    assert analyst.must_change_password is False
