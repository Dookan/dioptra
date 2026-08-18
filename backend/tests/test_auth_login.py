"""Login endpoint: credentials, enumeration resistance, lockout backoff."""

from __future__ import annotations

from datetime import timedelta

from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy.orm import Session

from app.auth.models import User
from app.auth.passwords import needs_rehash, verify_password
from app.core.clock import utc_now
from app.core.config import get_settings
from tests.conftest import SEED_PASSWORD


def _login(client: TestClient, username: str, password: str) -> Response:
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def test_login_returns_a_session_and_the_profile(client: TestClient, analyst: User) -> None:
    response = _login(client, "mmarin", SEED_PASSWORD)

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == get_settings().access_token_ttl_seconds
    assert body["user"]["username"] == "mmarin"
    assert body["user"]["role"] == "analyst"
    assert "password_hash" not in body["user"]


def test_login_sets_an_httponly_refresh_cookie(client: TestClient, analyst: User) -> None:
    response = _login(client, "mmarin", SEED_PASSWORD)

    cookie_header = response.headers["set-cookie"]
    assert get_settings().refresh_cookie_name in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header.replace("samesite", "SameSite")
    # The refresh token must never travel in the JSON body where a script sees it.
    assert "refresh_token" not in response.json()


def test_username_is_case_insensitive(client: TestClient, analyst: User) -> None:
    assert _login(client, "MMarin", SEED_PASSWORD).status_code == 200


def test_wrong_password_and_unknown_user_are_indistinguishable(
    client: TestClient, analyst: User
) -> None:
    wrong = _login(client, "mmarin", "definitely-not-the-password")
    unknown = _login(client, "nobody", "definitely-not-the-password")

    assert wrong.status_code == unknown.status_code == 401
    assert (
        wrong.json()
        == unknown.json()
        == {
            "code": "invalid_credentials",
            "message_key": "errors.auth.invalidCredentials",
        }
    )


def test_disabled_account_cannot_log_in(client: TestClient, db: Session, analyst: User) -> None:
    """A disabled account is REJECTED, and indistinguishably so.

    The response must look exactly like a wrong password: telling an
    unauthenticated caller "this account exists but is disabled" is free
    username enumeration. The audit trail keeps the real reason (asserted in
    test_audit.py); only the client-visible answer is flattened.
    """
    analyst.disabled = True
    db.commit()

    response = _login(client, "mmarin", SEED_PASSWORD)
    wrong_password = _login(client, "mmarin", "definitely-not-the-password")
    unknown_user = _login(client, "nobody", SEED_PASSWORD)

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"
    # Byte-identical to both other rejection shapes.
    assert response.json() == wrong_password.json() == unknown_user.json()


def test_login_transparently_upgrades_an_outdated_password_hash(
    client: TestClient, db: Session, analyst: User
) -> None:
    # ASVS V2.4: a password stored under older, cheaper cost parameters must be
    # re-hashed on the next successful login, invisibly to the user. Without this
    # test the rehash branch is real but unpinned — a revert would stay green and
    # every legacy hash would quietly keep its weak parameters forever.
    outdated = PasswordHasher(time_cost=1, memory_cost=8 * 1024, parallelism=1)
    analyst.password_hash = outdated.hash(SEED_PASSWORD)
    db.commit()
    assert "m=8192,t=1,p=1" in analyst.password_hash

    assert _login(client, "mmarin", SEED_PASSWORD).status_code == 200

    db.refresh(analyst)
    assert "m=19456,t=2,p=1" in analyst.password_hash
    assert needs_rehash(analyst.password_hash) is False
    # The upgrade must not lock the user out of their own password.
    assert verify_password(analyst.password_hash, SEED_PASSWORD) is True


def test_a_current_password_hash_is_left_alone_on_login(
    client: TestClient, db: Session, analyst: User
) -> None:
    # The other half of the branch: rehashing every login would be wasted work.
    before = analyst.password_hash

    assert _login(client, "mmarin", SEED_PASSWORD).status_code == 200

    db.refresh(analyst)
    assert analyst.password_hash == before


def test_failed_attempts_lock_the_account_with_a_retry_after(
    client: TestClient, db: Session, analyst: User
) -> None:
    settings = get_settings()
    for _ in range(settings.lockout_threshold):
        assert _login(client, "mmarin", "wrong-password").status_code == 401

    locked = _login(client, "mmarin", SEED_PASSWORD)

    assert locked.status_code == 423
    assert locked.json()["code"] == "account_locked"
    assert int(locked.headers["retry-after"]) > 0
    db.refresh(analyst)
    assert analyst.failed_attempts == settings.lockout_threshold
    assert analyst.locked_until is not None


def test_lockout_backoff_grows_with_further_failures(client: TestClient, analyst: User) -> None:
    settings = get_settings()
    assert settings.backoff_for(settings.lockout_threshold) < settings.backoff_for(
        settings.lockout_threshold + 1
    )
    # The last configured step repeats instead of overflowing.
    far_past_threshold = settings.lockout_threshold + len(settings.lockout_backoff_seconds) + 50
    assert settings.backoff_for(far_past_threshold) == settings.lockout_backoff_seconds[-1]


def test_each_further_failure_locks_the_account_for_longer(
    client: TestClient, db: Session, analyst: User
) -> None:
    """The wired-in half of the backoff contract.

    Asserting on `Settings.backoff_for()` in isolation leaves `authenticate()`
    free to pass it a CONSTANT — freezing the penalty at its first step forever
    while every other test stays green. Compare the advertised Retry-After across
    two consecutive lock cycles: a duration, so no wall-clock drift can fake the
    growth the way comparing two absolute `locked_until` stamps would.
    """
    settings = get_settings()

    def retry_after_now() -> int:
        locked = _login(client, "mmarin", SEED_PASSWORD)
        assert locked.status_code == 423
        return int(locked.headers["retry-after"])

    for _ in range(settings.lockout_threshold):
        assert _login(client, "mmarin", "wrong-password").status_code == 401
    first_penalty = retry_after_now()

    # Let the first lock lapse, then fail once more: attempt threshold+1.
    analyst.locked_until = utc_now() - timedelta(seconds=1)
    db.commit()
    assert _login(client, "mmarin", "wrong-password").status_code == 401

    db.refresh(analyst)
    assert analyst.failed_attempts == settings.lockout_threshold + 1
    assert retry_after_now() > first_penalty


def test_a_correct_password_after_the_lock_expires_resets_the_counter(
    client: TestClient, db: Session, analyst: User
) -> None:
    analyst.failed_attempts = get_settings().lockout_threshold
    analyst.locked_until = utc_now() - timedelta(seconds=1)
    db.commit()

    response = _login(client, "mmarin", SEED_PASSWORD)

    assert response.status_code == 200
    db.expire_all()
    reloaded = db.get(User, analyst.id)
    assert reloaded is not None
    assert reloaded.failed_attempts == 0
    assert reloaded.locked_until is None
    assert reloaded.last_login_at is not None


def test_a_correct_password_clears_a_partial_failure_streak(
    client: TestClient, db: Session, analyst: User
) -> None:
    assert _login(client, "mmarin", "wrong-password").status_code == 401
    assert _login(client, "mmarin", SEED_PASSWORD).status_code == 200

    db.refresh(analyst)
    assert analyst.failed_attempts == 0


def test_malformed_request_does_not_echo_the_submitted_password(client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"username": "mmarin"})

    assert response.status_code == 422
    assert response.json() == {"code": "validation_failed", "message_key": "errors.validation"}
    assert "password" not in response.text


def test_responses_carry_the_no_cdn_content_security_policy(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    policy = response.headers["content-security-policy"]
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["x-content-type-options"] == "nosniff"
