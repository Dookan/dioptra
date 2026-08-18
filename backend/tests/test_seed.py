"""Seeding is a development convenience that must never weaken production."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.auth.models import Role
from app.auth.service import get_user_by_username
from app.core.config import Settings, get_settings
from app.seed import SEED_ACCOUNTS, SeedRefused, seed


@pytest.fixture
def seed_passwords(monkeypatch: pytest.MonkeyPatch) -> None:
    for username, _, _ in SEED_ACCOUNTS:
        monkeypatch.setenv(f"DIOPTRA_SEED_PASSWORD_{username.upper()}", "a-seeded-password-2026")


def test_seed_creates_the_three_roles(db: Session, seed_passwords: None) -> None:
    created = seed(db)

    assert created == ["amedina", "mmarin", "cperez"]
    roles = {
        username: get_user_by_username(db, username).role  # type: ignore[union-attr]
        for username, _, _ in SEED_ACCOUNTS
    }
    assert roles == {"amedina": Role.ADMIN, "mmarin": Role.ANALYST, "cperez": Role.DEVELOPER}


def test_seeded_accounts_must_change_their_password(db: Session, seed_passwords: None) -> None:
    seed(db)

    for username, _, _ in SEED_ACCOUNTS:
        user = get_user_by_username(db, username)
        assert user is not None
        assert user.must_change_password is True


def test_seeding_twice_creates_nothing_new(db: Session, seed_passwords: None) -> None:
    seed(db)

    assert seed(db) == []


def test_seeding_without_a_password_refuses_instead_of_inventing_one(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    for username, _, _ in SEED_ACCOUNTS:
        monkeypatch.delenv(f"DIOPTRA_SEED_PASSWORD_{username.upper()}", raising=False)

    with pytest.raises(SeedRefused):
        seed(db)

    assert get_user_by_username(db, "amedina") is None


def test_seeding_is_refused_in_production(
    db: Session, seed_passwords: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "env", "prod")

    with pytest.raises(SeedRefused):
        seed(db)


def test_prod_refuses_a_non_secure_refresh_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed at startup rather than ship a cleartext session token."""
    monkeypatch.setenv("DIOPTRA_ENV", "prod")
    monkeypatch.setenv("DIOPTRA_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("DIOPTRA_REFRESH_COOKIE_SECURE", "false")

    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]  # values arrive from the environment


def test_prod_boots_with_a_secure_refresh_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    """The accept side: the guard must not block a correctly configured prod."""
    monkeypatch.setenv("DIOPTRA_ENV", "prod")
    monkeypatch.setenv("DIOPTRA_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("DIOPTRA_REFRESH_COOKIE_SECURE", "true")

    assert Settings().refresh_cookie_secure is True  # type: ignore[call-arg]
