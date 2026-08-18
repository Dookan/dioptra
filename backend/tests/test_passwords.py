"""Credential storage (ASVS V2.4)."""

from __future__ import annotations

import pytest

from app.auth.errors import WeakPassword
from app.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    hash_password,
    needs_rehash,
    spend_dummy_verification,
    validate_password_policy,
    verify_password,
)


def test_hash_is_argon2id_and_not_the_password() -> None:
    digest = hash_password("a-long-enough-password")
    assert digest.startswith("$argon2id$")
    assert "a-long-enough-password" not in digest


def test_same_password_hashes_differently() -> None:
    """Per-password salt: identical passwords MUST NOT share a digest."""
    assert hash_password("a-long-enough-password") != hash_password("a-long-enough-password")


def test_verify_accepts_the_password_and_rejects_others() -> None:
    digest = hash_password("a-long-enough-password")
    assert verify_password(digest, "a-long-enough-password") is True
    assert verify_password(digest, "a-long-enough-passwore") is False
    assert verify_password(digest, "") is False


def test_verify_rejects_a_corrupted_stored_hash_instead_of_raising() -> None:
    assert verify_password("not-a-hash", "a-long-enough-password") is False


def test_current_parameters_do_not_request_a_rehash() -> None:
    assert needs_rehash(hash_password("a-long-enough-password")) is False


def test_unparseable_hash_is_treated_as_needing_a_rehash() -> None:
    assert needs_rehash("$argon2id$broken") is True


def test_dummy_verification_never_raises() -> None:
    """The unknown-username path must not leak by raising a different error."""
    spend_dummy_verification("whatever")


@pytest.mark.parametrize("password", ["", "short", "x" * (MIN_PASSWORD_LENGTH - 1)])
def test_policy_rejects_short_passwords(password: str) -> None:
    with pytest.raises(WeakPassword):
        validate_password_policy(password)


@pytest.mark.parametrize(
    "length", [MIN_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH + 1, MAX_PASSWORD_LENGTH]
)
def test_policy_accepts_the_boundary_lengths(length: int) -> None:
    """The accept side of the boundary.

    docs/workflow-gates.md makes us demand 17/18/19 around `age >= 18` from the
    factory; the same rule applies to us. Without a case at exactly the minimum,
    `MIN <= len(pw)` can be weakened to `MIN < len(pw)` and the suite stays green,
    silently rejecting every password of exactly the documented minimum length.
    """
    validate_password_policy("x" * length)


def test_policy_rejects_absurdly_long_passwords() -> None:
    """Bound the Argon2 work an unauthenticated caller can ask for."""
    with pytest.raises(WeakPassword):
        validate_password_policy("x" * 10_000)


def test_policy_rejects_one_character_past_the_maximum() -> None:
    """The reject side of the upper boundary, adjacent rather than absurd."""
    with pytest.raises(WeakPassword):
        validate_password_policy("x" * (MAX_PASSWORD_LENGTH + 1))
