"""Access-token integrity (ASVS V3.3)."""

from __future__ import annotations

import uuid
from datetime import timedelta

import jwt
import pytest

from app.auth.errors import InvalidToken
from app.auth.models import Role
from app.auth.tokens import (
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
    issue_access_token,
)
from app.core.clock import utc_now
from app.core.config import get_settings


def _issue() -> tuple[str, uuid.UUID]:
    user_id = uuid.uuid4()
    token, _ = issue_access_token(user_id=user_id, username="mmarin", role=Role.ANALYST)
    return token, user_id


def test_roundtrip_preserves_identity_and_role() -> None:
    token, user_id = _issue()
    claims = decode_access_token(token)
    assert claims.subject == user_id
    assert claims.username == "mmarin"
    assert claims.role is Role.ANALYST


def test_tampered_payload_is_rejected() -> None:
    token, _ = _issue()
    head, payload, signature = token.split(".")
    with pytest.raises(InvalidToken):
        decode_access_token(f"{head}.{payload}x.{signature}")


def test_token_signed_with_another_key_is_rejected() -> None:
    forged = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "preferred_username": "amedina",
            "role": "admin",
            "iss": get_settings().jwt_issuer,
            "iat": int(utc_now().timestamp()),
            "exp": int((utc_now() + timedelta(minutes=5)).timestamp()),
            "jti": str(uuid.uuid4()),
        },
        "an-attacker-controlled-secret-value",
        algorithm="HS256",
    )
    with pytest.raises(InvalidToken):
        decode_access_token(forged)


def test_unsigned_token_is_rejected() -> None:
    """alg=none MUST NOT be honoured — the algorithm list is pinned."""
    forged = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "preferred_username": "amedina",
            "role": "admin",
            "iss": get_settings().jwt_issuer,
            "iat": int(utc_now().timestamp()),
            "exp": int((utc_now() + timedelta(minutes=5)).timestamp()),
            "jti": str(uuid.uuid4()),
        },
        key="",
        algorithm="none",
    )
    with pytest.raises(InvalidToken):
        decode_access_token(forged)


def test_expired_token_is_rejected() -> None:
    settings = get_settings()
    expired = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "preferred_username": "mmarin",
            "role": "analyst",
            "iss": settings.jwt_issuer,
            "iat": int((utc_now() - timedelta(hours=2)).timestamp()),
            "exp": int((utc_now() - timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
        },
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(InvalidToken):
        decode_access_token(expired)


def test_token_from_another_issuer_is_rejected() -> None:
    settings = get_settings()
    foreign = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "preferred_username": "mmarin",
            "role": "analyst",
            "iss": "some-other-product",
            "iat": int(utc_now().timestamp()),
            "exp": int((utc_now() + timedelta(minutes=5)).timestamp()),
            "jti": str(uuid.uuid4()),
        },
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(InvalidToken):
        decode_access_token(foreign)


def test_token_missing_required_claims_is_rejected() -> None:
    settings = get_settings()
    incomplete = jwt.encode(
        {"sub": str(uuid.uuid4()), "iss": settings.jwt_issuer},
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(InvalidToken):
        decode_access_token(incomplete)


def test_garbage_is_rejected() -> None:
    with pytest.raises(InvalidToken):
        decode_access_token("not-a-token")


def test_refresh_tokens_are_unique_and_stored_only_as_a_digest() -> None:
    first = generate_refresh_token()
    second = generate_refresh_token()
    assert first != second
    assert len(hash_refresh_token(first)) == 64
    assert hash_refresh_token(first) != first
    assert hash_refresh_token(first) == hash_refresh_token(first)
