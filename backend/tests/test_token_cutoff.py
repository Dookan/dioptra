"""The password-change cutoff, pinned at the second boundary.

`_token_cutoff` is load-bearing: removing its round-up leaves the whole suite
green while a token minted in the same second as a password change becomes
valid again. These cases exist so that mutant dies.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.deps import _token_cutoff
from app.auth.models import User
from app.auth.tokens import issue_access_token


@pytest.mark.parametrize("microsecond", [0, 1, 500_000, 999_999])
def test_cutoff_is_always_the_next_whole_second(microsecond: int) -> None:
    """Exactly +1s past the floor — not +0, not +2, whatever the microseconds."""
    changed = datetime(2026, 8, 18, 12, 0, 0, microsecond, tzinfo=UTC)

    assert _token_cutoff(changed) == datetime(2026, 8, 18, 12, 0, 1, tzinfo=UTC)


def test_cutoff_never_lands_before_the_change_itself() -> None:
    """A cutoff at or below the change would admit a pre-change token."""
    changed = datetime(2026, 8, 18, 12, 0, 0, 700_000, tzinfo=UTC)

    assert _token_cutoff(changed) > changed


def test_a_token_stamped_exactly_at_the_change_is_refused(
    client: TestClient, db: Session, analyst: User
) -> None:
    """The case the round-up exists for.

    `iat` is floored to the second, so a token minted at 12:00:00.9 and a change
    at 12:00:00.0 both carry second 12:00:00 and are indistinguishable. Without
    the round-up this token is accepted; with it the ambiguous second falls closed.
    """
    token, _ = issue_access_token(user_id=analyst.id, username=analyst.username, role=analyst.role)
    analyst.password_changed_at = datetime.now(tz=UTC).replace(microsecond=0)
    db.commit()

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_a_token_stamped_a_second_after_the_change_is_accepted(
    client: TestClient, db: Session, analyst: User
) -> None:
    """The accept side, one second past the cutoff — pins the +1s constant."""
    analyst.password_changed_at = datetime.now(tz=UTC).replace(microsecond=0) - timedelta(seconds=1)
    db.commit()
    token, _ = issue_access_token(user_id=analyst.id, username=analyst.username, role=analyst.role)

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
