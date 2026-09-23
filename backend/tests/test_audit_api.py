"""Reading the audit trail: the admin sees everything, everyone else their own actions."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import quote

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.audit import service as audit
from app.auth.models import User
from app.core.clock import utc_now
from tests.support import login


def _seed(db: Session) -> None:
    audit.record(db, actor_username="mmarin", action="finding.verdict.confirmed", target="f:1")
    audit.record(
        db,
        actor_username="cperez",
        action="tests.save",
        target="analysis:1",
        justification="<script>alert(1)</script>",
    )
    audit.record(db, actor_username="amedina", action="user.create", target="jrivas")
    db.commit()


def test_the_admin_reads_every_row_newest_first(
    client: TestClient, db: Session, admin: User, analyst: User, developer: User
) -> None:
    _seed(db)
    response = client.get("/api/v1/audit", headers=login(client, "amedina"))
    assert response.status_code == 200
    rows = response.json()
    actions = [row["action"] for row in rows]
    assert {"user.create", "tests.save", "finding.verdict.confirmed", "auth.login"} <= set(actions)
    assert {row["actor_username"] for row in rows} >= {"mmarin", "cperez", "amedina"}
    assert rows[0]["occurred_at"] >= rows[-1]["occurred_at"]
    hostile = next(row for row in rows if row["action"] == "tests.save")
    assert hostile["justification"] == "<script>alert(1)</script>", "text, escaped by the screen"


def test_an_analyst_and_a_developer_read_only_their_own_actions(
    client: TestClient, db: Session, admin: User, analyst: User, developer: User
) -> None:
    _seed(db)
    for username in ("mmarin", "cperez"):
        rows = client.get("/api/v1/audit", headers=login(client, username)).json()
        assert rows, username
        assert {row["actor_username"] for row in rows} == {username}


def test_since_and_limit_bound_the_read(client: TestClient, db: Session, admin: User) -> None:
    _seed(db)
    future = quote((utc_now() + timedelta(days=1)).isoformat())
    assert (
        client.get(f"/api/v1/audit?since={future}", headers=login(client, "amedina")).json() == []
    )
    past = quote((utc_now() - timedelta(days=1)).isoformat())
    rows = client.get(
        f"/api/v1/audit?since={past}&limit=2", headers=login(client, "amedina")
    ).json()
    assert len(rows) == 2
    too_many = client.get("/api/v1/audit?limit=5000", headers=login(client, "amedina"))
    assert too_many.status_code == 422


def test_the_trail_needs_a_session(client: TestClient) -> None:
    assert client.get("/api/v1/audit").status_code == 401
