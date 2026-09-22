"""E4 test plan: developer only, validated against the metrics, locked once E4 is left."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.workflow import errors as workflow_errors
from app.workflow import models as workflow_models
from app.workflow.models import CoverageCriterion
from app.workflow.test_plan import save_test_plan
from tests.support import login, make_finding, seed_done_analysis

RATIONALE = "Empezamos por la validación porque concentra los hallazgos."
ONE = [{"path": "src/file-0.js", "function": "validateForm", "line": 10}]


def _put(client: TestClient, headers: dict[str, str], analysis_id: object, **body: Any) -> Any:
    payload = {"criterion": "decisions", "rationale": RATIONALE, "functions": ONE, **body}
    return client.put(f"/api/v1/analyses/{analysis_id}/test-plan", json=payload, headers=headers)


def _at_plan(db: Session, analysis: Analysis) -> None:
    analysis.stage = Stage.PLAN
    db.commit()


def test_developer_saves_and_replaces_the_plan(
    client: TestClient, developer: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    _at_plan(db, analysis)
    headers = login(client, developer.username)
    assert (
        client.get(f"/api/v1/analyses/{analysis.id}/test-plan", headers=headers).status_code == 404
    )

    created = _put(client, headers, analysis.id)
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["criterion"] == "decisions" and body["rationale"] == RATIONALE
    assert body["functions"] == [
        {"path": "src/file-0.js", "function": "validateForm", "line": 10, "ccn": 12}
    ]
    assert body["created_by_username"] == "cperez"

    replaced = _put(
        client,
        headers,
        analysis.id,
        criterion="paths",
        functions=[*ONE, {"path": "src/utils.js", "function": "formatDate", "line": 3}, *ONE],
    )
    assert replaced.status_code == 200
    assert replaced.json()["criterion"] == "paths"
    assert [f["function"] for f in replaced.json()["functions"]] == ["validateForm", "formatDate"]
    assert (
        db.scalar(select(workflow_models.TestPlan)) is not None
        and len(list(db.scalars(select(workflow_models.TestPlan)))) == 1
    )

    fetched = client.get(f"/api/v1/analyses/{analysis.id}/test-plan", headers=headers)
    assert fetched.status_code == 200 and fetched.json()["criterion"] == "paths"
    rows = list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "testplan.save")))
    assert len(rows) == 2 and all(row.justification == RATIONALE for row in rows)


def test_plan_validation(client: TestClient, developer: User, db: Session) -> None:
    analysis = seed_done_analysis(db, [])
    _at_plan(db, analysis)
    headers = login(client, developer.username)
    empty = _put(client, headers, analysis.id, functions=[])
    assert empty.status_code == 422 and empty.json()["code"] == "test_plan_empty"
    unknown = _put(
        client,
        headers,
        analysis.id,
        functions=[{"path": "src/ghost.js", "function": "x", "line": 1}],
    )
    assert unknown.status_code == 422 and unknown.json()["code"] == "test_plan_function_unknown"
    wrong_line = _put(
        client,
        headers,
        analysis.id,
        functions=[{"path": "src/file-0.js", "function": "validateForm", "line": 11}],
    )
    assert wrong_line.status_code == 422
    assert wrong_line.json()["code"] == "test_plan_function_unknown"
    blank = _put(client, headers, analysis.id, rationale="  ok ")
    assert blank.status_code == 422 and blank.json()["code"] == "justification_required"
    criterion = _put(client, headers, analysis.id, criterion="vibes")
    assert criterion.status_code == 422 and criterion.json()["code"] == "validation_failed"
    assert db.scalar(select(workflow_models.TestPlan)) is None


def test_unknown_function_detail_is_escaped_and_bounded(developer: User, db: Session) -> None:
    analysis = seed_done_analysis(db, [])
    _at_plan(db, analysis)
    hostile = "a\nb" + "x" * 300
    with pytest.raises(workflow_errors.TestPlanFunctionUnknown) as excinfo:
        save_test_plan(
            db,
            analysis=analysis,
            actor=developer,
            criterion=CoverageCriterion.DECISIONS,
            rationale=RATIONALE,
            functions=[{"path": hostile, "function": "f", "line": 1}],
            source_ip=None,
        )
    detail = str(excinfo.value)
    assert "\\n" in detail and "\n" not in detail  # repr-escaped: one log line
    assert len(detail) <= 200


def test_analyst_and_admin_cannot_write_the_plan(
    client: TestClient, analyst: User, admin: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [])
    _at_plan(db, analysis)
    for user in (analyst, admin):
        headers = login(client, user.username)
        assert _put(client, headers, analysis.id).status_code == 403, user.username
    assert db.scalar(select(workflow_models.TestPlan)) is None


def test_plan_is_refused_before_e4(client: TestClient, developer: User, db: Session) -> None:
    analysis = seed_done_analysis(db, [])
    headers = login(client, developer.username)
    for stage in (Stage.CODE, Stage.ANALYSIS):
        analysis.stage = stage
        db.commit()
        early = _put(client, headers, analysis.id)
        assert early.status_code == 409 and early.json()["code"] == "stage_not_reached", stage
    assert db.scalar(select(workflow_models.TestPlan)) is None


def test_plan_is_locked_once_e4_is_left(client: TestClient, developer: User, db: Session) -> None:
    analysis = seed_done_analysis(db, [])
    _at_plan(db, analysis)
    headers = login(client, developer.username)
    assert _put(client, headers, analysis.id).status_code == 200
    analysis.stage = Stage.DESIGN
    db.commit()
    locked = _put(client, headers, analysis.id, criterion="statements")
    assert locked.status_code == 409 and locked.json()["code"] == "stage_locked"
    db.expire_all()
    plan = db.scalars(select(workflow_models.TestPlan)).one()
    assert plan.criterion.value == "decisions"
