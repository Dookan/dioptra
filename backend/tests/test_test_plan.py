"""E4 test plan: developer only, validated against the metrics, locked once E4 is left."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage, Verdict
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
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)], jail=tmp_path)
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
    assert all(row.target == f"analysis:{analysis.id}" for row in rows)
    assert all(row.actor_id == developer.id and row.actor_role == "developer" for row in rows)
    assert all(row.source_ip == "testclient" for row in rows)


def test_duplicates_are_folded_and_a_missing_ccn_defaults_to_one(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    rows: list[dict[str, object]] = [
        {"path": "src/a.js", "function": "alpha", "line": 1, "nloc": 3},  # Lizard row without ccn
        {"path": "src/b.js", "function": "beta", "line": 1, "nloc": 3, "ccn": 4},
    ]
    analysis = seed_done_analysis(db, [], functions=rows, jail=tmp_path)
    _at_plan(db, analysis)
    headers = login(client, developer.username)
    alpha = {"path": "src/a.js", "function": "alpha", "line": 1}
    beta = {"path": "src/b.js", "function": "beta", "line": 1}
    saved = _put(client, headers, analysis.id, functions=[alpha, alpha, beta])
    assert saved.status_code == 200, saved.text
    assert saved.json()["functions"] == [{**alpha, "ccn": 1}, {**beta, "ccn": 4}]


def test_the_planned_line_picks_the_function_when_names_repeat(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    # Two `dup` functions in one file: the first parses, the one the plan
    # names (line 5) is broken — the refusal must be about THAT one.
    rows: list[dict[str, object]] = [
        {"path": "src/dup.py", "function": "dup", "line": 1, "nloc": 2, "ccn": 1},
        {"path": "src/dup.py", "function": "dup", "line": 5, "nloc": 2, "ccn": 1},
    ]
    analysis = seed_done_analysis(db, [], functions=rows, jail=tmp_path)
    (tmp_path / "src" / "dup.py").write_text(
        "def dup(x):\n    return x\n\n\ndef dup(x):\n    if x\n        return 1\n"
    )
    _at_plan(db, analysis)
    headers = login(client, developer.username)
    first = {"path": "src/dup.py", "function": "dup", "line": 1}
    second = {"path": "src/dup.py", "function": "dup", "line": 5}
    assert _put(client, headers, analysis.id, functions=[first]).status_code == 200
    refused = _put(client, headers, analysis.id, functions=[second])
    assert refused.status_code == 422 and refused.json()["code"] == "test_plan_function_unbriefable"
    assert refused.json()["context"]["line"] == "5"


def test_plan_validation(client: TestClient, developer: User, db: Session, tmp_path: Path) -> None:
    analysis = seed_done_analysis(db, [], jail=tmp_path)
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


def test_unknown_function_detail_is_escaped_and_bounded(
    developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [], jail=tmp_path)
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
    client: TestClient, analyst: User, admin: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [], jail=tmp_path)
    _at_plan(db, analysis)
    for user in (analyst, admin):
        headers = login(client, user.username)
        assert _put(client, headers, analysis.id).status_code == 403, user.username
    assert db.scalar(select(workflow_models.TestPlan)) is None


def test_plan_is_refused_before_e4(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [], jail=tmp_path)
    headers = login(client, developer.username)
    for stage in (Stage.CODE, Stage.ANALYSIS):
        analysis.stage = stage
        db.commit()
        early = _put(client, headers, analysis.id)
        assert early.status_code == 409 and early.json()["code"] == "stage_not_reached", stage
    assert db.scalar(select(workflow_models.TestPlan)) is None


def test_plan_is_locked_once_e4_is_left(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [], jail=tmp_path)
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


def test_a_function_e5_could_never_approve_is_refused_at_e4(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    """Survey §8 addendum: without this, one bad function would strand the analysis at E5."""
    rows: list[dict[str, object]] = [
        {"path": "src/file-0.js", "function": "validateForm", "line": 10, "nloc": 4, "ccn": 1},
        {"path": "src/notes.rb", "function": "ruby", "line": 1, "nloc": 1, "ccn": 1},
        {"path": "src/broken.py", "function": "broken", "line": 1, "nloc": 3, "ccn": 2},
        {"path": "src/ghost.py", "function": "missing", "line": 1, "nloc": 1, "ccn": 1},
        {"path": "src/renamed.py", "function": "Klass::other", "line": 1, "nloc": 1, "ccn": 1},
        {"path": "src/wide.py", "function": "wide", "line": 1, "nloc": 205, "ccn": 3},
        {"path": "src/huge.py", "function": "big", "line": 1, "nloc": 2, "ccn": 1},
        {"path": "src/edge.py", "function": "edge", "line": 1, "nloc": 4, "ccn": 3},
    ]
    # `edge` has exactly MAX_CASES basis paths — fine alone, but the SAST
    # finding inside it makes min_cases 201: approval could never happen.
    analysis = seed_done_analysis(
        db, [make_finding(0, path="src/edge.py", line=2)], functions=rows, jail=tmp_path
    )
    (tmp_path / "src" / "edge.py").write_text(
        "def edge(x):\n    if " + " or ".join(f"x == {n}" for n in range(199)) + ":\n"
        "        return 1\n    return 0\n"
    )  # 1 + 199 `or` + the if = 200 basis paths
    (tmp_path / "src" / "notes.rb").write_text("def ruby; end\n")
    (tmp_path / "src" / "broken.py").write_text("def broken(x):\n    if x\n        return 1\n")
    (tmp_path / "src" / "ghost.py").unlink()
    (tmp_path / "src" / "renamed.py").write_text("def something_else():\n    return 1\n")
    # One condition with 250 `or`s: our complexity 252 > MAX_CASES on a graph of
    # four nodes, while Lizard's ccn column claims 3 — the parse is what decides.
    (tmp_path / "src" / "wide.py").write_text(
        "def wide(x):\n    if " + " or ".join(f"x == {n}" for n in range(251)) + ":\n"
        "        return 1\n    return 0\n"
    )
    (tmp_path / "src" / "huge.py").write_text("def big():\n    return 1\n" + "#" * (600 * 1024))
    _at_plan(db, analysis)
    headers = login(client, developer.username)

    expected = {
        "notes.rb": ("test_plan_function_unbriefable", "ruby"),
        "broken.py": ("test_plan_function_unbriefable", "broken"),
        "ghost.py": ("test_plan_function_unbriefable", "missing"),
        "renamed.py": ("test_plan_function_unbriefable", "Klass::other"),
        "wide.py": ("test_plan_function_too_complex", "wide"),
        "huge.py": ("test_plan_function_unbriefable", "big"),
        "edge.py": ("test_plan_function_too_complex", "edge"),
    }
    for row in rows[1:]:
        both = [ONE[0], {"path": row["path"], "function": row["function"], "line": row["line"]}]
        refused = _put(client, headers, analysis.id, functions=both)
        code, name = expected[str(row["path"]).rsplit("/", 1)[1]]
        assert refused.status_code == 422, refused.text
        assert refused.json()["code"] == code, row
        # The UI names the function from the context; the strings are text, bounded.
        assert refused.json()["context"] == {
            "path": row["path"],
            "function": name,
            "line": str(row["line"]),
        }
    # Nothing was stored by any refused body, and the parseable function alone is fine.
    assert db.scalar(select(workflow_models.TestPlan)) is None
    assert db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "testplan.save")) is None
    assert _put(client, headers, analysis.id).status_code == 200
    # The same function is fine once the finding is a false positive (min_cases 200).
    analysis.findings[0].verdict = Verdict.FALSE_POSITIVE
    db.commit()
    accepted = _put(client, headers, analysis.id, functions=[ONE[0], rows[-1]])
    assert accepted.status_code == 200, accepted.text
    analysis.findings[0].verdict = None
    db.commit()
    # The stage check and the metrics check come before any parse.
    analysis.stage = Stage.DESIGN
    db.commit()
    locked = _put(client, headers, analysis.id, functions=[ONE[0], rows[2]])
    assert locked.status_code == 409 and locked.json()["code"] == "stage_locked"
    assert "context" not in locked.json()


def test_save_attaches_the_plan_to_the_analysis_in_the_same_session(
    developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [], jail=tmp_path)
    _at_plan(db, analysis)
    plan = save_test_plan(
        db,
        analysis=analysis,
        actor=developer,
        criterion=CoverageCriterion.DECISIONS,
        rationale=RATIONALE,
        functions=ONE,
        source_ip=None,
    )
    # The gate that follows in the same request reads analysis.test_plan.
    assert analysis.test_plan is plan and plan.analysis_id == analysis.id


def test_an_analysis_without_metrics_knows_no_function(developer: User, db: Session) -> None:
    analysis = seed_done_analysis(db, [])
    analysis.metrics = None
    _at_plan(db, analysis)
    with pytest.raises(workflow_errors.TestPlanFunctionUnknown):
        save_test_plan(
            db,
            analysis=analysis,
            actor=developer,
            criterion=CoverageCriterion.DECISIONS,
            rationale=RATIONALE,
            functions=ONE,
            source_ip=None,
        )


def test_unknown_function_never_reaches_the_parser(developer: User, db: Session) -> None:
    # No jail at all: a function outside the metrics is "unknown", not "unbriefable".
    analysis = seed_done_analysis(db, [])
    _at_plan(db, analysis)
    with pytest.raises(workflow_errors.TestPlanFunctionUnknown):
        save_test_plan(
            db,
            analysis=analysis,
            actor=developer,
            criterion=CoverageCriterion.DECISIONS,
            rationale=RATIONALE,
            functions=[{"path": "src/ghost.js", "function": "x", "line": 1}],
            source_ip=None,
        )
    with pytest.raises(workflow_errors.TestPlanFunctionUnbriefable) as info:
        save_test_plan(
            db,
            analysis=analysis,
            actor=developer,
            criterion=CoverageCriterion.DECISIONS,
            rationale=RATIONALE,
            functions=ONE,
            source_ip=None,
        )
    assert info.value.context == {"path": "src/file-0.js", "function": "validateForm", "line": "10"}
    assert workflow_errors.TestPlanFunctionUnbriefable("p.py", "f", None, "x").context == {
        "path": "p.py",
        "function": "f",
        "line": "",
    }
