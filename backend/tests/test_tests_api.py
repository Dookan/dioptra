"""E6 through the API: the scaffold, the developer's file, the roles and the gate.

The gate is proven the way the plan asks (day 13): the transition is attempted
through the API directly, with no UI, and is refused until every approved case
has a body the developer wrote.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.core.clock import utc_now
from app.workflow import gates
from app.workflow import models as workflow_models
from tests.support import login, seed_done_analysis

FIXTURES = Path(__file__).parent / "fixtures" / "ast"
WIDTH: dict[str, Any] = {"path": "src/width-class.ts", "function": "widthClass", "line": 3}
FUNCTIONS: list[dict[str, object]] = [{**WIDTH, "nloc": 5, "ccn": 3}]
REASON = "Los tests de cada caso están escritos."

CASES = [
    {"title": "Total cero devuelve w0", "covers": ["R1", "R2", "F1", "F2"]},
    {"title": "Parte cero devuelve w0", "covers": []},
    {"title": "Mitad devuelve w50", "covers": []},
]


def _analysis_at_tests(db: Session, tmp_path: Path, *, stage: Stage = Stage.TESTS) -> Analysis:
    jail = tmp_path / "jail"
    (jail / "src").mkdir(parents=True)
    (jail / "src" / "width-class.ts").write_bytes((FIXTURES / "real_width_class.ts").read_bytes())
    analysis = seed_done_analysis(db, [], functions=FUNCTIONS)
    analysis.workspace_path = str(jail)
    analysis.stage = stage
    analysis.test_plan = workflow_models.TestPlan(
        analysis_id=analysis.id,
        rationale="Plan de prueba.",
        functions=list(FUNCTIONS),
        created_by_username="cperez",
    )
    analysis.case_designs = [
        workflow_models.CaseDesign(
            path=str(WIDTH["path"]),
            function=str(WIDTH["function"]),
            line=int(str(WIDTH["line"])),
            cases=CASES,
            brief={"items": [{"id": "R1", "kind": "branch", "line": 4, "text": "whole <= 0"}]},
            approved_at=utc_now(),
            approved_by_username="cperez",
            created_by_username="cperez",
        )
    ]
    db.commit()
    return analysis


def _scaffold(client: TestClient, headers: dict[str, str], analysis_id: object) -> Any:
    return client.get(f"/api/v1/analyses/{analysis_id}/scaffold", params=WIDTH, headers=headers)


def _put(client: TestClient, headers: dict[str, str], analysis_id: object, content: str) -> Any:
    return client.put(
        f"/api/v1/analyses/{analysis_id}/tests",
        json={**WIDTH, "content": content},
        headers=headers,
    )


def _advance(client: TestClient, headers: dict[str, str], analysis_id: object) -> Any:
    return client.post(
        f"/api/v1/analyses/{analysis_id}/stage/advance",
        json={"justification": REASON},
        headers=headers,
    )


def _written(scaffold: str) -> str:
    """The scaffold with one real statement inside every case — a developer's file."""
    return scaffold.replace(
        "    // TODO(developer): write this case.",
        "    expect(widthClass(1, 2)).toBe('w50');",
    )


def test_the_scaffold_is_offered_to_every_role_and_written_only_by_the_developer(
    client: TestClient, developer: User, analyst: User, admin: User, db: Session, tmp_path: Path
) -> None:
    analysis = _analysis_at_tests(db, tmp_path)
    for user in (developer, analyst, admin):
        response = _scaffold(client, login(client, user.username), analysis.id)
        assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["filename"] == "width_class.widthclass.6a467e.dioptra.test.ts"
    assert payload["runner"] == "vitest" and payload["content"] == ""
    assert [case["id"] for case in payload["cases"]] == ["C1", "C2", "C3"]
    assert not any(case["written"] for case in payload["cases"])

    for user in (analyst, admin):
        refused = _put(client, login(client, user.username), analysis.id, payload["scaffold"])
        assert refused.status_code == 403, refused.text
    assert client.get(f"/api/v1/analyses/{analysis.id}/scaffold", params=WIDTH).status_code == 401


def test_the_gate_opens_only_when_every_case_has_a_body(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _analysis_at_tests(db, tmp_path)
    headers = login(client, developer.username)
    scaffold = _scaffold(client, headers, analysis.id).json()["scaffold"]

    # The untouched scaffold is not a written test: the gate stays closed.
    stored = _put(client, headers, analysis.id, scaffold)
    assert stored.status_code == 200, stored.text
    assert not any(case["written"] for case in stored.json()["cases"])
    assert gates.check(Stage.TESTS, analysis).reason == "tests_not_written"
    blocked = _advance(client, headers, analysis.id)
    assert blocked.status_code == 409 and blocked.json()["code"] == "gate_closed"
    db.refresh(analysis)
    assert analysis.stage is Stage.TESTS

    # One case still empty is still closed.
    partial = _written(scaffold).replace(
        "    expect(widthClass(1, 2)).toBe('w50');",
        "    // TODO(developer): write this case.",
        1,
    )
    body = _put(client, headers, analysis.id, partial).json()
    assert [case["written"] for case in body["cases"]] == [False, True, True]
    assert _advance(client, headers, analysis.id).status_code == 409

    # Every case written: the gate opens and the stage moves once.
    complete = _put(client, headers, analysis.id, _written(scaffold))
    assert all(case["written"] for case in complete.json()["cases"])
    assert gates.check(Stage.TESTS, analysis).open
    moved = _advance(client, headers, analysis.id)
    assert moved.status_code == 200, moved.text
    assert moved.json()["stage"] == Stage.VERIFICATION.value

    entry = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "tests.save")).first()
    assert entry is not None and entry.actor_username == "cperez"
    assert "widthClass" in str(entry.target)


def test_the_file_is_only_writable_at_e6(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    early = _analysis_at_tests(db, tmp_path, stage=Stage.DESIGN)
    headers = login(client, developer.username)
    scaffold = _scaffold(client, headers, early.id).json()["scaffold"]
    too_early = _put(client, headers, early.id, scaffold)
    assert too_early.status_code == 409 and too_early.json()["code"] == "stage_not_reached"

    late = _analysis_at_tests(db, tmp_path / "late", stage=Stage.REPORT)
    locked = _put(client, headers, late.id, scaffold)
    assert locked.status_code == 409 and locked.json()["code"] == "stage_locked"
    assert db.scalars(select(workflow_models.TestFile)).first() is None


def test_a_stored_file_that_does_not_parse_leaves_every_case_unwritten(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _analysis_at_tests(db, tmp_path)
    headers = login(client, developer.username)
    broken = _put(client, headers, analysis.id, "it('C1 · x', () => { const ")
    assert broken.status_code == 200, broken.text
    payload = broken.json()
    assert payload["parse_error"] is True
    assert not any(case["written"] for case in payload["cases"])
    # The gate may not raise on unparsable text — it simply stays closed.
    assert gates.check(Stage.TESTS, analysis).reason == "tests_not_written"

    states = client.get(f"/api/v1/analyses/{analysis.id}/test-files", headers=headers).json()
    assert states == [
        {**WIDTH, "cases": 3, "written": 0, "parse_error": True},
    ]


def test_only_a_reopened_function_is_writable_at_verification(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    """The E7 → E5 loop reopens ONE function without moving the stage backwards.

    `tasks/phase4-survey.md` §4 names this test: a reopened function is
    editable at E7 and no other one is.
    """
    analysis = _analysis_at_tests(db, tmp_path, stage=Stage.VERIFICATION)
    headers = login(client, developer.username)
    scaffold = _scaffold(client, headers, analysis.id).json()["scaffold"]

    # Nothing reopened yet: the deliverable of a stage already left is locked.
    locked = _put(client, headers, analysis.id, scaffold)
    assert locked.status_code == 409 and locked.json()["code"] == "stage_locked"

    analysis.case_designs[0].reopened_at = utc_now()
    db.commit()
    reopened = _put(client, headers, analysis.id, _written(scaffold))
    assert reopened.status_code == 200, reopened.text
    assert all(case["written"] for case in reopened.json()["cases"])

    # A second planned function that was NOT reopened stays locked.
    other = {"path": "src/other.js", "function": "otra", "line": 2}
    (Path(str(analysis.workspace_path)) / "src" / "other.js").write_text(
        "export function otra(x) {\n  if (x > 0) return 1;\n  return 0;\n}\n"
    )
    plan = analysis.test_plan
    assert plan is not None
    plan.functions = [*FUNCTIONS, {**other, "nloc": 4, "ccn": 2}]
    analysis.case_designs.append(
        workflow_models.CaseDesign(
            path=str(other["path"]),
            function=str(other["function"]),
            line=int(str(other["line"])),
            cases=[{"title": "Un caso", "covers": []}],
            brief={"items": []},
            approved_at=utc_now(),
            approved_by_username="cperez",
            created_by_username="cperez",
        )
    )
    db.commit()
    still_locked = client.put(
        f"/api/v1/analyses/{analysis.id}/tests",
        json={**other, "content": "it('C1 · x', () => { const a = 1; });\n"},
        headers=headers,
    )
    assert still_locked.status_code == 409
    assert still_locked.json()["code"] == "stage_locked"
