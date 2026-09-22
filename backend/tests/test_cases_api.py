"""E5 day 15 through the API: the brief, the developer's cases, the approval and the gate.

The E5 gate is proven the way the plan asks (day 13): trying to leave the
stage through the API directly, with no UI, and being refused until every
planned function has its cases approved.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.workflow import design, gates
from app.workflow import errors as workflow_errors
from app.workflow import models as workflow_models
from app.workflow.models import MAX_CASES
from tests.support import login, make_finding, seed_done_analysis

FIXTURES = Path(__file__).parent / "fixtures" / "ast"
WIDTH: dict[str, Any] = {"path": "src/width-class.ts", "function": "widthClass", "line": 3}
ESCAPE: dict[str, Any] = {"path": "src/escape.py", "function": "mermaid_escape", "line": 7}
FUNCTIONS: list[dict[str, object]] = [
    {**WIDTH, "nloc": 5, "ccn": 3},
    {**ESCAPE, "nloc": 14, "ccn": 7},
    {"path": "src/other.py", "function": "unplanned", "line": 1, "nloc": 2, "ccn": 1},
]
REASON = "Casos aprobados para cada función del plan."


def _jailed_analysis(db: Session, tmp_path: Path, *, with_finding: bool = False) -> Analysis:
    jail = tmp_path / "jail"
    (jail / "src").mkdir(parents=True)
    (jail / "src" / "width-class.ts").write_bytes((FIXTURES / "real_width_class.ts").read_bytes())
    (jail / "src" / "escape.py").write_bytes((FIXTURES / "real_mermaid_escape.py").read_bytes())
    (jail / "src" / "other.py").write_text("def unplanned():\n    return 1\n")
    findings = [make_finding(0, path="src/width-class.ts", line=4)] if with_finding else []
    analysis = seed_done_analysis(db, findings, functions=FUNCTIONS)
    analysis.workspace_path = str(jail)
    analysis.stage = Stage.DESIGN
    analysis.test_plan = workflow_models.TestPlan(
        analysis_id=analysis.id,
        rationale="Plan de prueba.",
        functions=[row for row in FUNCTIONS if row["function"] != "unplanned"],
        created_by_username="cperez",
    )
    db.commit()
    return analysis


def _brief(
    client: TestClient, headers: dict[str, str], analysis_id: object, ref: dict[str, Any]
) -> Any:
    return client.get(f"/api/v1/analyses/{analysis_id}/brief", params=ref, headers=headers)


def _put(
    client: TestClient,
    headers: dict[str, str],
    analysis_id: object,
    ref: dict[str, Any],
    cases: list[Any],
) -> Any:
    return client.put(
        f"/api/v1/analyses/{analysis_id}/cases", json={**ref, "cases": cases}, headers=headers
    )


def _approve(
    client: TestClient, headers: dict[str, str], analysis_id: object, ref: dict[str, Any]
) -> Any:
    return client.post(f"/api/v1/analyses/{analysis_id}/cases/approve", json=ref, headers=headers)


def _advance(client: TestClient, headers: dict[str, str], analysis_id: object) -> Any:
    return client.post(
        f"/api/v1/analyses/{analysis_id}/stage/advance",
        json={"justification": REASON},
        headers=headers,
    )


def _covering_cases(brief: dict[str, Any]) -> list[dict[str, Any]]:
    """One case per item, then padding up to ``min_cases`` — enough to approve."""
    cases = [
        {"title": f"Caso para {item['id']}", "covers": [item["id"]]} for item in brief["items"]
    ]
    while len(cases) < brief["min_cases"]:
        cases.append({"title": f"Caso extra {len(cases) + 1}", "covers": []})
    return cases


def test_brief_of_a_planned_function_for_every_role(
    client: TestClient, developer: User, analyst: User, admin: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path, with_finding=True)
    for user in (developer, analyst, admin):
        response = _brief(client, login(client, user.username), analysis.id, WIDTH)
        assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["cases"] == [] and payload["approved_at"] is None
    brief = payload["brief"]
    assert brief["complexity"] == 3 and brief["min_cases"] == 4  # + one SAST finding inside
    assert [item["id"] for item in brief["items"]] == ["R1", "R2", "F1", "F2", "E1", "M1"]
    assert brief["items"][-1]["text"] == "Hallazgo 0"

    unplanned = _brief(
        client,
        login(client, developer.username),
        analysis.id,
        {"path": "src/other.py", "function": "unplanned", "line": 1},
    )
    assert unplanned.status_code == 422 and unplanned.json()["code"] == "ast_function_not_in_plan"
    assert client.get(f"/api/v1/analyses/{analysis.id}/brief", params=WIDTH).status_code == 401


def test_cases_are_validated_against_the_live_brief(
    client: TestClient, developer: User, analyst: User, admin: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)
    hostile = "C1 · <script>alert(1)</script> con \x00 y   espacios\r\n"
    saved = _put(
        client, headers, analysis.id, WIDTH, [{"title": hostile, "covers": ["R1", "F1", "R1"]}]
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["cases"] == [
        {"title": "C1 · <script>alert(1)</script> con y espacios", "covers": ["R1", "F1"]}
    ]
    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "design.cases.save")
    ).one()
    assert entry.actor_username == "cperez" and "widthClass" in str(entry.target)

    unknown = _put(client, headers, analysis.id, WIDTH, [{"title": "Caso", "covers": ["Z9"]}])
    assert unknown.status_code == 422 and unknown.json()["code"] == "case_item_unknown"
    short = _put(client, headers, analysis.id, WIDTH, [{"title": "  ab ", "covers": []}])
    assert short.status_code == 422 and short.json()["code"] == "cases_invalid"
    long_title = _put(client, headers, analysis.id, WIDTH, [{"title": "x" * 501, "covers": []}])
    assert long_title.status_code == 422 and long_title.json()["code"] == "cases_invalid"
    # The schema and the service share MAX_CASES: one case past it fails validation.
    many = _put(client, headers, analysis.id, WIDTH, [{"title": "Caso"}] * (MAX_CASES + 1))
    assert many.status_code == 422 and many.json()["code"] == "validation_failed"
    # An item id of another function's brief is unknown here.
    foreign = _put(client, headers, analysis.id, WIDTH, [{"title": "Caso", "covers": ["R7"]}])
    assert foreign.status_code == 422 and foreign.json()["code"] == "case_item_unknown"
    # Nothing of the refused bodies was stored.
    db.expire_all()
    row = db.scalars(select(workflow_models.CaseDesign)).one()
    assert len(row.cases) == 1
    exact = _put(client, headers, analysis.id, WIDTH, [{"title": "Caso"}] * MAX_CASES)
    assert exact.status_code == 200 and len(exact.json()["cases"]) == MAX_CASES
    bounds = _put(client, headers, analysis.id, WIDTH, [{"title": "abc"}, {"title": "x" * 500}])
    assert bounds.status_code == 200
    assert [len(c["title"]) for c in bounds.json()["cases"]] == [3, 500]

    for other in (analyst, admin):
        other_headers = login(client, other.username)
        assert _put(client, other_headers, analysis.id, WIDTH, []).status_code == 403
        assert _approve(client, other_headers, analysis.id, WIDTH).status_code == 403
    assert (
        len(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")).all())
        == 4
    )
    unplanned = _put(
        client,
        headers,
        analysis.id,
        {"path": "src/other.py", "function": "unplanned", "line": 1},
        [],
    )
    assert unplanned.status_code == 422 and unplanned.json()["code"] == "ast_function_not_in_plan"

    analysis.stage = Stage.PLAN
    db.commit()
    early = _put(client, headers, analysis.id, WIDTH, [])
    assert early.status_code == 409 and early.json()["code"] == "stage_not_reached"
    early_approve = _approve(client, headers, analysis.id, WIDTH)
    assert early_approve.status_code == 409 and early_approve.json()["code"] == "stage_not_reached"
    analysis.stage = Stage.TESTS
    db.commit()
    late = _put(client, headers, analysis.id, WIDTH, [])
    assert late.status_code == 409 and late.json()["code"] == "stage_locked"


def test_approval_needs_every_item_and_enough_cases(
    client: TestClient, developer: User, analyst: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)
    brief = _brief(client, headers, analysis.id, WIDTH).json()["brief"]
    cases = _covering_cases(brief)

    nothing = _approve(client, headers, analysis.id, WIDTH)
    assert nothing.status_code == 422 and nothing.json()["code"] == "brief_not_covered"

    _put(client, headers, analysis.id, WIDTH, cases[:-1] + [{**cases[-1], "covers": []}])
    uncovered = _approve(client, headers, analysis.id, WIDTH)
    assert uncovered.status_code == 422 and uncovered.json()["code"] == "brief_not_covered"

    # Every item covered but one case short of the basis paths (min_cases 3).
    two = [
        {"title": "Un caso para casi todo", "covers": [item["id"] for item in brief["items"]]},
        {"title": "Otro caso más", "covers": []},
    ]
    assert brief["min_cases"] == 3 and len(two) == brief["min_cases"] - 1
    _put(client, headers, analysis.id, WIDTH, two)
    few = _approve(client, headers, analysis.id, WIDTH)
    assert few.status_code == 422 and few.json()["code"] == "cases_too_few"
    assert not db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "design.cases.approve")
    ).all()

    _put(client, headers, analysis.id, WIDTH, cases)
    denied = _approve(client, login(client, analyst.username), analysis.id, WIDTH)
    assert denied.status_code == 403
    approved = _approve(client, headers, analysis.id, WIDTH)
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_by_username"] == "cperez"
    assert approved.json()["approved_at"] is not None
    db.expire_all()
    row = db.scalars(select(workflow_models.CaseDesign)).one()
    assert row.brief is not None and row.brief["min_cases"] == 3
    assert [item["id"] for item in row.brief["items"]] == ["R1", "R2", "F1", "F2", "E1"]
    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "design.cases.approve")
    ).one()
    assert entry.actor_username == "cperez"

    # Approving again is idempotent; editing the cases reopens the approval.
    assert _approve(client, headers, analysis.id, WIDTH).status_code == 200
    edited = _put(client, headers, analysis.id, WIDTH, cases)
    assert edited.status_code == 200 and edited.json()["approved_at"] is None
    db.expire_all()
    row = db.scalars(select(workflow_models.CaseDesign)).one()
    assert row.brief is None and row.approved_at is None and row.approved_by_username is None

    analysis.stage = Stage.TESTS
    db.commit()
    late = _approve(client, headers, analysis.id, WIDTH)
    assert late.status_code == 409 and late.json()["code"] == "stage_locked"


def test_design_cannot_be_left_until_every_planned_function_is_approved(
    client: TestClient, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    headers = login(client, developer.username)

    blocked = _advance(client, headers, analysis.id)
    assert blocked.status_code == 409
    assert blocked.json()["message_key"] == "errors.workflow.gate.casesNotApproved"

    for ref in (WIDTH,):
        brief = _brief(client, headers, analysis.id, ref).json()["brief"]
        _put(client, headers, analysis.id, ref, _covering_cases(brief))
        assert _approve(client, headers, analysis.id, ref).status_code == 200
    # One of two planned functions approved: still closed.
    still = _advance(client, headers, analysis.id)
    assert still.status_code == 409
    assert still.json()["message_key"] == "errors.workflow.gate.casesNotApproved"
    db.expire_all()
    assert gates.leave_design(analysis).open is False

    states = client.get(f"/api/v1/analyses/{analysis.id}/case-designs", headers=headers)
    assert states.status_code == 200
    assert [(s["function"], s["cases"], s["approved_by_username"]) for s in states.json()] == [
        ("widthClass", 5, "cperez"),
        ("mermaid_escape", 0, None),
    ]

    brief = _brief(client, headers, analysis.id, ESCAPE).json()["brief"]
    assert brief["min_cases"] == 7
    _put(client, headers, analysis.id, ESCAPE, _covering_cases(brief))
    assert _approve(client, headers, analysis.id, ESCAPE).status_code == 200
    db.expire_all()
    assert gates.leave_design(analysis).open is True
    left = _advance(client, headers, analysis.id)
    assert left.status_code == 200, left.text
    assert left.json()["stage"] == "tests"

    # E6's gate is built (P4 day 16) and closed: no test file has been stored.
    assert (
        _advance(client, headers, analysis.id).json()["message_key"]
        == "errors.workflow.gate.testsNotWritten"
    )
    db.expire_all()
    assert analysis.stage is Stage.TESTS
    # The approved design is locked with the stage.
    late = _put(client, headers, analysis.id, WIDTH, [])
    assert late.status_code == 409 and late.json()["code"] == "stage_locked"


def test_clean_cases_caps_the_count_itself(db: Session, tmp_path: Path) -> None:
    # Defense in depth: the schema refuses first, the service must refuse too.
    analysis = _jailed_analysis(db, tmp_path)
    brief = design.brief_for(analysis, design.FunctionRef(**WIDTH))
    assert len(design.clean_cases([{"title": "Caso"}] * MAX_CASES, brief)) == MAX_CASES
    with pytest.raises(workflow_errors.CasesInvalid):
        design.clean_cases([{"title": "Caso"}] * (MAX_CASES + 1), brief)


def test_leave_design_is_pure_and_matches_by_function_key(db: Session, tmp_path: Path) -> None:
    analysis = _jailed_analysis(db, tmp_path)
    assert gates.leave_design(analysis).reason == "cases_not_approved"
    # A row for the function but not approved, or approved for another line: closed.
    analysis.case_designs.append(
        workflow_models.CaseDesign(
            analysis_id=analysis.id, created_by_username="cperez", cases=[], **WIDTH
        )
    )
    analysis.case_designs.append(
        workflow_models.CaseDesign(
            analysis_id=analysis.id,
            created_by_username="cperez",
            cases=[],
            approved_at=analysis.created_at,
            approved_by_username="cperez",
            path=ESCAPE["path"],
            function=ESCAPE["function"],
            line=99,
        )
    )
    db.commit()
    db.expire_all()
    assert gates.leave_design(analysis).reason == "cases_not_approved"
    for row_design in analysis.case_designs:
        row_design.approved_at = analysis.created_at
        row_design.approved_by_username = "cperez"
    analysis.case_designs[1].line = ESCAPE["line"]
    db.commit()
    db.expire_all()
    assert gates.leave_design(analysis).open is True
    # No plan at all is the plan's own reason, not a silent pass.
    analysis.test_plan = None
    db.commit()
    db.expire_all()
    assert gates.leave_design(analysis).reason == "test_plan_missing"
