"""The gate-skip suite (plan, day 13): every transition tried through the API, no UI.

Each stage is left only by the right role, only through its gate, only with a
written reason, and only forwards. Stages whose gate has not been built yet
are unreachable — the machine fails closed.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, AnalysisStatus, Stage
from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth.models import User
from app.core.clock import utc_now
from app.workflow import gates
from app.workflow import models as workflow_models
from tests.support import login, make_finding, seed_done_analysis

REASON = "Revisado el estado de la etapa; se puede avanzar."
PLAN = {
    "criterion": "decisions",
    "rationale": "Empezamos por la validación porque concentra los hallazgos.",
    "functions": [{"path": "src/file-0.js", "function": "validateForm", "line": 10}],
}


def _advance(client: TestClient, headers: dict[str, str], analysis_id: object, **body: Any) -> Any:
    payload = {"justification": REASON, **body}
    return client.post(
        f"/api/v1/analyses/{analysis_id}/stage/advance", json=payload, headers=headers
    )


def _verdict_all(client: TestClient, headers: dict[str, str], analysis: Analysis) -> None:
    for finding in analysis.findings:
        response = client.post(
            f"/api/v1/findings/{finding.id}/verdict",
            json={"verdict": "confirmed", "justification": REASON},
            headers=headers,
        )
        assert response.status_code == 200, response.text


def _stage(db: Session, analysis: Analysis) -> Stage:
    db.expire_all()
    stored = db.get(Analysis, analysis.id)
    assert stored is not None
    return stored.stage


def test_analysis_is_born_at_code(client: TestClient, analyst: User, db: Session) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    headers = login(client, analyst.username)
    body = client.get(f"/api/v1/analyses/{analysis.id}", headers=headers).json()
    assert body["stage"] == "code"


def test_code_cannot_be_left_before_the_pipeline_is_done(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [], status=AnalysisStatus.RUNNING)
    headers = login(client, analyst.username)
    response = _advance(client, headers, analysis.id)
    assert response.status_code == 409, response.text
    assert response.json() == {
        "code": "gate_closed",
        "message_key": "errors.workflow.gate.analysisNotDone",
    }
    assert _stage(db, analysis) is Stage.CODE
    assert db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "stage.advance")) is None


def test_analysis_cannot_be_left_with_a_pending_verdict(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0), make_finding(1)])
    headers = login(client, analyst.username)
    assert _advance(client, headers, analysis.id).status_code == 200  # code → analysis
    client.post(
        f"/api/v1/findings/{analysis.findings[0].id}/verdict",
        json={"verdict": "confirmed", "justification": REASON},
        headers=headers,
    )
    response = _advance(client, headers, analysis.id)
    assert response.status_code == 409
    assert response.json()["message_key"] == "errors.workflow.gate.triagePending"
    assert _stage(db, analysis) is Stage.ANALYSIS


def test_plan_cannot_be_left_without_a_test_plan(
    client: TestClient, analyst: User, developer: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)])
    analyst_headers = login(client, analyst.username)
    _advance(client, analyst_headers, analysis.id)
    _verdict_all(client, analyst_headers, analysis)
    assert _advance(client, analyst_headers, analysis.id).status_code == 200  # → plan
    developer_headers = login(client, developer.username)
    response = _advance(client, developer_headers, analysis.id)
    assert response.status_code == 409
    assert response.json()["message_key"] == "errors.workflow.gate.testPlanMissing"
    assert _stage(db, analysis) is Stage.PLAN


def test_full_walk_to_design_and_the_e5_gate_refuses_without_approval(
    client: TestClient, analyst: User, developer: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)], jail=tmp_path)
    analyst_headers = login(client, analyst.username)
    developer_headers = login(client, developer.username)

    assert _advance(client, analyst_headers, analysis.id).json()["stage"] == "analysis"
    _verdict_all(client, analyst_headers, analysis)
    assert _advance(client, analyst_headers, analysis.id).json()["stage"] == "plan"
    saved = client.put(
        f"/api/v1/analyses/{analysis.id}/test-plan", json=PLAN, headers=developer_headers
    )
    assert saved.status_code == 200, saved.text
    assert _advance(client, developer_headers, analysis.id).json()["stage"] == "design"

    # E5's gate: no planned function has approved cases yet (tests/test_cases_api.py
    # walks the approval and the transition to tests).
    blocked = _advance(client, developer_headers, analysis.id)
    assert blocked.status_code == 409
    assert blocked.json()["message_key"] == "errors.workflow.gate.casesNotApproved"
    assert _stage(db, analysis) is Stage.DESIGN

    rows = list(
        db.scalars(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "stage.advance")
            .order_by(AuditLogEntry.occurred_at)
        )
    )
    assert [row.target for row in rows] == [
        f"analysis:{analysis.id}:code->analysis",
        f"analysis:{analysis.id}:analysis->plan",
        f"analysis:{analysis.id}:plan->design",
    ]
    assert [row.actor_username for row in rows] == ["mmarin", "mmarin", "cperez"]
    assert all(row.justification == REASON for row in rows)


def test_leave_plan_checks_every_clause_of_the_plan(db: Session) -> None:
    # Defense in depth: the PUT rejects these first, the gate must still refuse them.
    analysis = seed_done_analysis(db, [])
    assert gates.leave_plan(analysis).reason == "test_plan_missing"
    analysis.test_plan = workflow_models.TestPlan(
        analysis_id=analysis.id, rationale="   ", functions=[], created_by_username="cperez"
    )
    assert gates.leave_plan(analysis).reason == "test_plan_missing"
    analysis.test_plan.functions = [{"path": "a.js", "function": "f", "line": 1, "ccn": 1}]
    assert gates.leave_plan(analysis).reason == "test_plan_missing"
    analysis.test_plan.rationale = "Porque sí, con razón escrita."
    assert gates.leave_plan(analysis).open is True
    analysis.test_plan.functions = []
    assert gates.leave_plan(analysis).open is False


def test_every_unbuilt_gate_is_closed() -> None:
    analysis = Analysis()
    # Every stage's gate is built now (P4 day 17 closed VERIFICATION): each
    # one is closed for its OWN reason on an empty analysis, never open by
    # default. REPORT still has no entry, and a missing entry is CLOSED.
    for stage in (Stage.DESIGN, Stage.TESTS, Stage.VERIFICATION):
        assert gates.check(stage, analysis).open is False, stage
    # REGISTER is the project's (always open); REPORT has no gate entry and
    # the default for a missing entry is CLOSED, never open.
    assert gates.check(Stage.REGISTER, analysis).open is True
    final = gates.check(Stage.REPORT, analysis)
    assert final.open is False and final.reason == "gate_not_built"


def test_wrong_role_cannot_leave_a_stage(
    client: TestClient, analyst: User, developer: User, admin: User, db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [make_finding(0)], jail=tmp_path)
    developer_headers = login(client, developer.username)
    # code: analyst or admin only
    assert _advance(client, developer_headers, analysis.id).status_code == 403
    admin_headers = login(client, admin.username)
    assert _advance(client, admin_headers, analysis.id).status_code == 200  # admin may leave code
    # analysis: analyst only
    analyst_headers = login(client, analyst.username)
    _verdict_all(client, analyst_headers, analysis)
    assert _advance(client, admin_headers, analysis.id).status_code == 403
    assert _advance(client, developer_headers, analysis.id).status_code == 403
    assert _advance(client, analyst_headers, analysis.id).status_code == 200
    # plan: developer only
    client.put(f"/api/v1/analyses/{analysis.id}/test-plan", json=PLAN, headers=developer_headers)
    assert _advance(client, analyst_headers, analysis.id).status_code == 403
    assert _advance(client, admin_headers, analysis.id).status_code == 403
    assert _stage(db, analysis) is Stage.PLAN

    denied = list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")))
    assert len(denied) == 5
    assert all(row.outcome is AuditOutcome.DENIED for row in denied)
    assert {row.target for row in denied} == {
        f"analysis:{analysis.id}:code->analysis",
        f"analysis:{analysis.id}:analysis->plan",
        f"analysis:{analysis.id}:plan->design",
    }


def test_role_is_checked_before_the_gate_and_the_reason_before_the_gate(
    client: TestClient, analyst: User, developer: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [], status=AnalysisStatus.RUNNING)
    # Wrong role on a closed gate: 403, never a hint about the gate.
    assert _advance(client, login(client, developer.username), analysis.id).status_code == 403
    # Right role, no reason: 422 before the gate is even consulted.
    response = _advance(client, login(client, analyst.username), analysis.id, justification="   ")
    assert response.status_code == 422 and response.json()["code"] == "justification_required"


def test_report_is_final_and_nothing_moves_backwards(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [])
    analysis.stage = Stage.REPORT
    db.commit()
    headers = login(client, analyst.username)
    response = _advance(client, headers, analysis.id)
    assert response.status_code == 409 and response.json()["code"] == "stage_final"
    assert _stage(db, analysis) is Stage.REPORT
    # There is no endpoint that sets a stage; the API surface is advance-only.
    for method, path in (
        ("post", f"/api/v1/analyses/{analysis.id}/stage/back"),
        ("put", f"/api/v1/analyses/{analysis.id}/stage"),
        ("patch", f"/api/v1/analyses/{analysis.id}"),
    ):
        assert getattr(client, method)(
            path, json={"stage": "code"}, headers=headers
        ).status_code in {
            404,
            405,
        }


def test_stage_is_the_analysis_own(client: TestClient, analyst: User, db: Session) -> None:
    first = seed_done_analysis(db, [])
    second = seed_done_analysis(db, [])
    headers = login(client, analyst.username)
    assert _advance(client, headers, first.id).status_code == 200
    assert _stage(db, first) is Stage.ANALYSIS
    assert _stage(db, second) is Stage.CODE


def test_unknown_analysis_is_404(client: TestClient, analyst: User) -> None:
    response = _advance(client, login(client, analyst.username), uuid.uuid4())
    assert response.status_code == 404


def test_leave_tests_checks_every_clause_of_its_own(db: Session) -> None:
    """Defense in depth, as for ``leave_plan``: each clause refuses on its own.

    ``all([])`` is True, so both the empty plan and an approved design with no
    case would OPEN a server-side gate if either guard were dropped.
    """
    analysis = seed_done_analysis(db, [])
    assert gates.leave_tests(analysis).reason == "test_plan_missing"
    analysis.test_plan = workflow_models.TestPlan(
        analysis_id=analysis.id,
        rationale="Porque sí, con razón escrita.",
        functions=[],
        created_by_username="cperez",
    )
    assert gates.leave_tests(analysis).reason == "test_plan_missing"

    row = {"path": "a.js", "function": "f", "line": 1, "ccn": 1}
    analysis.test_plan.functions = [row]
    assert gates.leave_tests(analysis).reason == "cases_not_approved"

    analysis.case_designs = [
        workflow_models.CaseDesign(
            path="a.js",
            function="f",
            line=1,
            cases=[],
            brief={"items": []},
            approved_at=utc_now(),
            approved_by_username="cperez",
            created_by_username="cperez",
        )
    ]
    analysis.test_files = [
        workflow_models.TestFile(
            path="a.js",
            function="f",
            line=1,
            filename="a.f.000000.dioptra.test.js",
            content="// nothing of mine\n",
            created_by_username="cperez",
        )
    ]
    db.flush()
    # A design with no case may not open the gate: there is nothing to have written.
    assert gates.leave_tests(analysis).reason == "tests_not_written"


def test_a_malformed_plan_row_closes_every_gate_and_raises_in_none(db: Session) -> None:
    """`planned_keys` exists for exactly this, and nothing tested it.

    Skipping a row that is not a dict would OPEN the gate for a function
    nobody checked; letting `row.get` run on it would turn a stage transition
    into a 500. Only `test_plan.save_test_plan` writes this column, so a row
    like these means the column was corrupted underneath us.
    """
    good: dict[str, Any] = {"path": "a.js", "function": "f", "line": 1, "ccn": 1}
    corrupted: list[list[Any]] = [[good, "not a dict"], [None], [[]], [good, 7]]
    for rows in corrupted:
        analysis = seed_done_analysis(db, [])
        analysis.test_plan = workflow_models.TestPlan(
            analysis_id=analysis.id,
            rationale="Porque sí, con razón escrita.",
            functions=rows,
            created_by_username="cperez",
        )
        db.flush()
        for gate in (gates.leave_design, gates.leave_tests, gates.leave_verification):
            result = gate(analysis)
            assert result.open is False, (gate.__name__, rows)

    # A `functions` column that is not a list at all is no plan.
    analysis = seed_done_analysis(db, [])
    analysis.test_plan = workflow_models.TestPlan(
        analysis_id=analysis.id,
        rationale="Porque sí, con razón escrita.",
        functions="nonsense",
        created_by_username="cperez",
    )
    db.flush()
    for gate in (gates.leave_design, gates.leave_tests, gates.leave_verification):
        assert gate(analysis).reason == "test_plan_missing", gate.__name__


def test_a_malformed_row_keeps_the_gate_shut_even_when_every_real_row_is_done(
    db: Session,
) -> None:
    """The exposure is a plan whose legitimate functions are ALL satisfied.

    Skipping the corrupt row would then leave nothing to check and the gate
    would OPEN for a function nobody ever looked at. That is why
    `planned_keys` emits an unmatchable key instead of dropping the row.
    """
    good: dict[str, Any] = {"path": "a.js", "function": "f", "line": 1, "ccn": 1}
    analysis = seed_done_analysis(db, [])
    analysis.test_plan = workflow_models.TestPlan(
        analysis_id=analysis.id,
        rationale="Porque si, con razon escrita.",
        functions=[good],
        created_by_username="cperez",
    )
    analysis.case_designs = [
        workflow_models.CaseDesign(
            path="a.js",
            function="f",
            line=1,
            cases=[{"title": "Un caso", "covers": []}],
            brief={"items": []},
            approved_at=utc_now(),
            approved_by_username="cperez",
            created_by_username="cperez",
        )
    ]
    analysis.verification_runs = [
        workflow_models.VerificationRun(
            analysis_id=analysis.id,
            path="a.js",
            function="f",
            line=1,
            status=workflow_models.VerificationStatus.PASSED,
            created_by_username="cperez",
        )
    ]
    db.flush()
    # Everything real is done, so both gates are open...
    assert gates.leave_design(analysis).open is True
    assert gates.leave_verification(analysis).open is True

    # ...and one corrupt row shuts them again.
    analysis.test_plan.functions = [good, "not a dict"]  # type: ignore[list-item]
    db.flush()
    assert gates.leave_design(analysis).reason == "cases_not_approved"
    assert gates.leave_verification(analysis).reason == "not_verified"
