"""E7: the re-audit, the gate and the E7 → E5 loop.

The sandbox itself is faked here — what is under test is the verdict: a
failing test, a case that asserts nothing, coverage short of the E4 criterion,
a brief item whose line never ran, and a surviving mutant each close the gate
on their own, and each one is shown to the developer by name.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.sandbox.executor import SandboxResult
from app.sandbox.workspace import Attempt
from app.workflow import gates, verify
from app.workflow import models as workflow_models
from app.workflow.models import VerificationStatus
from tests.support import login, seed_done_analysis

FIXTURES = Path(__file__).parent / "fixtures" / "ast"
WIDTH: dict[str, Any] = {"path": "src/width-class.ts", "function": "widthClass", "line": 3}
FUNCTIONS: list[dict[str, object]] = [{**WIDTH, "nloc": 5, "ccn": 3}]
REASON = "Los tests corren en verde y cubren la consigna."

BRIEF = {
    "items": [
        {"id": "R1", "kind": "branch", "line": 4, "text": "whole <= 0", "detail": "true"},
        {"id": "R2", "kind": "branch", "line": 4, "text": "whole <= 0", "detail": "false"},
    ]
}
CASES = [
    {"title": "Total cero", "covers": ["R1"]},
    {"title": "Total positivo", "covers": ["R2"]},
    {"title": "Mitad", "covers": []},
]

WRITTEN = (
    'import { describe, it, expect } from "vitest";\n'
    'import { widthClass } from "./width-class.ts";\n'
    'it("C1 · Total cero", () => { expect(widthClass(1, 0)).toBe("w0"); });\n'
    'it("C2 · Total positivo", () => { expect(widthClass(1, 2)).toBe("w50"); });\n'
    'it("C3 · Mitad", () => { expect(widthClass(1, 2)).toBe("w50"); });\n'
)


def _coverage(missing: list[int], partial: list[int]) -> bytes:
    statements = {str(i): {"start": {"line": line}} for i, line in enumerate([3, 4, 5, 6])}
    counts = {
        key: (0 if value["start"]["line"] in missing else 1) for key, value in statements.items()
    }
    return json.dumps(
        {
            "/run/attempt/width-class.ts": {
                "statementMap": statements,
                "s": counts,
                "branchMap": {"0": {"line": 4}},
                "b": {"0": [0, 1] if 4 in partial else [1, 1]},
            }
        }
    ).encode()


def _result(
    *,
    missing: list[int] | None = None,
    partial: list[int] | None = None,
    survivors: int = 0,
    failed: str | None = None,
) -> SandboxResult:
    junit = (
        f'<testsuites><testsuite name="s"><testcase name="{failed}">'
        '<failure message="boom">x</failure></testcase></testsuite></testsuites>'
    ).encode()
    return SandboxResult(
        exit_code=0,
        stderr="",
        duration_ms=1234,
        coverage=_coverage(missing or [], partial or []),
        junit=junit if failed else b"<testsuites></testsuites>",
        mutation=json.dumps(
            {
                "tool": "stryker",
                "killed": 10,
                "total": 10 + survivors,
                "survived": [
                    {"id": str(i), "line": "4", "mutant": "ConditionalExpression: false"}
                    for i in range(survivors)
                ],
            }
        ).encode(),
    )


def _analysis(db: Session, tmp_path: Path, *, content: str = WRITTEN) -> Analysis:
    jail = tmp_path / "jail"
    (jail / "src").mkdir(parents=True)
    (jail / "src" / "width-class.ts").write_bytes((FIXTURES / "real_width_class.ts").read_bytes())
    analysis = seed_done_analysis(db, [], functions=FUNCTIONS)
    analysis.workspace_path = str(jail)
    analysis.stage = Stage.VERIFICATION
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
            brief=BRIEF,
            approved_at=utc_now(),
            approved_by_username="cperez",
            created_by_username="cperez",
        )
    ]
    analysis.test_files = [
        workflow_models.TestFile(
            path=str(WIDTH["path"]),
            function=str(WIDTH["function"]),
            line=int(str(WIDTH["line"])),
            filename="width_class.widthclass.6a467e.dioptra.test.ts",
            content=content,
            created_by_username="cperez",
        )
    ]
    db.commit()
    return analysis


def _run(
    db: Session, analysis: Analysis, actor: User, result: SandboxResult
) -> workflow_models.VerificationRun:
    from app.sandbox import executor

    original = executor.run

    def fake_run(settings: Settings, attempt: Attempt) -> SandboxResult:
        # Pin the arguments: passing the wrong settings or a wrong attempt
        # would silently verify something other than what was asked for.
        assert isinstance(settings, Settings)
        assert isinstance(attempt, Attempt)
        assert attempt.run_dir.is_dir()
        assert (attempt.run_dir / attempt.module_file).is_file()
        return result

    executor.run = fake_run
    try:
        runs = verify.run_verification(
            db, get_settings(), analysis=analysis, actor=actor, source_ip="10.0.0.9"
        )
    finally:
        executor.run = original
    db.commit()
    return runs[0]


def test_a_green_run_passes_and_opens_the_gate(
    db: Session, developer: User, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    run = _run(db, analysis, developer, _result())
    assert run.status is VerificationStatus.PASSED
    assert run.reasons == [] and run.uncovered_items == []
    assert run.coverage["statement_percent"] == 100.0
    assert run.duration_ms == 1234
    assert gates.leave_verification(analysis).open is True

    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "verification.run")
    ).one()
    assert entry.actor_username == "cperez" and entry.source_ip == "10.0.0.9"


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"survivors": 2}, "mutant_survived"),
        ({"missing": [5]}, "coverage_short"),
        ({"partial": [4]}, "coverage_short"),
        ({"failed": "C2 · Total positivo"}, "tests_failed"),
    ],
)
def test_each_re_audit_rule_closes_the_gate_on_its_own(
    db: Session, developer: User, tmp_path: Path, kwargs: dict[str, Any], reason: str
) -> None:
    analysis = _analysis(db, tmp_path)
    run = _run(db, analysis, developer, _result(**kwargs))
    assert run.status is VerificationStatus.FAILED
    assert reason in run.reasons
    assert gates.leave_verification(analysis).reason == "verification_failed"


def test_a_surviving_mutant_is_shown_to_the_developer_by_name(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """The plan's own criterion: a surviving mutant demonstrably rejects the gate."""
    analysis = _analysis(db, tmp_path)
    run = _run(db, analysis, developer, _result(survivors=1))
    assert run.reasons == ["mutant_survived"]
    assert run.surviving_mutants == [
        {"id": "0", "line": "4", "mutant": "ConditionalExpression: false"}
    ]
    assert gates.check(Stage.VERIFICATION, analysis).open is False


def test_a_case_that_asserts_nothing_is_rejected(
    db: Session, developer: User, tmp_path: Path
) -> None:
    toothless = WRITTEN.replace(
        'it("C3 · Mitad", () => { expect(widthClass(1, 2)).toBe("w50"); });',
        'it("C3 · Mitad", () => { widthClass(1, 2); });',
    )
    analysis = _analysis(db, tmp_path, content=toothless)
    run = _run(db, analysis, developer, _result())
    assert "assertion_free" in run.reasons and run.assertion_free_cases == ["C3"]


def test_a_brief_item_whose_line_never_ran_is_named(
    db: Session, developer: User, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    # Line 4 holds both R1 and R2; a partial branch there covers neither.
    run = _run(db, analysis, developer, _result(partial=[4]))
    assert run.uncovered_items == ["R1", "R2"]
    assert "brief_uncovered" in run.reasons


def test_the_gate_is_closed_while_a_function_has_never_been_verified(
    db: Session, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    assert gates.leave_verification(analysis).reason == "not_verified"


def test_the_loop_back_to_design_never_moves_the_stage_backwards(
    client: TestClient, db: Session, developer: User, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    _run(db, analysis, developer, _result(survivors=1))
    headers = login(client, developer.username)

    response = client.post(
        f"/api/v1/analyses/{analysis.id}/reopen-design",
        json={"justification": "El mutante sobrevivió; rediseñamos los casos."},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    db.expire_all()
    analysis = db.get(Analysis, analysis.id)  # type: ignore[assignment]
    # The stage machine stays monotonic: E7 is still E7.
    assert analysis.stage is Stage.VERIFICATION
    design = analysis.case_designs[0]
    assert design.approved_at is None and design.reopened_at is not None
    assert gates.check(Stage.VERIFICATION, analysis).open is False

    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "verification.reopen")
    ).one()
    assert "mutante" in str(entry.justification)


def test_verification_is_developer_only_and_only_at_e7(
    client: TestClient, db: Session, developer: User, analyst: User, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    for user in (analyst,):
        refused = client.post(
            f"/api/v1/analyses/{analysis.id}/verify", headers=login(client, user.username)
        )
        assert refused.status_code == 403, refused.text
    assert client.post(f"/api/v1/analyses/{analysis.id}/verify").status_code == 401

    analysis.stage = Stage.TESTS
    db.commit()
    early = client.post(
        f"/api/v1/analyses/{analysis.id}/verify", headers=login(client, developer.username)
    )
    assert early.status_code == 409 and early.json()["code"] == "stage_not_reached"


def test_only_the_functions_that_failed_are_reopened(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """One passed, one failed: the passing design keeps its approval untouched."""
    analysis = _analysis(db, tmp_path)
    other = {"path": "src/other.ts", "function": "otra", "line": 1}
    plan = analysis.test_plan
    assert plan is not None
    plan.functions = [*FUNCTIONS, {**other, "nloc": 2, "ccn": 1}]
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
    _run(db, analysis, developer, _result(survivors=1))
    # `otra` passed; only the function whose run failed may be reopened.
    db.expire(analysis)
    for run in analysis.verification_runs:
        if run.function == "otra":
            run.status = VerificationStatus.PASSED
    db.commit()
    db.expire(analysis)

    reopened = verify.reopen_design(
        db,
        analysis=analysis,
        actor=developer,
        justification="El mutante sobrevivió en widthClass.",
        source_ip="10.0.0.9",
    )
    db.commit()
    assert reopened == ["src/width-class.ts:widthClass"]
    by_function = {design.function: design for design in analysis.case_designs}
    assert by_function["widthClass"].reopened_at is not None
    assert by_function["widthClass"].approved_at is None
    # The one that passed is untouched: nothing to redesign there.
    assert by_function["otra"].reopened_at is None
    assert by_function["otra"].approved_at is not None

    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "verification.reopen")
    ).one()
    assert entry.actor_id == developer.id
    assert entry.actor_role == developer.role.value
    assert entry.source_ip == "10.0.0.9"
    assert entry.target == f"analysis:{analysis.id}:1"


def test_the_recorded_run_carries_what_the_screen_shows(
    db: Session, developer: User, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    result = _result(survivors=1, failed="C1 · Total cero")
    run = _run(db, analysis, developer, result)
    assert run.failed_cases == ["C1 · Total cero"]
    assert run.duration_ms == 1234
    assert run.created_by_username == "cperez"
    assert run.detail is None
    assert run.path == WIDTH["path"] and run.function == WIDTH["function"]

    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "verification.run")
    ).one()
    assert entry.target == f"analysis:{analysis.id}:1"
    assert entry.actor_id == developer.id and entry.actor_role == developer.role.value


def test_a_container_that_measured_nothing_is_never_scored_as_a_pass(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """The fail-OPEN this gate could have had, pinned shut.

    With no result document every question answers "yes" on the empty values:
    100 % of no lines, no failing test, no surviving mutant. That must be an
    error, not a verdict.
    """
    analysis = _analysis(db, tmp_path)
    nothing = SandboxResult(
        exit_code=0,
        stderr="",
        duration_ms=99,
        coverage=None,
        junit=None,
        mutation=None,
    )
    run = _run(db, analysis, developer, nothing)
    assert run.status is VerificationStatus.ERRORED
    assert run.reasons == ["sandbox_error"]
    assert run.detail is not None
    for name in ("coverage.json", "junit.xml", "mutation.json"):
        assert name in run.detail
    assert run.duration_ms == 99
    assert gates.leave_verification(analysis).reason == "verification_failed"


def test_a_runner_that_exits_non_zero_is_an_error_not_a_verdict(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """The wrappers swallow test failures on purpose; a non-zero exit is the
    entrypoint itself breaking, and a broken entrypoint measures nothing."""
    analysis = _analysis(db, tmp_path)
    broken = SandboxResult(
        exit_code=127,
        stderr="dioptra-run-js: not found\x00con un NUL dentro",
        duration_ms=12,
        coverage=_coverage([], []),
        junit=b"<testsuites></testsuites>",
        mutation=b'{"tool": "stryker", "survived": []}',
    )
    run = _run(db, analysis, developer, broken)
    assert run.status is VerificationStatus.ERRORED
    assert run.detail is not None and "exit 127" in run.detail
    # A NUL from the audited code's stderr would be a driver error on
    # PostgreSQL, which would roll the whole batch back.
    assert "\x00" not in run.detail


def test_a_function_with_no_stored_test_file_fails_rather_than_being_skipped(
    db: Session, developer: User, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    analysis.test_files = []
    db.commit()
    run = _run(db, analysis, developer, _result())
    assert run.status is VerificationStatus.FAILED and run.reasons == ["tests_failed"]
    assert gates.leave_verification(analysis).reason == "verification_failed"


def test_leave_verification_refuses_an_empty_plan_by_name(
    db: Session, developer: User, tmp_path: Path
) -> None:
    analysis = _analysis(db, tmp_path)
    plan = analysis.test_plan
    assert plan is not None
    plan.functions = []
    db.commit()
    assert gates.leave_verification(analysis).reason == "test_plan_missing"


def test_a_sandbox_that_cannot_run_is_a_recorded_run_not_a_crash(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """ "The sandbox is unavailable" is a result the developer must see.

    It is also the only path where the attempt directory is discarded by the
    `finally`, so the assertion below is what keeps that cleanup honest.
    """
    from app.sandbox import executor
    from app.sandbox.errors import SandboxUnavailable

    analysis = _analysis(db, tmp_path)
    seen: list[Path] = []

    def boom(settings: Settings, attempt: Attempt) -> SandboxResult:
        del settings
        seen.append(attempt.run_dir)
        raise SandboxUnavailable("docker binary not found on the worker")

    original = executor.run
    executor.run = boom
    try:
        runs = verify.run_verification(
            db, get_settings(), analysis=analysis, actor=developer, source_ip=None
        )
    finally:
        executor.run = original
    db.commit()

    run = runs[0]
    assert run.status is VerificationStatus.ERRORED
    assert run.reasons == ["sandbox_error"]
    assert run.detail is not None and "docker" in run.detail
    assert run.coverage["statement_percent"] == 100.0
    assert run.uncovered_items == [] and run.surviving_mutants == []
    assert run.duration_ms == 0
    # The gate treats "could not run" exactly like a failure.
    assert gates.leave_verification(analysis).reason == "verification_failed"
    # And the attempt directory is gone even though the run raised.
    assert seen and not seen[0].exists()


def test_a_test_file_that_stops_parsing_makes_every_case_assertion_free(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """The file parsed when it was saved; if it does not now, nothing is proven."""
    analysis = _analysis(db, tmp_path, content='it("C1 · x", () => { const ')
    run = _run(db, analysis, developer, _result())
    assert run.assertion_free_cases == ["C1", "C2", "C3"]
    assert "assertion_free" in run.reasons


def test_the_criterion_from_the_plan_is_the_one_applied(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """`statements` ⊂ `decisions`: a half-taken branch fails one and not the other."""
    analysis = _analysis(db, tmp_path)
    plan = analysis.test_plan
    assert plan is not None
    plan.criterion = workflow_models.CoverageCriterion.STATEMENTS
    db.commit()
    lenient = _run(db, analysis, developer, _result(partial=[4]))
    assert "coverage_short" not in lenient.reasons
    # The brief items are still checked by line, criterion or no criterion.
    assert lenient.uncovered_items == ["R1", "R2"]

    plan.criterion = workflow_models.CoverageCriterion.DECISIONS
    db.commit()
    strict = _run(db, analysis, developer, _result(partial=[4]))
    assert "coverage_short" in strict.reasons


def test_the_developer_can_start_a_verification_and_an_empty_plan_cannot(
    client: TestClient, db: Session, developer: User, tmp_path: Path
) -> None:
    """The happy path through the API, with the sandbox faked at its boundary."""
    from app.sandbox import executor

    analysis = _analysis(db, tmp_path)
    headers = login(client, developer.username)
    original = executor.run

    def fake_run(settings: Settings, attempt: Attempt) -> SandboxResult:
        del settings, attempt
        return _result()

    executor.run = fake_run
    try:
        started = client.post(f"/api/v1/analyses/{analysis.id}/verify", headers=headers)
    finally:
        executor.run = original
    assert started.status_code == 200, started.text

    db.expire_all()
    runs = client.get(f"/api/v1/analyses/{analysis.id}/verification", headers=headers).json()
    assert [run["status"] for run in runs] == ["passed"]
    assert runs[0]["coverage"]["statement_percent"] == 100.0

    # A plan with no function is refused before anything is enqueued.
    analysis = db.get(Analysis, analysis.id)  # type: ignore[assignment]
    plan = analysis.test_plan
    assert plan is not None
    plan.functions = []
    db.commit()
    empty = client.post(f"/api/v1/analyses/{analysis.id}/verify", headers=headers)
    assert empty.status_code == 422 and empty.json()["code"] == "test_plan_empty"


def test_the_written_reason_for_reopening_is_enforced_by_the_server(
    client: TestClient, db: Session, developer: User, tmp_path: Path
) -> None:
    """The screen disables its button below ten characters; the floor is here.

    Reopening discards an attestation, so it is a sensitive action and carries
    the same justification rule as a stage transition or a triage verdict.
    """
    analysis = _analysis(db, tmp_path)
    _run(db, analysis, developer, _result(survivors=1))
    headers = login(client, developer.username)
    url = f"/api/v1/analyses/{analysis.id}/reopen-design"

    for bad in ("", "   ", "corto", "  a b  "):
        refused = client.post(url, json={"justification": bad}, headers=headers)
        assert refused.status_code == 422, (bad, refused.text)
        assert refused.json()["code"] == "justification_required"
    db.expire_all()
    reopened = db.get(Analysis, analysis.id)
    assert reopened is not None and reopened.case_designs[0].reopened_at is None

    noisy = "  El   mutante   sobrevivió\u0000 en widthClass.  "
    ok = client.post(url, json={"justification": noisy}, headers=headers)
    assert ok.status_code == 200, ok.text
    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "verification.reopen")
    ).one()
    # Collapsed and control-stripped, like every other justified action.
    assert entry.justification == "El mutante sobrevivió en widthClass."


def test_verifying_a_reopened_function_records_a_reason_instead_of_losing_the_batch(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """A reopened design has no approval, so it has no scaffold either.

    Before the fix that raised OUTSIDE `verify_function`'s guard, which killed
    the job and rolled back every row already written for the batch.
    """
    analysis = _analysis(db, tmp_path)
    _run(db, analysis, developer, _result(survivors=1))
    verify.reopen_design(
        db,
        analysis=analysis,
        actor=developer,
        justification="El mutante sobrevivió; rediseñamos los casos.",
        source_ip=None,
    )
    db.commit()
    db.expire(analysis)

    run = _run(db, analysis, developer, _result())
    assert run.status is VerificationStatus.ERRORED
    assert run.reasons == ["sandbox_error"]
    assert run.detail is not None and "widthClass" in run.detail
    assert gates.leave_verification(analysis).reason == "verification_failed"


def test_a_nul_in_a_successful_run_stderr_never_reaches_the_row(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """The NUL strip was asserted only on the error arm.

    A run that SUCCEEDS can still carry a NUL in the audited code's stderr,
    and PostgreSQL refuses it in a `text` column — which would roll back the
    whole batch, not just this row.
    """
    analysis = _analysis(db, tmp_path)
    noisy = SandboxResult(
        exit_code=0,
        stderr="ruido del codigo auditado\u0000con un NUL",
        duration_ms=7,
        coverage=_coverage([], []),
        junit=b"<testsuites></testsuites>",
        mutation=b'{"tool": "stryker", "killed": 1, "total": 1, "survived": []}',
    )
    run = _run(db, analysis, developer, noisy)
    assert run.status is VerificationStatus.PASSED
    assert run.detail is not None and "\u0000" not in run.detail
    assert "ruido del codigo auditado" in run.detail


def test_reopening_the_design_is_only_possible_at_e7(
    client: TestClient, db: Session, developer: User, tmp_path: Path
) -> None:
    """Reopening clears an attestation; after E7 the report may already be signed."""
    analysis = _analysis(db, tmp_path)
    _run(db, analysis, developer, _result(survivors=1))
    headers = login(client, developer.username)
    url = f"/api/v1/analyses/{analysis.id}/reopen-design"
    body = {"justification": "El mutante sobrevivio; redisenamos los casos."}

    for stage, code in ((Stage.TESTS, "stage_not_reached"), (Stage.REPORT, "stage_locked")):
        fresh = db.get(Analysis, analysis.id)
        assert fresh is not None
        fresh.stage = stage
        db.commit()
        refused = client.post(url, json=body, headers=headers)
        assert refused.status_code == 409, (stage, refused.text)
        assert refused.json()["code"] == code
    db.expire_all()
    stale = db.get(Analysis, analysis.id)
    assert stale is not None and stale.case_designs[0].reopened_at is None


def test_a_reopened_function_can_be_redesigned_reapproved_and_rewritten_at_e7(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """The whole loop, in order: reopen → cases → approval → test file → a pass closes it.

    Found by the P5 walk of the platform on itself: `approve_cases` refused a
    reopened function with `stage_locked`, so the gate could never reopen.
    """
    from app.workflow import authoring, design  # noqa: PLC0415
    from app.workflow.design import FunctionRef  # noqa: PLC0415
    from app.workflow.errors import StageLocked  # noqa: PLC0415

    analysis = _analysis(db, tmp_path)
    ref = FunctionRef(path=str(WIDTH["path"]), function=str(WIDTH["function"]), line=3)
    _run(db, analysis, developer, _result(survivors=1))
    with pytest.raises(StageLocked):
        design.approve_cases(db, analysis=analysis, actor=developer, ref=ref, source_ip=None)

    verify.reopen_design(
        db,
        analysis=analysis,
        actor=developer,
        justification="Rediseñar el caso del mutante.",
        source_ip=None,
    )
    db.commit()
    # Approval re-checks the LIVE brief of the real fixture: one case per item.
    live = design.brief_for(analysis, ref)
    cases = [{"title": f"Caso para {item.id}", "covers": [item.id]} for item in live.items]
    while len(cases) < live.min_cases:
        cases.append({"title": f"Caso extra {len(cases) + 1}", "covers": []})
    design.save_cases(db, analysis=analysis, actor=developer, ref=ref, cases=cases, source_ip=None)
    approved = design.approve_cases(db, analysis=analysis, actor=developer, ref=ref, source_ip=None)
    assert approved.approved_at is not None
    assert approved.reopened_at is not None, "approval alone must not close the loop"
    authoring.save_tests(
        db, analysis=analysis, actor=developer, ref=ref, content=WRITTEN, source_ip=None
    )
    db.commit()
    assert gates.leave_verification(analysis).open is False

    passed = _run(db, analysis, developer, _result())
    assert passed.status is VerificationStatus.PASSED
    db.expire_all()
    analysis = db.get(Analysis, analysis.id)  # type: ignore[assignment]
    assert analysis.case_designs[0].reopened_at is None, "a pass closes the loop"
    assert gates.leave_verification(analysis).open is True
    with pytest.raises(StageLocked):
        design.save_cases(
            db, analysis=analysis, actor=developer, ref=ref, cases=cases, source_ip=None
        )


def test_an_equivalent_mutant_is_excused_with_a_reason_and_discounted_on_the_next_run(
    client: TestClient, db: Session, developer: User, analyst: User, tmp_path: Path
) -> None:
    """The developer judges a survivor equivalent; the NEXT run stops counting it."""
    from app.workflow.models import EquivalentMutant  # noqa: PLC0415

    analysis = _analysis(db, tmp_path)
    first = _run(db, analysis, developer, _result(survivors=2))
    assert first.status is VerificationStatus.FAILED
    url = f"/api/v1/analyses/{analysis.id}/mutants/equivalent"
    body = {
        **WIDTH,
        "mutant_id": "0",
        "justification": "Cambia el nombre del codec a mayúsculas: Python lo acepta igual.",
    }

    assert client.post(url, json=body, headers=login(client, analyst.username)).status_code == 403
    unknown = client.post(
        url, json={**body, "mutant_id": "99"}, headers=login(client, developer.username)
    )
    assert unknown.status_code == 404 and unknown.json()["code"] == "mutant_unknown"
    short = client.post(
        url, json={**body, "justification": "corto"}, headers=login(client, developer.username)
    )
    assert short.status_code == 422 and short.json()["code"] == "justification_required"

    marked = client.post(url, json=body, headers=login(client, developer.username))
    assert marked.status_code == 200, marked.text
    row = db.scalars(select(EquivalentMutant)).one()
    assert (row.mutant_id, row.created_by_username) == ("0", "cperez")
    assert row.mutant == "ConditionalExpression: false"
    entry = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "verification.mutant.equivalent")
    ).one()
    assert entry.justification is not None and "codec" in entry.justification
    # Marking twice is idempotent, and the latest run row is untouched (immutable history).
    assert client.post(url, json=body, headers=login(client, developer.username)).status_code == 200
    db.expire_all()
    analysis = db.get(Analysis, analysis.id)  # type: ignore[assignment]
    assert (
        len(verify.latest_runs(analysis)[(WIDTH["path"], WIDTH["function"], 3)].surviving_mutants)
        == 2
    )
    assert gates.leave_verification(analysis).open is False

    # The next run: one real survivor left → still failed, the excused one recorded apart.
    second = _run(db, analysis, developer, _result(survivors=2))
    assert second.status is VerificationStatus.FAILED
    assert [m["id"] for m in second.surviving_mutants] == ["1"]
    assert [m["id"] for m in second.equivalent_mutants] == ["0"]
    # Excuse the other one too: the third run passes and the gate opens.
    client.post(url, json={**body, "mutant_id": "1"}, headers=login(client, developer.username))
    third = _run(db, analysis, developer, _result(survivors=2))
    assert third.status is VerificationStatus.PASSED
    assert [m["id"] for m in third.equivalent_mutants] == ["0", "1"]
    db.expire_all()
    analysis = db.get(Analysis, analysis.id)  # type: ignore[assignment]
    assert gates.leave_verification(analysis).open is True
    listing = client.get(
        f"/api/v1/analyses/{analysis.id}/verification", headers=login(client, developer.username)
    )
    assert listing.json()[0]["equivalent_mutants"][0]["id"] == "0"


def test_an_excusal_binds_to_the_mutants_text_not_only_its_id(
    db: Session, developer: User, tmp_path: Path
) -> None:
    """Ids are index-based: a renumbered mutant under an excused id is a real survivor again."""
    from app.workflow.models import EquivalentMutant  # noqa: PLC0415

    analysis = _analysis(db, tmp_path)
    _run(db, analysis, developer, _result(survivors=1))
    from app.workflow.design import FunctionRef  # noqa: PLC0415

    ref = FunctionRef(path=str(WIDTH["path"]), function=str(WIDTH["function"]), line=3)
    verify.mark_equivalent(
        db,
        analysis=analysis,
        actor=developer,
        ref=ref,
        mutant_id="0",
        justification="Cambia solo el texto del registro.",
        source_ip=None,
    )
    db.commit()
    stored = db.scalars(select(EquivalentMutant)).one()
    assert stored.mutant == "ConditionalExpression: false"
    # Same id, same text → excused; same id, different text → NOT excused.
    same = _run(db, analysis, developer, _result(survivors=1))
    assert same.status is VerificationStatus.PASSED and [
        m["id"] for m in same.equivalent_mutants
    ] == ["0"]
    stored.mutant = "a different mutant now lives under id 0"
    db.commit()
    changed = _run(db, analysis, developer, _result(survivors=1))
    assert changed.status is VerificationStatus.FAILED
    assert [m["id"] for m in changed.surviving_mutants] == [
        "0"
    ] and changed.equivalent_mutants == []


def test_the_loop_guards_the_adversary_found_unpinned(
    client: TestClient, db: Session, developer: User, tmp_path: Path
) -> None:
    """Diagram text at E7 only once reopened; a failed run keeps the flag; the mark's stage."""
    from app.workflow import design  # noqa: PLC0415
    from app.workflow.design import FunctionRef  # noqa: PLC0415
    from app.workflow.errors import StageLocked, StageNotReached  # noqa: PLC0415
    from app.workflow.models import EquivalentMutant  # noqa: PLC0415

    analysis = _analysis(db, tmp_path)
    ref = FunctionRef(path=str(WIDTH["path"]), function=str(WIDTH["function"]), line=3)
    url = f"/api/v1/analyses/{analysis.id}/mutants/equivalent"
    body = {**WIDTH, "mutant_id": "0", "justification": "Nunca se ejecutó todavía."}
    # A function that was never verified has no survivor to excuse.
    never = client.post(url, json=body, headers=login(client, developer.username))
    assert never.status_code == 404 and never.json()["code"] == "mutant_unknown"

    _run(db, analysis, developer, _result(survivors=1))
    with pytest.raises(StageLocked):
        design.save_diagram_text(
            db, analysis=analysis, actor=developer, ref=ref, text="flowchart TD", source_ip=None
        )
    verify.reopen_design(
        db, analysis=analysis, actor=developer, justification="Rediseñar el caso.", source_ip=None
    )
    db.commit()
    row = design.save_diagram_text(
        db, analysis=analysis, actor=developer, ref=ref, text="flowchart TD", source_ip=None
    )
    assert row.reopened_at is not None
    # A run that FAILS after the reopen keeps the function reopened (an
    # unapproved function is ERRORED, so approve again first).
    live = design.brief_for(analysis, ref)
    cases = [{"title": f"Caso para {item.id}", "covers": [item.id]} for item in live.items]
    while len(cases) < live.min_cases:
        cases.append({"title": f"Caso extra {len(cases) + 1}", "covers": []})
    design.save_cases(db, analysis=analysis, actor=developer, ref=ref, cases=cases, source_ip=None)
    design.approve_cases(db, analysis=analysis, actor=developer, ref=ref, source_ip=None)
    db.commit()
    failed = _run(db, analysis, developer, _result(survivors=1))
    assert failed.status is VerificationStatus.FAILED
    db.expire_all()
    analysis = db.get(Analysis, analysis.id)  # type: ignore[assignment]
    assert analysis.case_designs[0].reopened_at is not None

    # An excusal of ANOTHER function never reaches this one.
    db.add(
        EquivalentMutant(
            analysis_id=analysis.id,
            path=str(WIDTH["path"]),
            function="anotherFunction",
            line=3,
            mutant_id="0",
            mutant="ConditionalExpression: false",
            justification="Es de otra función.",
            created_by_username="cperez",
        )
    )
    db.commit()
    run = _run(db, analysis, developer, _result(survivors=1))
    assert run.status is VerificationStatus.FAILED
    assert [m["id"] for m in run.surviving_mutants] == ["0"] and run.equivalent_mutants == []

    # The mark is an E7 action: refused after E8 and before E7.
    analysis.stage = Stage.REPORT
    db.commit()
    with pytest.raises(StageLocked):
        verify.mark_equivalent(
            db,
            analysis=analysis,
            actor=developer,
            ref=ref,
            mutant_id="0",
            justification="Cambia solo el texto del registro.",
            source_ip=None,
        )
    analysis.stage = Stage.TESTS
    db.commit()
    with pytest.raises(StageNotReached):
        verify.mark_equivalent(
            db,
            analysis=analysis,
            actor=developer,
            ref=ref,
            mutant_id="0",
            justification="Cambia solo el texto del registro.",
            source_ip=None,
        )
