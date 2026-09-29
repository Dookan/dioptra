"""Cancelling an analysis, gracefully (phase 12, `tasks/phase12-survey.md`).

`mmarin`'s definition of graceful is the acceptance here: it is not an error
(its own status, CANCELLED, and no coverage row for the tool it killed); it
stops in seconds; it never collides with the finish. Plus the decisions of §7:
the creator (still analyst) or an admin, no written reason, the partial rows
deleted, a dead worker's cancel closed by the sweep after the grace.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from app.analysis import pipeline
from app.analysis.models import (
    Analysis,
    AnalysisStatus,
    RawToolOutput,
    SourceKind,
    ToolCategory,
    ToolRun,
    ToolStatus,
)
from app.analysis.runners.base import ExecutionResult, RunnerSpec
from app.analysis.runners.executor import LocalExecutor
from app.analysis.sweep import sweep_analyses
from app.audit.models import AuditLogEntry
from app.auth.models import SYSTEM_ACTOR, Role, User
from app.auth.service import create_user
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.process import Ending, run_stoppable
from app.ingest.upload import UPLOAD_NAME
from app.projects.models import Project
from tests.conftest import SEED_PASSWORD
from tests.test_pipeline import FixtureExecutor, _ingest, login


def _actions(db: Session, prefix: str = "analysis.cancel") -> list[tuple[str, str, str | None]]:
    rows = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action.like(f"{prefix}%"))).all()
    # Sorted: two rows of one transaction share a timestamp and ids are uuids.
    return sorted((row.action, row.actor_username, row.justification) for row in rows)


def _row(
    db: Session,
    status: AnalysisStatus,
    *,
    creator: User | None,
    requested_ago: timedelta | None = None,
) -> Analysis:
    project = Project(name=f"p-{uuid.uuid4().hex[:8]}")
    db.add(project)
    db.commit()
    now = utc_now()
    analysis = Analysis(
        project_id=project.id,
        source_kind=SourceKind.ZIP,
        source_ref="x.zip",
        status=status,
        created_by_id=creator.id if creator else None,
        started_at=now if status is AnalysisStatus.RUNNING else None,
        current_step="semgrep" if status is AnalysisStatus.RUNNING else None,
        cancel_requested_at=(now - requested_ago) if requested_ago is not None else None,
    )
    db.add(analysis)
    db.commit()
    return analysis


def _tree(analysis: Analysis) -> Path:
    directory = get_settings().workspace_root / str(analysis.project_id) / str(analysis.id)
    (directory / "src").mkdir(parents=True)
    (directory / "src" / "a.js").write_text("x\n", encoding="utf-8")
    (directory / UPLOAD_NAME).write_bytes(b"PK")
    return directory


def _cancel(
    client: TestClient, user: User, analysis_id: uuid.UUID
) -> tuple[int, dict[str, object]]:
    response = client.post(
        f"/api/v1/analyses/{analysis_id}/cancel", headers=login(client, user.username)
    )
    return response.status_code, response.json()


@pytest.fixture
def plain_run(monkeypatch: pytest.MonkeyPatch) -> FixtureExecutor:
    executor = FixtureExecutor()
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: executor)
    return executor


def _other_analyst(db: Session) -> User:
    user = create_user(
        db,
        username="jrios",
        display_name="Juan Rios",
        role=Role.ANALYST,
        password=SEED_PASSWORD,
        must_change_password=False,
    )
    db.commit()
    return user


# --- stops in seconds -----------------------------------------------------------


def test_a_stoppable_process_is_killed_within_seconds_with_its_children(tmp_path: Path) -> None:
    """A tool that would run a minute stops at the next slice — group and all."""
    child = tmp_path / "child.pid"
    script = f"sleep 60 & echo $! > {child}; wait"
    asked: list[float] = []

    def should_stop() -> bool:
        asked.append(time.monotonic())
        return child.exists()

    started = time.monotonic()
    done = run_stoppable(
        ["sh", "-c", script], timeout_seconds=60, should_stop=should_stop, poll_seconds=0.1
    )
    assert time.monotonic() - started < 5
    assert done.ending is Ending.STOPPED
    assert (done.returncode, done.kill_confirmed) == (None, True)
    pid = int(child.read_text().strip())
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):  # the grandchild died with the group
        os.kill(pid, 0)
    assert asked


def test_a_stoppable_process_that_exits_keeps_its_result() -> None:
    done = run_stoppable(
        [sys.executable, "-c", "import sys; sys.stderr.write('e'); print('o'); sys.exit(3)"],
        timeout_seconds=30,
        should_stop=lambda: False,
        poll_seconds=0.1,
    )
    assert (done.ending, done.returncode, done.stdout.strip(), done.stderr) == (
        Ending.EXITED,
        3,
        b"o",
        b"e",
    )


def test_the_timeout_still_times_out_and_is_not_a_stop() -> None:
    done = run_stoppable(
        ["sleep", "30"], timeout_seconds=0.3, should_stop=lambda: False, poll_seconds=0.1
    )
    assert done.ending is Ending.TIMED_OUT


def test_an_unconfirmed_kill_is_reported(tmp_path: Path) -> None:
    done = run_stoppable(
        ["sleep", "30"],
        timeout_seconds=30,
        should_stop=lambda: True,
        on_kill=lambda: False,
        poll_seconds=0.1,
    )
    assert (done.ending, done.kill_confirmed) == (Ending.STOPPED, False)


def test_a_local_run_asked_to_stop_is_cancelled_not_failed(tmp_path: Path) -> None:
    settings = get_settings()
    spec = RunnerSpec(
        tool="slow",
        category=ToolCategory.SAST,
        argv=("sleep", "30"),
        output_file="report.sarif",
        timeout_seconds=60,
    )
    started = time.monotonic()
    result = LocalExecutor(settings, should_stop=lambda: True).run(
        spec, workspace=tmp_path, out_dir=tmp_path
    )
    assert time.monotonic() - started < 10
    assert result.cancelled is True
    assert result.output is None
    assert result.document is None


def test_the_docker_kill_hook_runs_on_a_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The container is killed by name: killing the docker CLIENT would not stop it."""
    from app.analysis.runners import executor as module  # noqa: PLC0415

    killed: list[list[str]] = []

    class _Killed:
        returncode = 0
        stderr = b""

    def fake_kill(argv: list[str], **_kw: object) -> _Killed:
        killed.append(argv)
        return _Killed()

    monkeypatch.setattr(
        "app.analysis.runners.executor.shutil.which", lambda name: "/bin/sleep" if name else None
    )
    monkeypatch.setattr("app.analysis.runners.executor.subprocess.run", fake_kill)
    docker = module.DockerExecutor(get_settings(), should_stop=lambda: True)
    monkeypatch.setattr(docker, "command", lambda *_a, **_k: ["sleep", "30"])
    spec = RunnerSpec(
        tool="slow",
        category=ToolCategory.SAST,
        argv=("x",),
        output_file="report.sarif",
        timeout_seconds=60,
    )
    result = docker.run(spec, workspace=tmp_path, out_dir=tmp_path)
    assert result.cancelled is True
    assert result.kill_confirmed is True
    assert killed
    assert killed[0][1] == "kill"
    assert killed[0][2].startswith("dioptra-slow-")


# --- the worker closes its own work --------------------------------------------


class CancelMidRun(FixtureExecutor):
    """The person clicks "Cancelar" while the first tool runs."""

    def __init__(self, *, killed: bool = False) -> None:
        super().__init__()
        self.killed = killed

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        result = super().run(spec, workspace=workspace, out_dir=out_dir)
        if len(self.specs) == 1:
            with pipeline.get_session_factory()() as other:  # type: ignore[attr-defined]
                other.execute(update(Analysis).values(cancel_requested_at=utc_now()))
                other.commit()
            if self.killed:
                return ExecutionResult(
                    ToolStatus.FAILED, None, "", None, False, 1, "cancelled", cancelled=True
                )
        return result


@pytest.mark.parametrize("killed", [False, True])
def test_a_cancel_mid_run_ends_cancelled_and_leaves_nothing(
    client: TestClient,
    analyst: User,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
    killed: bool,
) -> None:
    executor = CancelMidRun(killed=killed)
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: executor)
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))

    db.expire_all()
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert analysis.status is AnalysisStatus.CANCELLED
    assert (analysis.failure_code, analysis.current_step) == (None, None)
    assert analysis.finished_at is not None
    # Not a failure, and nothing kept: no coverage row — not even for the tool
    # the cancel killed — no raw output, no finding, no SBOM, no metrics.
    assert analysis.tool_runs == []
    assert analysis.raw_outputs == []
    assert analysis.findings == []
    assert (analysis.sbom, analysis.metrics) == (None, None)
    assert len(executor.specs) == 1
    assert analysis.workspace_path is not None
    assert not Path(analysis.workspace_path).parent.exists()
    assert _actions(db, "analysis.cancel") == [("analysis.cancel", SYSTEM_ACTOR, None)]
    raw = db.execute(text("SELECT status FROM analyses")).scalar_one()
    assert raw == "CANCELLED"  # the member NAME, in the widened column


def test_an_unconfirmed_kill_leaves_the_files_to_the_sweep(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    class StillMounted(CancelMidRun):
        def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
            super().run(spec, workspace=workspace, out_dir=out_dir)
            return ExecutionResult(
                ToolStatus.FAILED,
                None,
                "",
                None,
                False,
                1,
                "cancelled",
                cancelled=True,
                kill_confirmed=False,
            )

    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: StillMounted())
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))
    db.expire_all()
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert analysis.status is AnalysisStatus.CANCELLED
    assert analysis.workspace_path is not None
    directory = Path(analysis.workspace_path).parent
    assert directory.exists()

    settings = get_settings()
    # Too young: a container of the run could still hold the mount.
    assert sweep_analyses(db, settings).cancelled_trees_removed == 0
    assert directory.exists()
    later = utc_now() + timedelta(minutes=settings.analysis_stale_minutes + 1)
    assert sweep_analyses(db, settings, now=later).cancelled_trees_removed == 1
    assert not directory.exists()


# --- never collides with the finish ---------------------------------------------


def test_a_cancel_between_the_results_and_done_keeps_nothing(
    client: TestClient,
    analyst: User,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
    plain_run: FixtureExecutor,
) -> None:
    """The request lands while the worker writes its findings: the cancel wins whole."""
    original = pipeline._close

    def late_request(session: Session, *args: object, **kwargs: object) -> bool:
        with pipeline.get_session_factory()() as other:  # type: ignore[attr-defined]
            other.execute(update(Analysis).values(cancel_requested_at=utc_now()))
            other.commit()
        return original(session, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pipeline, "_close", late_request)
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))

    db.expire_all()
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert analysis.status is AnalysisStatus.CANCELLED
    assert (analysis.findings, analysis.sbom, analysis.metrics) == ([], None, None)
    assert analysis.tool_runs == []


def test_a_cancel_after_done_is_refused_and_the_results_stay(
    client: TestClient, analyst: User, db: Session, plain_run: FixtureExecutor
) -> None:
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))
    code, body = _cancel(client, analyst, analysis_id)
    assert (code, body["code"]) == (409, "analysis_not_cancellable")
    db.expire_all()
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE
    assert analysis.findings
    assert _actions(db) == []


def test_the_worker_and_the_sweep_closing_one_row_write_one_audit_row(db: Session) -> None:
    row = _row(db, AnalysisStatus.RUNNING, creator=None, requested_ago=timedelta(minutes=6))
    settings = get_settings()
    assert sweep_analyses(db, settings).cancelled == 1
    # The worker wakes up late and runs its own cancel path on the closed row.
    pipeline._cancel(db, settings, row.id, row.project_id, kill_confirmed=True)
    assert _actions(db) == [("analysis.cancel", SYSTEM_ACTOR, None)]


# --- QUEUED: closed by the request itself ---------------------------------------


def test_a_queued_analysis_is_cancelled_at_once_and_its_job_does_nothing(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _row(db, AnalysisStatus.QUEUED, creator=analyst)
    directory = _tree(row)

    code, body = _cancel(client, analyst, row.id)

    assert code == 202
    assert (body["status"], body["cancel_requested"]) == ("cancelled", False)
    assert not directory.exists()
    assert _actions(db) == [
        ("analysis.cancel", analyst.username, None),
        ("analysis.cancel.request", analyst.username, None),
    ]
    # The queue message arrives later and finds nothing to claim.
    executor = FixtureExecutor()
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: executor)
    pipeline.run_pipeline(row.id)
    assert executor.specs == []
    db.expire_all()
    again = db.get(Analysis, row.id)
    assert again is not None
    assert again.status is AnalysisStatus.CANCELLED


# --- RUNNING: a request the worker answers --------------------------------------


def test_a_running_analysis_gets_a_request_once(
    client: TestClient, analyst: User, db: Session
) -> None:
    row = _row(db, AnalysisStatus.RUNNING, creator=analyst)
    directory = _tree(row)

    first = _cancel(client, analyst, row.id)
    second = _cancel(client, analyst, row.id)

    assert first[0] == second[0] == 202
    assert (first[1]["status"], first[1]["cancel_requested"]) == ("running", True)
    assert second[1]["cancel_requested"] is True
    # The API never touches files a worker may be using.
    assert directory.exists()
    assert _actions(db) == [("analysis.cancel.request", analyst.username, None)]


def test_a_dead_workers_cancel_is_closed_by_the_next_click_after_the_grace(
    client: TestClient, analyst: User, db: Session
) -> None:
    row = _row(db, AnalysisStatus.RUNNING, creator=analyst, requested_ago=timedelta(minutes=6))
    directory = _tree(row)
    db.add(
        ToolRun(
            analysis_id=row.id, tool="semgrep", category=ToolCategory.SAST, status=ToolStatus.RAN
        )
    )
    db.add(
        RawToolOutput(
            analysis_id=row.id,
            tool="semgrep",
            exit_code=0,
            stderr=None,
            output=b"{}",
            truncated=False,
        )
    )
    db.commit()

    code, body = _cancel(client, analyst, row.id)

    assert code == 409  # the sweep inside the request closed it: nothing left to cancel
    db.expire_all()
    closed = db.get(Analysis, row.id)
    assert closed is not None
    assert closed.status is AnalysisStatus.CANCELLED
    assert (closed.tool_runs, closed.raw_outputs) == ([], [])
    assert not directory.exists()
    assert _actions(db) == [("analysis.cancel", SYSTEM_ACTOR, None)]


def test_a_young_request_is_not_closed_by_the_sweep(db: Session) -> None:
    row = _row(db, AnalysisStatus.RUNNING, creator=None, requested_ago=timedelta(minutes=4))
    assert sweep_analyses(db, get_settings()).cancelled == 0
    db.refresh(row)
    assert row.status is AnalysisStatus.RUNNING


def test_the_grace_has_a_floor() -> None:
    with pytest.raises(ValueError, match="analysis_cancel_grace_minutes"):
        Settings(analysis_cancel_grace_minutes=0)  # type: ignore[call-arg]


# --- who may cancel --------------------------------------------------------------


def test_an_admin_may_cancel_any_analysis(
    client: TestClient, analyst: User, admin: User, db: Session
) -> None:
    row = _row(db, AnalysisStatus.QUEUED, creator=analyst)
    assert _cancel(client, admin, row.id)[0] == 202
    assert ("analysis.cancel.request", admin.username, None) in _actions(db)


def test_another_analyst_may_not_cancel(client: TestClient, analyst: User, db: Session) -> None:
    row = _row(db, AnalysisStatus.QUEUED, creator=analyst)
    other = _other_analyst(db)
    code, body = _cancel(client, other, row.id)
    assert (code, body["code"]) == (403, "forbidden")
    denied = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")).all()
    assert [(d.actor_username, d.target) for d in denied] == [
        (other.username, f"analysis {row.id} cancel")
    ]
    db.refresh(row)
    assert row.status is AnalysisStatus.QUEUED
    assert _actions(db) == []


def test_an_orphan_analysis_is_the_admins_only(
    client: TestClient, analyst: User, db: Session
) -> None:
    row = _row(db, AnalysisStatus.QUEUED, creator=None)
    assert _cancel(client, analyst, row.id)[0] == 403


def test_a_developer_may_not_cancel_even_their_own(
    client: TestClient, developer: User, db: Session
) -> None:
    """A creator since demoted to developer keeps no E2 right (survey §9.2)."""
    row = _row(db, AnalysisStatus.QUEUED, creator=developer)
    assert _cancel(client, developer, row.id)[0] == 403
    denied = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")).all()
    assert len(denied) == 1
    db.refresh(row)
    assert row.status is AnalysisStatus.QUEUED


def test_an_unknown_analysis_is_404(client: TestClient, analyst: User) -> None:
    assert _cancel(client, analyst, uuid.uuid4())[0] == 404


def test_the_request_takes_no_reason(client: TestClient, analyst: User, db: Session) -> None:
    row = _row(db, AnalysisStatus.QUEUED, creator=analyst)
    response = client.post(
        f"/api/v1/analyses/{row.id}/cancel",
        headers=login(client, analyst.username),
        json={"justification": "ignored entirely"},
    )
    assert response.status_code == 202
    assert all(justification is None for *_rest, justification in _actions(db))


# --- a cancelled analysis goes nowhere -------------------------------------------


def test_a_cancelled_analysis_cannot_be_exported_advanced_or_cancelled_again(
    client: TestClient, analyst: User, db: Session
) -> None:
    row = _row(db, AnalysisStatus.CANCELLED, creator=analyst)
    headers = login(client, analyst.username)
    for fmt in ("html", "md", "docx"):
        response = client.get(
            f"/api/v1/analyses/{row.id}/report", params={"format": fmt}, headers=headers
        )
        assert response.status_code == 409, fmt
    job = client.post(f"/api/v1/analyses/{row.id}/report/jobs", headers=headers, json={})
    assert job.status_code == 409
    advance = client.post(
        f"/api/v1/analyses/{row.id}/stage/advance",
        headers=headers,
        json={"justification": "intentando avanzar un análisis cancelado"},
    )
    assert advance.status_code in (409, 422)
    assert _cancel(client, analyst, row.id)[0] == 409
    assert client.get(f"/api/v1/analyses/{row.id}", headers=headers).json()["status"] == "cancelled"


# --- the acquisition stops too ----------------------------------------------------


def test_an_extraction_asked_to_stop_raises_and_removes_the_jail(tmp_path: Path) -> None:
    import io  # noqa: PLC0415
    import zipfile  # noqa: PLC0415

    from app.core.process import Stopped  # noqa: PLC0415
    from app.ingest.archive import ExtractionLimits, extract_zip  # noqa: PLC0415

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index in range(3):
            archive.writestr(f"f{index}.txt", "x")
    buffer.seek(0)
    jail = tmp_path / "jail"
    limits = ExtractionLimits(max_entries=10, max_unpacked_bytes=1 << 20, max_ratio=100)
    with pytest.raises(Stopped):
        extract_zip(buffer, jail, limits, should_stop=lambda: True)
    assert not jail.exists()
    buffer.seek(0)
    extract_zip(buffer, jail, limits, should_stop=lambda: False)
    assert sorted(p.name for p in jail.iterdir()) == ["f0.txt", "f1.txt", "f2.txt"]


def test_a_clone_asked_to_stop_is_killed_and_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.core.process import Stopped  # noqa: PLC0415
    from app.ingest.git_source import shallow_clone  # noqa: PLC0415

    fake_git = tmp_path / "git"
    fake_git.write_text('#!/bin/sh\nfor last; do :; done\nmkdir -p "$last"\nexec sleep 60\n')
    fake_git.chmod(0o755)
    monkeypatch.setattr("app.ingest.git_source.shutil.which", lambda _name: str(fake_git))
    monkeypatch.setattr(
        "app.ingest.git_source.socket.getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("140.82.112.3", 443))],
    )
    destination = tmp_path / "a" / "clone"
    started = time.monotonic()
    with pytest.raises(Stopped):
        shallow_clone(
            "https://github.com/org/repo.git",
            destination,
            timeout_seconds=60,
            should_stop=lambda: destination.exists(),
        )
    assert time.monotonic() - started < 10
    assert not destination.exists()


# --- the precommit panel's cases --------------------------------------------------


def test_a_failing_stop_check_keeps_waiting_and_the_deadline_holds() -> None:
    """The database restarting during a long tool must not leave it unwatched."""

    def broken() -> bool:
        message = "database is restarting"
        raise RuntimeError(message)

    done = run_stoppable(["sleep", "30"], timeout_seconds=0.5, should_stop=broken, poll_seconds=0.1)
    assert done.ending is Ending.TIMED_OUT


def test_an_interrupted_wait_kills_the_group_and_the_container(tmp_path: Path) -> None:
    """RQ's job timeout lands INSIDE the loop: nothing may outlive it."""
    child = tmp_path / "child.pid"
    killed: list[bool] = []

    class JobTimeout(BaseException):
        pass

    def record_kill() -> bool:
        killed.append(True)
        return True

    def interrupt() -> bool:
        if child.exists():
            raise JobTimeout
        return False

    with pytest.raises(JobTimeout):
        run_stoppable(
            ["sh", "-c", f"sleep 60 & echo $! > {child}; wait"],
            timeout_seconds=60,
            should_stop=interrupt,
            on_kill=record_kill,
            poll_seconds=0.1,
        )
    assert killed == [True]
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(int(child.read_text().strip()), 0)


def test_the_stale_pass_leaves_a_pending_cancel_to_the_cancel_pass(db: Session) -> None:
    """A run past the stale window but cancelled a minute ago ends CANCELLED, not FAILED."""
    row = _row(db, AnalysisStatus.RUNNING, creator=None, requested_ago=timedelta(minutes=1))
    db.execute(
        update(Analysis)
        .where(Analysis.id == row.id)
        .values(started_at=utc_now() - timedelta(hours=3))
    )
    db.commit()
    stats = sweep_analyses(db, get_settings())
    db.refresh(row)
    assert (stats.abandoned, row.status) == (0, AnalysisStatus.RUNNING)
    later = utc_now() + timedelta(minutes=10)
    sweep_analyses(db, get_settings(), now=later)
    db.refresh(row)
    assert (row.status, row.failure_code) == (AnalysisStatus.CANCELLED, None)


def test_a_late_cancel_never_wipes_a_row_another_path_failed(db: Session) -> None:
    row = _row(db, AnalysisStatus.FAILED, creator=None)
    db.add(
        ToolRun(
            analysis_id=row.id, tool="semgrep", category=ToolCategory.SAST, status=ToolStatus.RAN
        )
    )
    db.commit()
    pipeline._cancel(db, get_settings(), row.id, row.project_id, kill_confirmed=True)
    db.refresh(row)
    assert row.status is AnalysisStatus.FAILED
    assert len(row.tool_runs) == 1
    assert _actions(db) == []


# --- the pipeline hands its stop check to every stoppable step (QA panel) --------


def test_the_executor_gets_the_pipelines_stop_check_and_it_reads_the_row(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deleted predicate or a dropped kwarg would make a cancel wait for the tool."""
    seen: dict[str, list[bool]] = {"before": [], "after": []}

    class Probing(FixtureExecutor):
        def __init__(self, should_stop: object) -> None:
            super().__init__()
            assert callable(should_stop)
            self.should_stop = should_stop

        def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
            if not self.specs:
                seen["before"].append(self.should_stop())
                with pipeline.get_session_factory()() as other:  # type: ignore[attr-defined]
                    other.execute(update(Analysis).values(cancel_requested_at=utc_now()))
                    other.commit()
                seen["after"].append(self.should_stop())
            return super().run(spec, workspace=workspace, out_dir=out_dir)

    monkeypatch.setattr(
        "app.analysis.pipeline.build_executor",
        lambda _s, *, should_stop=None: Probing(should_stop),
    )
    _ingest(client, login(client, analyst.username))
    assert seen == {"before": [False], "after": [True]}


def test_the_extraction_gets_the_pipelines_stop_check(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.ingest import upload  # noqa: PLC0415

    checks: list[bool] = []
    original = upload.extract_upload

    def probing(workspace: Path, settings: Settings, *, should_stop: object = None) -> None:
        assert callable(should_stop)
        checks.append(should_stop())
        original(workspace, settings, should_stop=should_stop)

    monkeypatch.setattr("app.analysis.pipeline.extract_upload", probing)
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: FixtureExecutor())
    _ingest(client, login(client, analyst.username))
    assert checks == [False]


def test_the_clone_gets_the_pipelines_stop_check(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    checks: list[bool] = []

    def probing(
        url: str, destination: Path, *, timeout_seconds: int, should_stop: object = None
    ) -> None:
        assert callable(should_stop)
        checks.append(should_stop())
        destination.mkdir(parents=True)
        (destination / "a.js").write_text("x\n", encoding="utf-8")

    monkeypatch.setattr("app.analysis.pipeline.shallow_clone", probing)
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: FixtureExecutor())
    monkeypatch.setattr(
        "app.ingest.git_source.socket.getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("140.82.112.3", 443))],
    )
    headers = login(client, analyst.username)
    project = client.post(
        "/api/v1/projects",
        json={"name": "git-project", "system": {"name": "sistema-git"}},
        headers=headers,
    ).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/ingest/git",
        json={"url": "https://github.com/org/repo.git"},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    assert checks == [False]


# --- the mutation pass's gaps ------------------------------------------------------


def test_a_cancel_touches_only_its_own_row(
    client: TestClient, analyst: User, db: Session, session_factory: object
) -> None:
    """Dropping ``Analysis.id ==`` from any update would cancel every analysis."""
    queued, bystander = (_row(db, AnalysisStatus.QUEUED, creator=analyst) for _ in range(2))
    kept = _tree(bystander)
    running, other_running = (_row(db, AnalysisStatus.RUNNING, creator=analyst) for _ in range(2))

    assert _cancel(client, analyst, queued.id)[0] == 202
    assert _cancel(client, analyst, running.id)[0] == 202
    db.expire_all()
    assert db.get(Analysis, bystander.id).status is AnalysisStatus.QUEUED  # type: ignore[union-attr]
    assert kept.exists()
    assert db.get(Analysis, other_running.id).cancel_requested_at is None  # type: ignore[union-attr]
    assert pipeline._cancel_pending(db, running.id) is True
    assert pipeline._cancel_pending(db, other_running.id) is False

    pipeline._cancel(db, get_settings(), running.id, running.project_id, kill_confirmed=True)
    db.expire_all()
    assert db.get(Analysis, running.id).status is AnalysisStatus.CANCELLED  # type: ignore[union-attr]
    assert db.get(Analysis, other_running.id).status is AnalysisStatus.RUNNING  # type: ignore[union-attr]
    # A cancelled row with its request set is no longer "pending": it left RUNNING.
    assert pipeline._cancel_pending(db, running.id) is False


def test_the_queued_path_stamps_the_row_and_every_row_names_its_actor(
    client: TestClient, analyst: User, db: Session
) -> None:
    row = _row(db, AnalysisStatus.QUEUED, creator=analyst)
    _cancel(client, analyst, row.id)
    db.refresh(row)
    assert row.finished_at is not None
    assert row.cancel_requested_at is not None
    rows = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action.like("analysis.cancel%"))
    ).all()
    assert len(rows) == 2
    for entry in rows:
        assert (entry.actor_id, entry.actor_role, entry.target, entry.source_ip) == (
            analyst.id,
            "analyst",
            str(row.id),
            "testclient",
        )


def test_the_running_request_row_names_its_actor(
    client: TestClient, analyst: User, db: Session
) -> None:
    row = _row(db, AnalysisStatus.RUNNING, creator=analyst)
    _cancel(client, analyst, row.id)
    (entry,) = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "analysis.cancel.request")
    ).all()
    assert (entry.actor_id, entry.actor_role, entry.target, entry.source_ip) == (
        analyst.id,
        "analyst",
        str(row.id),
        "testclient",
    )


def test_a_refusal_row_is_a_denial_with_its_actor(
    client: TestClient, analyst: User, db: Session
) -> None:
    from app.audit.models import AuditOutcome  # noqa: PLC0415

    row = _row(db, AnalysisStatus.QUEUED, creator=analyst)
    other = _other_analyst(db)
    _cancel(client, other, row.id)
    (entry,) = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")).all()
    assert (entry.outcome, entry.actor_id, entry.actor_role, entry.source_ip) == (
        AuditOutcome.DENIED,
        other.id,
        "analyst",
        "testclient",
    )


def test_the_workers_cancel_row_names_the_analysis(db: Session) -> None:
    row = _row(db, AnalysisStatus.RUNNING, creator=None)
    pipeline._cancel(db, get_settings(), row.id, row.project_id, kill_confirmed=True)
    (entry,) = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "analysis.cancel")
    ).all()
    assert (entry.actor_username, entry.target) == (SYSTEM_ACTOR, str(row.id))


def test_a_late_cancel_clears_what_the_worker_wrote_after_the_sweep(db: Session) -> None:
    """The sweep closed the row CANCELLED; the worker then committed a stray row."""
    row = _row(db, AnalysisStatus.RUNNING, creator=None, requested_ago=timedelta(minutes=6))
    sweep_analyses(db, get_settings())
    db.add(
        ToolRun(
            analysis_id=row.id, tool="semgrep", category=ToolCategory.SAST, status=ToolStatus.RAN
        )
    )
    db.commit()
    pipeline._cancel(db, get_settings(), row.id, row.project_id, kill_confirmed=True)
    db.refresh(row)
    assert row.tool_runs == []
    assert _actions(db) == [("analysis.cancel", SYSTEM_ACTOR, None)]  # still one row


@pytest.mark.parametrize(
    ("status", "requested", "stop"),
    [
        (AnalysisStatus.RUNNING, None, False),
        (AnalysisStatus.RUNNING, timedelta(0), True),
        (AnalysisStatus.FAILED, None, True),  # the sweep abandoned it
    ],
)
def test_the_stop_check_reads_the_row(
    db: Session,
    session_factory: object,
    monkeypatch: pytest.MonkeyPatch,
    status: AnalysisStatus,
    requested: timedelta | None,
    stop: bool,
) -> None:
    monkeypatch.setattr("app.analysis.pipeline.get_session_factory", lambda: session_factory)
    row = _row(db, status, creator=None, requested_ago=requested)
    assert pipeline._stop_check(row.id)() is stop


def test_the_stop_check_of_a_vanished_row_stops(
    session_factory: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.analysis.pipeline.get_session_factory", lambda: session_factory)
    assert pipeline._stop_check(uuid.uuid4())() is True


# --- the stoppable path of run_argv keeps run_argv's contract -------------------


def _argv(*args: str) -> list[str]:
    return [sys.executable, "-c", *args]


def test_a_stoppable_run_keeps_the_exit_code_stderr_duration_and_cwd(tmp_path: Path) -> None:
    from app.analysis.runners.executor import run_argv  # noqa: PLC0415

    outcome = run_argv(
        _argv("import os, sys, time; time.sleep(0.3); sys.stderr.write(os.getcwd()); sys.exit(3)"),
        cwd=tmp_path,
        timeout_seconds=30,
        should_stop=lambda: False,
    )
    assert (outcome.status, outcome.exit_code, outcome.detail, outcome.stopped) == (
        None,
        3,
        None,
        False,
    )
    assert outcome.stderr == str(tmp_path)
    assert 250 <= outcome.duration_ms < 10_000


def test_a_stoppable_run_that_times_out_is_a_timeout(tmp_path: Path) -> None:
    from app.analysis.runners.executor import run_argv  # noqa: PLC0415

    outcome = run_argv(
        _argv("import sys, time; sys.stderr.write('late'); sys.stderr.flush(); time.sleep(30)"),
        cwd=tmp_path,
        timeout_seconds=1,
        should_stop=lambda: False,
    )
    assert (outcome.status, outcome.exit_code, outcome.detail) == (
        ToolStatus.TIMEOUT,
        None,
        "killed after 1s",
    )
    assert outcome.stderr == "late"
    assert 900 <= outcome.duration_ms < 10_000


def test_a_stoppable_run_of_a_missing_binary_is_missing(tmp_path: Path) -> None:
    from app.analysis.runners.executor import run_argv  # noqa: PLC0415

    outcome = run_argv(
        ["/nonexistent/tool", "x"], cwd=tmp_path, timeout_seconds=5, should_stop=lambda: False
    )
    assert (outcome.status, outcome.exit_code, outcome.stderr, outcome.detail) == (
        ToolStatus.MISSING,
        None,
        "",
        "/nonexistent/tool not found",
    )
    assert 0 <= outcome.duration_ms < 5_000


def _second_ask() -> Callable[[], bool]:
    """No on the first ask (the child has time to write), yes on the next."""
    asked: list[int] = []

    def should_stop() -> bool:
        asked.append(1)
        return len(asked) > 1

    return should_stop


def test_a_stopped_run_keeps_its_stderr_and_an_unconfirmed_kill(tmp_path: Path) -> None:
    from app.analysis.runners.executor import run_argv  # noqa: PLC0415

    outcome = run_argv(
        _argv("import sys, time; sys.stderr.write('partial'); sys.stderr.flush(); time.sleep(30)"),
        cwd=tmp_path,
        timeout_seconds=30,
        on_timeout=lambda: False,
        should_stop=_second_ask(),
    )
    assert (outcome.stopped, outcome.kill_confirmed, outcome.status) == (True, False, None)
    assert outcome.stderr == "partial"
    assert 0 < outcome.duration_ms < 10_000


def test_a_stop_is_seen_at_the_first_slice_and_keeps_what_was_printed(tmp_path: Path) -> None:
    started = time.monotonic()
    done = run_stoppable(
        ["sh", "-c", "echo out; echo err >&2; exec sleep 30"],
        timeout_seconds=30,
        should_stop=lambda: time.monotonic() - started > 0.2,
        poll_seconds=0.1,
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert time.monotonic() - started < 0.9  # the slice is the poll, never a second
    assert (done.ending, done.stdout, done.stderr) == (Ending.STOPPED, b"out\n", b"err\n")


def test_a_stoppable_run_gets_its_env_and_cwd(tmp_path: Path) -> None:
    done = run_stoppable(
        ["sh", "-c", 'echo "$DIOPTRA_PROBE:$(pwd)"'],
        timeout_seconds=30,
        should_stop=lambda: False,
        cwd=tmp_path,
        env={"DIOPTRA_PROBE": "seen", "PATH": "/usr/bin:/bin"},
    )
    assert done.stdout.decode().strip() == f"seen:{tmp_path}"


# --- the stoppable clone keeps the clone's contract --------------------------------


def _fake_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    fake = tmp_path / "git"
    fake.write_text(f'#!/bin/sh\nfor last; do :; done\nmkdir -p "$last"\n{body}\n')
    fake.chmod(0o755)
    monkeypatch.setattr("app.ingest.git_source.shutil.which", lambda _name: str(fake))
    monkeypatch.setattr(
        "app.ingest.git_source.socket.getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("140.82.112.3", 443))],
    )
    return tmp_path / "a" / "clone"


def test_a_stoppable_clone_that_succeeds_keeps_its_tree_and_its_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.ingest.git_source import shallow_clone  # noqa: PLC0415

    destination = _fake_git(
        tmp_path, monkeypatch, 'echo "$HOME:$GIT_TERMINAL_PROMPT" > "$last/env"; exit 0'
    )
    shallow_clone(
        "https://github.com/org/repo.git",
        destination,
        timeout_seconds=30,
        should_stop=lambda: False,
    )
    assert (destination / "env").read_text().strip() == f"{destination.parent}:0"


@pytest.mark.parametrize(("body", "timeout"), [("exit 1", 30), ("exec sleep 30", 1)])
def test_a_stoppable_clone_that_fails_or_times_out_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, timeout: int
) -> None:
    from app.ingest.errors import RepoUnreachable  # noqa: PLC0415
    from app.ingest.git_source import shallow_clone  # noqa: PLC0415

    destination = _fake_git(tmp_path, monkeypatch, body)
    with pytest.raises(RepoUnreachable):
        shallow_clone(
            "https://github.com/org/repo.git",
            destination,
            timeout_seconds=timeout,
            should_stop=lambda: False,
        )
    assert not destination.exists()


def test_a_cancel_during_the_extraction_ends_cancelled_with_nothing_left(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The acquisition's ``Stopped`` becomes a cancel, not a crash (mutation pass)."""
    from app.core.process import Stopped  # noqa: PLC0415

    def stopped(workspace: Path, settings: Settings, *, should_stop: object = None) -> None:
        with pipeline.get_session_factory()() as other:  # type: ignore[attr-defined]
            other.execute(update(Analysis).values(cancel_requested_at=utc_now()))
            other.commit()
        workspace.mkdir(parents=True)
        message = "extraction"
        raise Stopped(message)

    executor = FixtureExecutor()
    monkeypatch.setattr("app.analysis.pipeline.extract_upload", stopped)
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: executor)
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))

    db.expire_all()
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert (analysis.status, analysis.failure_code) == (AnalysisStatus.CANCELLED, None)
    assert executor.specs == []
    assert analysis.workspace_path is not None
    assert not Path(analysis.workspace_path).parent.exists()
    assert _actions(db) == [("analysis.cancel", SYSTEM_ACTOR, None)]


def test_a_stop_from_the_acquisition_without_a_request_is_an_abandon(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row left RUNNING under the worker (the sweep): no cancel is invented."""
    from app.core.process import Stopped  # noqa: PLC0415

    def swept(workspace: Path, settings: Settings, *, should_stop: object = None) -> None:
        with pipeline.get_session_factory()() as other:  # type: ignore[attr-defined]
            other.execute(
                update(Analysis).values(
                    status=AnalysisStatus.FAILED, failure_code="analysis_abandoned"
                )
            )
            other.commit()
        message = "extraction"
        raise Stopped(message)

    monkeypatch.setattr("app.analysis.pipeline.extract_upload", swept)
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: FixtureExecutor())
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))
    db.expire_all()
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert (analysis.status, analysis.failure_code) == (AnalysisStatus.FAILED, "analysis_abandoned")
    assert _actions(db) == []
