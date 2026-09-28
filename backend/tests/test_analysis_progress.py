"""The analysis says where it is while it runs (phase 10).

A 1 GiB archive makes the pipeline minutes long; the screen polls and names
the step. These tests pin the three things that has to rest on: the steps are
entered in order, each is visible to ANOTHER session at the moment it runs
(the poll is another request), and nothing is left behind once it ends.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.models import Analysis, AnalysisStatus, SourceKind, ToolRun, ToolStatus
from app.analysis.progress import ACQUIRE, NORMALIZE, pipeline_steps, progress_of
from app.analysis.runners.base import ExecutionResult, RunnerSpec
from app.auth.models import User
from tests.test_pipeline import FixtureExecutor, _ingest, login


def test_the_steps_are_the_acquisition_each_tool_and_the_normalisation() -> None:
    assert pipeline_steps() == (
        ACQUIRE,
        "semgrep",
        "gitleaks",
        "osv-scanner",
        "syft",
        "lizard",
        "cloc",
        NORMALIZE,
    )


@pytest.mark.parametrize(
    ("status", "step", "expected"),
    [
        (AnalysisStatus.RUNNING, "semgrep", (2, 8)),
        (AnalysisStatus.RUNNING, ACQUIRE, (1, 8)),
        (AnalysisStatus.RUNNING, NORMALIZE, (8, 8)),
        (AnalysisStatus.RUNNING, "not-a-step", None),
        (AnalysisStatus.RUNNING, None, None),
        (AnalysisStatus.QUEUED, "semgrep", None),
        (AnalysisStatus.DONE, "cloc", None),
        (AnalysisStatus.FAILED, "semgrep", None),
    ],
)
def test_progress_is_only_said_of_a_running_analysis_on_a_known_step(
    status: AnalysisStatus, step: str | None, expected: tuple[int, int] | None
) -> None:
    analysis = Analysis(
        project_id=uuid.uuid4(), source_kind=SourceKind.ZIP, source_ref="x", status=status
    )
    analysis.current_step = step
    progress = progress_of(analysis)
    if expected is None:
        assert progress is None
    else:
        assert progress is not None
        assert (progress.index, progress.total, progress.step) == (*expected, step)


class WatchingExecutor(FixtureExecutor):
    """Looks at the analysis from ANOTHER session while each tool runs."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        super().__init__()
        self.sessions = sessions
        self.seen: list[tuple[str, str | None, str | None, int]] = []

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        with self.sessions() as other:
            analysis = other.scalars(select(Analysis)).one()
            finished = other.scalar(
                select(func.count()).select_from(ToolRun).where(ToolRun.analysis_id == analysis.id)
            )
            self.seen.append(
                (spec.tool, analysis.current_step, analysis.status.value, finished or 0)
            )
        return super().run(spec, workspace=workspace, out_dir=out_dir)


def test_each_step_is_visible_to_a_poll_while_it_runs(
    client: TestClient,
    analyst: User,
    db: Session,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watcher = WatchingExecutor(session_factory)
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _settings: watcher)
    entered: list[str] = []
    from app.analysis import pipeline

    original = pipeline._enter

    def spy(db_: Session, analysis: Any, step: str) -> None:
        entered.append(step)
        original(db_, analysis, step)

    monkeypatch.setattr(pipeline, "_enter", spy)

    analysis_id = _ingest(client, login(client, analyst.username))

    assert tuple(entered) == pipeline_steps()
    main_runs = [seen for seen in watcher.seen if not seen[0].endswith("-history")]
    for position, (tool, step, status, finished) in enumerate(main_runs):
        # The step names the tool that is running, from another session.
        assert (tool, step, status) == (tool, tool, "running")
        # Every tool before this one already left its committed row.
        assert finished >= position
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None
    db.refresh(analysis)
    assert analysis.status is AnalysisStatus.DONE
    assert analysis.current_step is None
    assert (
        client.get(
            f"/api/v1/analyses/{analysis_id}", headers=login(client, analyst.username)
        ).json()["progress"]
        is None
    )


def test_a_failed_run_leaves_no_step_behind(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Broken(FixtureExecutor):
        def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
            del spec, workspace, out_dir
            return ExecutionResult(ToolStatus.FAILED, 2, "boom", None, False, 1, "exit 2")

    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _settings: Broken())
    headers = login(client, analyst.username)
    project = client.post(
        "/api/v1/projects", json={"name": "p-broken", "system": {"name": "s"}}, headers=headers
    ).json()
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.js", "1")
    body = client.post(
        f"/api/v1/projects/{project['id']}/ingest",
        content=buffer.getvalue(),
        headers={**headers, "Content-Type": "application/zip"},
    ).json()
    assert (body["status"], body["failure_code"], body["progress"]) == (
        "failed",
        "no_tool_ran",
        None,
    )
    analysis = db.get(Analysis, uuid.UUID(body["id"]))
    assert analysis is not None
    db.refresh(analysis)
    assert analysis.current_step is None


def test_the_api_reports_the_step_of_a_running_analysis(
    client: TestClient, analyst: User, db: Session
) -> None:
    headers = login(client, analyst.username)
    project = client.post(
        "/api/v1/projects", json={"name": "p-running", "system": {"name": "s"}}, headers=headers
    ).json()
    analysis = Analysis(
        project_id=uuid.UUID(project["id"]),
        source_kind=SourceKind.ZIP,
        source_ref="big.zip",
        status=AnalysisStatus.RUNNING,
    )
    analysis.current_step = "osv-scanner"
    db.add(analysis)
    db.commit()
    body = client.get(f"/api/v1/analyses/{analysis.id}", headers=headers).json()
    assert body["progress"] == {"step": "osv-scanner", "index": 4, "total": 8}
    listed = client.get(f"/api/v1/projects/{project['id']}/analyses", headers=headers).json()
    assert listed[0]["progress"] == {"step": "osv-scanner", "index": 4, "total": 8}


def test_entering_a_step_commits_it_rather_than_flushing() -> None:
    """The suite's SQLite shares one connection, so a flush would look visible
    there; the real poll is another connection and sees only a COMMIT (QA
    panel, phase 10: `_enter` with `flush()` passed every test above)."""
    from app.analysis import pipeline

    calls: list[str] = []

    class Recorder:
        def commit(self) -> None:
            calls.append("commit")

        def flush(self) -> None:
            calls.append("flush")

    analysis = Analysis(project_id=uuid.uuid4(), source_kind=SourceKind.ZIP, source_ref="x")
    pipeline._enter(Recorder(), analysis, "syft")  # type: ignore[arg-type]
    assert analysis.current_step == "syft"
    assert calls == ["commit"]
