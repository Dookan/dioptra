"""Stale analyses are closed, orphan spools cleared, transitions conditional.

Hardening 1.5.1 (`tasks/hardening-1.5.1-survey.md` §2, §5.1, §11): nothing
used to close an analysis whose worker died, and `run_pipeline` re-ran any row
it was handed. Every case of the survey's table is here, plus the race the
panel named: a worker still alive after the sweep must not revive its row.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select, text, update
from sqlalchemy.orm import ORMExecuteState, Session

from app.analysis import pipeline
from app.analysis.models import Analysis, AnalysisStatus, SourceKind, ToolRun
from app.analysis.runners.base import ExecutionResult, RunnerSpec
from app.analysis.sweep import ABANDONED, AnalysisSweepStats, sweep_analyses, sweep_quietly
from app.audit.models import AuditLogEntry
from app.auth.models import SYSTEM_ACTOR, User
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.ingest.upload import UPLOAD_NAME
from app.projects.models import Project
from tests.test_pipeline import FixtureExecutor, _ingest, login


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    root = tmp_path / "ws"
    root.mkdir()
    return get_settings().model_copy(update={"workspace_root": root})


def _project(db: Session) -> Project:
    project = Project(name=f"p-{uuid.uuid4().hex[:8]}")
    db.add(project)
    db.commit()
    return project


def _analysis(
    db: Session,
    project: Project,
    status: AnalysisStatus,
    *,
    age: timedelta = timedelta(0),
) -> Analysis:
    now = utc_now()
    analysis = Analysis(
        project_id=project.id,
        source_kind=SourceKind.ZIP,
        source_ref="x.zip",
        status=status,
        created_at=now - age,
        started_at=(now - age) if status is not AnalysisStatus.QUEUED else None,
        current_step="semgrep" if status is AnalysisStatus.RUNNING else None,
    )
    db.add(analysis)
    db.commit()
    return analysis


def _tree(settings: Settings, project_id: uuid.UUID, analysis_id: uuid.UUID) -> Path:
    directory = settings.workspace_root / str(project_id) / str(analysis_id)
    (directory / "src").mkdir(parents=True)
    (directory / "src" / "a.js").write_text("x\n", encoding="utf-8")
    (directory / UPLOAD_NAME).write_bytes(b"PK")
    return directory


def _age(path: Path, minutes: int) -> None:
    stamp = (utc_now() - timedelta(minutes=minutes)).timestamp()
    os.utime(path, (stamp, stamp))


def _raw_status(db: Session, analysis_id: uuid.UUID) -> str:
    rows = db.execute(text("SELECT id, status FROM analyses")).all()
    wanted = analysis_id.hex
    return str(next(status for ident, status in rows if str(ident).replace("-", "") == wanted))


# --- the stale pass ------------------------------------------------------------


def test_a_running_analysis_past_the_window_is_abandoned_with_its_files(
    db: Session, settings: Settings
) -> None:
    project = _project(db)
    stale = _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(minutes=121))
    directory = _tree(settings, project.id, stale.id)

    stats = sweep_analyses(db, settings)

    db.refresh(stale)
    assert stats.abandoned == 1
    assert stale.status is AnalysisStatus.FAILED
    assert stale.failure_code == ABANDONED
    assert stale.current_step is None
    assert stale.finished_at is not None
    assert not directory.exists()
    # The status column stores the member NAME: a raw 'failed' would never match.
    assert _raw_status(db, stale.id) == "FAILED"
    rows = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "analysis.abandon")).all()
    assert [(row.actor_username, row.target) for row in rows] == [
        (SYSTEM_ACTOR, f"{stale.id} was running")
    ]


def test_a_running_analysis_inside_the_window_is_left_alone(
    db: Session, settings: Settings
) -> None:
    project = _project(db)
    live = _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(minutes=119))
    directory = _tree(settings, project.id, live.id)
    _age(directory / UPLOAD_NAME, 119)

    stats = sweep_analyses(db, settings)

    db.refresh(live)
    assert stats.abandoned == 0
    assert live.status is AnalysisStatus.RUNNING
    assert (directory / UPLOAD_NAME).exists()


def test_a_queued_analysis_is_abandoned_only_after_the_retention_window(
    db: Session, settings: Settings
) -> None:
    project = _project(db)
    waiting = _analysis(db, project, AnalysisStatus.QUEUED, age=timedelta(hours=23))
    lost = _analysis(db, project, AnalysisStatus.QUEUED, age=timedelta(hours=25))
    waiting_dir = _tree(settings, project.id, waiting.id)
    _age(waiting_dir / UPLOAD_NAME, 23 * 60)
    lost_dir = _tree(settings, project.id, lost.id)

    stats = sweep_analyses(db, settings)

    db.refresh(waiting)
    db.refresh(lost)
    assert stats.abandoned == 1
    assert waiting.status is AnalysisStatus.QUEUED
    assert (waiting_dir / UPLOAD_NAME).exists()
    assert (lost.status, lost.failure_code) == (AnalysisStatus.FAILED, ABANDONED)
    assert not lost_dir.exists()


def test_finished_analyses_are_never_abandoned(db: Session, settings: Settings) -> None:
    project = _project(db)
    done = _analysis(db, project, AnalysisStatus.DONE, age=timedelta(days=3))
    failed = _analysis(db, project, AnalysisStatus.FAILED, age=timedelta(days=3))
    sweep_analyses(db, settings)
    db.refresh(done)
    db.refresh(failed)
    assert done.status is AnalysisStatus.DONE
    assert failed.status is AnalysisStatus.FAILED
    assert failed.failure_code is None


# --- the spool pass --------------------------------------------------------------


def test_an_old_spool_without_a_row_takes_its_directory_with_it(
    db: Session, settings: Settings
) -> None:
    directory = _tree(settings, uuid.uuid4(), uuid.uuid4())
    _age(directory / UPLOAD_NAME, 121)
    stats = sweep_analyses(db, settings)
    assert stats.orphans_removed == 1
    assert not directory.exists()


def test_a_young_spool_without_a_row_is_an_upload_still_arriving(
    db: Session, settings: Settings
) -> None:
    directory = _tree(settings, uuid.uuid4(), uuid.uuid4())
    _age(directory / UPLOAD_NAME, 60)
    assert sweep_analyses(db, settings).orphans_removed == 0
    assert (directory / UPLOAD_NAME).exists()


def test_a_finished_analysis_loses_its_stray_spool_and_keeps_its_jail(
    db: Session, settings: Settings
) -> None:
    project = _project(db)
    for status in (AnalysisStatus.DONE, AnalysisStatus.FAILED):
        row = _analysis(db, project, status)
        directory = _tree(settings, project.id, row.id)
        _age(directory / UPLOAD_NAME, 121)
        sweep_analyses(db, settings)
        assert not (directory / UPLOAD_NAME).exists()
        assert (directory / "src" / "a.js").is_file()


def test_the_spool_pass_leaves_queued_and_running_rows_to_the_stale_pass(
    db: Session, settings: Settings
) -> None:
    project = _project(db)
    queued = _analysis(db, project, AnalysisStatus.QUEUED, age=timedelta(hours=2))
    directory = _tree(settings, project.id, queued.id)
    _age(directory / UPLOAD_NAME, 121)
    stats = sweep_analyses(db, settings)
    assert (stats.orphans_removed, stats.spools_removed) == (0, 0)
    assert (directory / UPLOAD_NAME).exists()


def test_the_spool_pass_touches_only_uuid_directories_and_never_follows_a_link(
    db: Session, settings: Settings, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / UPLOAD_NAME).write_bytes(b"PK")
    _age(outside / UPLOAD_NAME, 500)
    project_dir = settings.workspace_root / str(uuid.uuid4())
    project_dir.mkdir()
    (project_dir / str(uuid.uuid4())).symlink_to(outside)
    (settings.workspace_root / str(uuid.uuid4())).symlink_to(tmp_path)
    named = settings.workspace_root / "not-a-uuid" / str(uuid.uuid4())
    named.mkdir(parents=True)
    (named / UPLOAD_NAME).write_bytes(b"PK")
    _age(named / UPLOAD_NAME, 500)
    link_spool = _tree(settings, uuid.uuid4(), uuid.uuid4())
    (link_spool / UPLOAD_NAME).unlink()
    (link_spool / UPLOAD_NAME).symlink_to(outside / UPLOAD_NAME)

    stats = sweep_analyses(db, settings)

    assert (stats.orphans_removed, stats.spools_removed) == (0, 0)
    assert (outside / UPLOAD_NAME).exists()
    assert (named / UPLOAD_NAME).exists()
    assert link_spool.exists()


def test_a_missing_workspace_root_is_nothing_to_sweep(db: Session, tmp_path: Path) -> None:
    settings = get_settings().model_copy(update={"workspace_root": tmp_path / "absent"})
    assert sweep_analyses(db, settings).orphans_removed == 0


def test_a_failing_sweep_never_reaches_the_caller(
    db: Session, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("disk")

    monkeypatch.setattr("app.analysis.sweep.sweep_analyses", boom)
    sweep_quietly(db, settings)  # no exception


# --- settings --------------------------------------------------------------------


def test_the_stale_window_must_exceed_the_pipelines_timeout() -> None:
    # runner 600 s × 8 + clone 300 s = 5 100 s = 85 min.
    with pytest.raises(ValueError, match="ANALYSIS_STALE_MINUTES"):
        Settings(analysis_stale_minutes=85)  # type: ignore[call-arg]
    Settings(analysis_stale_minutes=86)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="QUEUE_RETENTION_HOURS"):
        Settings(analysis_stale_minutes=180, analysis_queue_retention_hours=2)  # type: ignore[call-arg]


# --- conditional transitions --------------------------------------------------


def test_a_job_for_a_row_that_is_not_queued_does_nothing(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: FixtureExecutor())
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE
    runs, findings = len(analysis.tool_runs), len(analysis.findings)

    pipeline.run_pipeline(analysis_id)  # a duplicate message

    db.expire_all()
    again = db.get(Analysis, analysis_id)
    assert again is not None
    assert again.status is AnalysisStatus.DONE
    assert (len(again.tool_runs), len(again.findings)) == (runs, findings)


def test_the_sweep_closing_a_row_stops_its_worker_and_keeps_the_outcome(
    client: TestClient,
    analyst: User,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The worker is alive and runs on; the sweep closes its row mid-run."""

    class SweptMidRun(FixtureExecutor):
        def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
            result = super().run(spec, workspace=workspace, out_dir=out_dir)
            if len(self.specs) == 1:  # the first tool that actually runs, whichever it is
                with pipeline.get_session_factory()() as other:  # type: ignore[attr-defined]
                    other.execute(
                        text("UPDATE analyses SET status = 'FAILED', failure_code = :code"),
                        {"code": ABANDONED},
                    )
                    other.commit()
            return result

    executor = SweptMidRun()
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: executor)
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))

    db.expire_all()
    analysis = db.get(Analysis, analysis_id)
    assert analysis is not None
    assert (analysis.status, analysis.failure_code) == (AnalysisStatus.FAILED, ABANDONED)
    # The next step saw the row closed and stopped: only the first tool (and its
    # own history pass, which is part of the same step) ever ran.
    first = executor.specs[0].tool
    assert executor.specs
    assert all(spec.tool.startswith(first) for spec in executor.specs), executor.specs
    assert not analysis.findings


def test_a_late_finish_never_revives_an_abandoned_row(db: Session, settings: Settings) -> None:
    project = _project(db)
    row = _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(hours=3))
    sweep_analyses(db, settings)

    pipeline._close(db, row.id, AnalysisStatus.DONE, None)
    pipeline._close(db, row.id, AnalysisStatus.FAILED, "pipeline_error")

    db.refresh(row)
    assert (row.status, row.failure_code) == (AnalysisStatus.FAILED, ABANDONED)
    with pytest.raises(pipeline.AnalysisAbandoned):
        pipeline._enter(db, row, "lizard")


def test_a_running_row_is_closed_by_its_own_worker(db: Session) -> None:
    project = _project(db)
    row = _analysis(db, project, AnalysisStatus.RUNNING)
    pipeline._enter(db, row, "lizard")
    assert row.current_step == "lizard"
    pipeline._close(db, row.id, AnalysisStatus.FAILED, "no_tool_ran")
    db.refresh(row)
    assert (row.status, row.failure_code) == (AnalysisStatus.FAILED, "no_tool_ran")
    assert db.scalar(select(Analysis.current_step).where(Analysis.id == row.id)) is None
    assert row.finished_at is not None
    assert _raw_status(db, row.id) == "FAILED"


def test_the_ingest_route_sweeps_before_it_spools(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: FixtureExecutor())
    project = _project(db)
    stale = _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(hours=3))
    _ingest(client, login(client, analyst.username))
    db.refresh(stale)
    assert (stale.status, stale.failure_code) == (AnalysisStatus.FAILED, ABANDONED)


# --- mutation pass (1.5.1): what the first tests did not pin ---------------------


def _at(db: Session, project: Project, status: AnalysisStatus, when: datetime) -> Analysis:
    analysis = Analysis(
        project_id=project.id,
        source_kind=SourceKind.ZIP,
        source_ref="x.zip",
        status=status,
        created_at=when,
        started_at=when if status is AnalysisStatus.RUNNING else None,
    )
    db.add(analysis)
    db.commit()
    return analysis


def test_the_windows_are_strict_at_their_exact_edge(db: Session, settings: Settings) -> None:
    now = utc_now()
    project = _project(db)
    running = _at(db, project, AnalysisStatus.RUNNING, now - timedelta(minutes=120))
    queued = _at(db, project, AnalysisStatus.QUEUED, now - timedelta(hours=24))
    orphan = _tree(settings, uuid.uuid4(), uuid.uuid4())
    stamp = (now - timedelta(minutes=120)).timestamp()
    os.utime(orphan / UPLOAD_NAME, (stamp, stamp))

    stats = sweep_analyses(db, settings, now=now)

    assert stats == AnalysisSweepStats(0, 0, 0)
    db.refresh(running)
    db.refresh(queued)
    assert (running.status, queued.status) == (AnalysisStatus.RUNNING, AnalysisStatus.QUEUED)
    assert (orphan / UPLOAD_NAME).exists()


def test_every_stale_row_and_every_spool_is_counted(db: Session, settings: Settings) -> None:
    project = _project(db)
    for _ in range(2):
        _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(hours=3))
    for _ in range(2):
        _age(_tree(settings, uuid.uuid4(), uuid.uuid4()) / UPLOAD_NAME, 500)
    for _ in range(2):
        done = _analysis(db, project, AnalysisStatus.DONE)
        _age(_tree(settings, project.id, done.id) / UPLOAD_NAME, 500)
    assert sweep_analyses(db, settings) == AnalysisSweepStats(2, 2, 2)


def test_a_missing_root_reports_nothing_at_all(db: Session, tmp_path: Path) -> None:
    settings = get_settings().model_copy(update={"workspace_root": tmp_path / "absent"})
    assert sweep_analyses(db, settings) == AnalysisSweepStats(0, 0, 0)


def test_a_row_that_moves_on_between_the_read_and_the_update_keeps_its_outcome(
    db: Session, settings: Settings
) -> None:
    project = _project(db)
    finishing = _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(hours=3))
    stuck = _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(hours=3))
    flipped: list[uuid.UUID] = []

    @event.listens_for(db, "do_orm_execute")
    def _worker_finishes_first(state: ORMExecuteState) -> None:
        # The first abandon UPDATE of the pass: its worker commits DONE a moment
        # before, whichever row the sweep reads first.
        if state.is_update and not flipped:
            params = state.statement.compile().params  # type: ignore[attr-defined]
            target = next(v for k, v in params.items() if k.startswith("id"))
            state.session.connection().execute(
                text("UPDATE analyses SET status = 'DONE' WHERE id = :id"), {"id": target.hex}
            )
            flipped.append(target)

    stats = sweep_analyses(db, settings)
    event.remove(db, "do_orm_execute", _worker_finishes_first)

    assert stats.abandoned == 1  # the other one, and the loop went on to it
    db.expire_all()
    raced = db.get(Analysis, flipped[0])
    assert raced is not None
    assert (raced.status, raced.failure_code) == (AnalysisStatus.DONE, None)
    other = stuck if flipped[0] == finishing.id else finishing
    db.refresh(other)
    assert (other.status, other.failure_code) == (AnalysisStatus.FAILED, ABANDONED)
    rows = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "analysis.abandon"))
    assert [row.target for row in rows] == [f"{other.id} was running"]


def test_a_project_directory_that_links_outside_the_root_is_never_followed(
    db: Session, settings: Settings, tmp_path: Path
) -> None:
    project = _project(db)
    stale = _analysis(db, project, AnalysisStatus.RUNNING, age=timedelta(hours=3))
    outside = tmp_path / "elsewhere"
    victim = outside / str(stale.id)
    victim.mkdir(parents=True)
    (victim / "keep.txt").write_text("not ours\n", encoding="utf-8")
    (settings.workspace_root / str(project.id)).symlink_to(outside)

    assert sweep_analyses(db, settings).abandoned == 1
    assert (victim / "keep.txt").is_file()


def test_entries_that_are_not_ours_are_skipped_without_stopping_the_walk(
    db: Session, settings: Settings, tmp_path: Path
) -> None:
    # Sorted before the real orphan: a non-uuid name, a uuid WITHOUT its dashes
    # (the platform never writes one, and the path rebuilt from the id would
    # miss it), and a linked uuid-named directory.
    first, last = uuid.UUID("0" * 32), uuid.UUID("f" * 32)
    (settings.workspace_root / "0-not-a-uuid").mkdir()
    undashed = settings.workspace_root / ("1" * 32) / str(last)
    undashed.mkdir(parents=True)
    (undashed / UPLOAD_NAME).write_bytes(b"PK")
    _age(undashed / UPLOAD_NAME, 500)
    (settings.workspace_root / str(first)).symlink_to(tmp_path)
    project_dir = settings.workspace_root / str(last)
    (project_dir / "0-junk").mkdir(parents=True)
    (project_dir / str(first)).mkdir()  # an analysis dir with no spool
    young = project_dir / str(uuid.UUID("1" * 32))  # an upload still arriving
    young.mkdir()
    (young / UPLOAD_NAME).write_bytes(b"PK")
    orphan = project_dir / str(last)
    orphan.mkdir()
    (orphan / UPLOAD_NAME).write_bytes(b"PK")
    _age(orphan / UPLOAD_NAME, 500)

    assert sweep_analyses(db, settings).orphans_removed == 1
    assert not orphan.exists()
    assert (undashed / UPLOAD_NAME).exists()
    assert (young / UPLOAD_NAME).exists()


def test_a_job_claims_only_its_own_row_and_stamps_it(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    del client  # the app fixture points the pipeline at this test's database
    project = _project(db)
    mine = _analysis(db, project, AnalysisStatus.QUEUED)
    other = _analysis(db, project, AnalysisStatus.QUEUED)
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: FixtureExecutor())

    pipeline.run_pipeline(mine.id)  # no workspace: it fails, but only after claiming

    db.expire_all()
    claimed = db.get(Analysis, mine.id)
    untouched = db.get(Analysis, other.id)
    assert claimed is not None
    assert untouched is not None
    assert claimed.status is AnalysisStatus.FAILED
    assert claimed.started_at is not None
    assert (untouched.status, untouched.started_at) == (AnalysisStatus.QUEUED, None)


def test_a_crash_is_closed_as_a_pipeline_error(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Crashing(FixtureExecutor):
        def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
            del spec, workspace, out_dir
            raise RuntimeError("the executor itself broke")

    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: Crashing())
    analysis = db.get(Analysis, uuid.UUID(_ingest(client, login(client, analyst.username))))
    assert analysis is not None
    assert (analysis.status, analysis.failure_code) == (AnalysisStatus.FAILED, "pipeline_error")
    assert analysis.finished_at is not None


def test_closing_and_entering_touch_only_their_own_row(db: Session) -> None:
    project = _project(db)
    mine = _analysis(db, project, AnalysisStatus.RUNNING)
    other = _analysis(db, project, AnalysisStatus.RUNNING)
    pipeline._enter(db, mine, "cloc")
    pipeline._close(db, mine.id, AnalysisStatus.DONE, None)
    db.refresh(other)
    assert (other.status, other.current_step) == (AnalysisStatus.RUNNING, "semgrep")
    db.refresh(mine)
    assert (mine.status, mine.failure_code) == (AnalysisStatus.DONE, None)


# --- coverage adversary (1.5.1) -------------------------------------------------


def test_a_duplicate_message_for_a_running_analysis_never_runs_it_twice(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: FixtureExecutor())
    analysis_id = uuid.UUID(_ingest(client, login(client, analyst.username)))
    db.execute(
        update(Analysis)
        .where(Analysis.id == analysis_id)
        .values(status=AnalysisStatus.RUNNING, current_step="lizard")
    )
    db.commit()
    before = len(db.scalars(select(ToolRun).where(ToolRun.analysis_id == analysis_id)).all())

    pipeline.run_pipeline(analysis_id)  # the same job delivered again while it runs

    db.expire_all()
    row = db.get(Analysis, analysis_id)
    assert row is not None
    assert (row.status, row.current_step) == (AnalysisStatus.RUNNING, "lizard")
    after = db.scalars(select(ToolRun).where(ToolRun.analysis_id == analysis_id)).all()
    assert len(after) == before


def test_an_old_spool_that_is_a_link_is_never_taken_for_an_orphan(
    db: Session, settings: Settings, tmp_path: Path
) -> None:
    target = tmp_path / "target.zip"
    target.write_bytes(b"PK")
    directory = settings.workspace_root / str(uuid.uuid4()) / str(uuid.uuid4())
    directory.mkdir(parents=True)
    (directory / UPLOAD_NAME).symlink_to(target)
    stamp = (utc_now() - timedelta(minutes=500)).timestamp()
    os.utime(directory / UPLOAD_NAME, (stamp, stamp), follow_symlinks=False)

    assert sweep_analyses(db, settings).orphans_removed == 0
    assert directory.exists()
    assert target.exists()


def test_the_windows_may_be_equal_to_their_floor() -> None:
    Settings(analysis_stale_minutes=120, analysis_queue_retention_hours=2)  # type: ignore[call-arg]
