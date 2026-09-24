"""Phase 8: the PDF export is a worker job (tasks/phase8-survey.md).

The queue runs inline in the suite, so a request that enqueues also renders —
that is the round trip. Tests that need a job to STAY queued replace
``enqueue_report`` with a no-op, which is exactly the state a real broker
leaves a job in until the worker takes it.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth.models import Role, User
from app.auth.service import create_user
from app.core import queue
from app.core.clock import utc_now
from app.core.config import get_settings
from app.reports import engine, jobs
from app.reports.models import ReportJob, ReportJobStatus
from tests.conftest import SEED_PASSWORD
from tests.support import login, make_finding, seed_done_analysis

FAKE_PDF = b"%PDF-1.7 fake body for the job tests"


@pytest.fixture
def fake_render(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Replace WeasyPrint: the jobs are about the queue, not the renderer."""
    calls: list[int] = []

    def render(*_args: Any, **_kwargs: Any) -> bytes:
        calls.append(1)
        return FAKE_PDF

    monkeypatch.setattr(engine, "render_pdf", render)
    return calls


@pytest.fixture
def held(monkeypatch: pytest.MonkeyPatch) -> list[tuple[uuid.UUID, int]]:
    """Enqueue nothing: jobs stay QUEUED, as they do until a worker takes them."""
    enqueued: list[tuple[uuid.UUID, int]] = []

    def enqueue(job_id: uuid.UUID, *, delay_seconds: int = 0) -> None:
        enqueued.append((job_id, delay_seconds))

    monkeypatch.setattr(queue, "enqueue_report", enqueue)
    return enqueued


@pytest.fixture
def other_analyst(db: Session) -> User:
    user = create_user(
        db,
        username="jlopez",
        display_name="Julia Lopez",
        role=Role.ANALYST,
        password=SEED_PASSWORD,
        must_change_password=False,
    )
    db.commit()
    return user


def _spool() -> Path:
    return get_settings().report_spool_dir


def _rows(db: Session, action: str) -> list[AuditLogEntry]:
    db.expire_all()
    return list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == action)))


def _start(client: TestClient, analysis_id: uuid.UUID, headers: dict[str, str]) -> Any:
    return client.post(f"/api/v1/analyses/{analysis_id}/report/jobs", json={}, headers=headers)


# --- the round trip ---------------------------------------------------------------


def test_a_real_pdf_round_trips_and_leaves_nothing_behind(
    client: TestClient, analyst: User, db: Session
) -> None:
    analysis = seed_done_analysis(db, [make_finding(1)])
    headers = login(client, analyst.username)

    started = _start(client, analysis.id, headers)
    assert started.status_code == 202, started.text
    job = started.json()
    assert job["status"] == "done" and job["byte_size"] > 0 and job["ahead"] == 0
    path = _spool() / f"{job['id']}.pdf"
    assert path.is_file()
    assert oct(path.stat().st_mode & 0o777) == "0o600"

    download = client.get(f"/api/v1/report-jobs/{job['id']}/download", headers=headers)
    assert download.status_code == 200
    assert download.content.startswith(b"%PDF")
    assert download.headers["content-type"] == "application/pdf"
    assert "attachment" in download.headers["content-disposition"]
    # Deleted once the response was sent (survey §7.3), and not a second time.
    assert not path.exists()
    again = client.get(f"/api/v1/report-jobs/{job['id']}/download", headers=headers)
    assert again.status_code == 409 and again.json()["code"] == "report_job_not_ready"

    row = db.get(ReportJob, uuid.UUID(job["id"]))
    assert row is not None
    db.refresh(row)
    assert row.status is ReportJobStatus.EXPIRED and row.downloaded_at is not None

    request_rows = _rows(db, "report.export.request")
    assert len(request_rows) == 1
    assert request_rows[0].actor_username == analyst.username
    assert request_rows[0].actor_role == "analyst"
    assert str(analysis.id) in (request_rows[0].target or "")
    worker_rows = _rows(db, "report.export")
    assert len(worker_rows) == 1 and worker_rows[0].outcome is AuditOutcome.OK
    assert worker_rows[0].actor_username == analyst.username
    # "The current version" is resolved and the trail says which one rendered.
    assert "v=1" in (worker_rows[0].target or "")
    assert len(_rows(db, "report.export.download")) == 1


@pytest.mark.parametrize("role_fixture", ["developer", "admin"])
def test_every_role_may_export_the_pdf(
    client: TestClient,
    db: Session,
    fake_render: list[int],
    role_fixture: str,
    request: pytest.FixtureRequest,
) -> None:
    user: User = request.getfixturevalue(role_fixture)
    analysis = seed_done_analysis(db, [make_finding(1)])
    headers = login(client, user.username)
    job = _start(client, analysis.id, headers).json()
    download = client.get(f"/api/v1/report-jobs/{job['id']}/download", headers=headers)
    assert download.status_code == 200 and download.content == FAKE_PDF
    assert fake_render == [1]


def test_the_synchronous_pdf_is_refused_and_renders_nothing(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("the request must not render a PDF")

    monkeypatch.setattr(engine, "render_pdf", explode)
    analysis = seed_done_analysis(db, [make_finding(1)])
    headers = login(client, analyst.username)
    for query in ("?format=pdf", ""):  # "pdf" is also the default
        response = client.get(f"/api/v1/analyses/{analysis.id}/report{query}", headers=headers)
        assert response.status_code == 409
        assert response.json()["code"] == "report_pdf_is_queued"
    # The other three formats stay synchronous.
    for fmt in ("html", "md", "docx"):
        response = client.get(
            f"/api/v1/analyses/{analysis.id}/report?format={fmt}", headers=headers
        )
        assert response.status_code == 200, fmt


def test_a_job_needs_a_finished_analysis_and_an_existing_version(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    from app.analysis.models import AnalysisStatus

    headers = login(client, analyst.username)
    running = seed_done_analysis(db, [], status=AnalysisStatus.RUNNING)
    refused = _start(client, running.id, headers)
    assert refused.status_code == 409 and refused.json()["code"] == "analysis_not_ready"

    done = seed_done_analysis(db, [make_finding(1)])
    missing = client.post(
        f"/api/v1/analyses/{done.id}/report/jobs", json={"version": 7}, headers=headers
    )
    assert missing.status_code == 404
    assert missing.json()["code"] == "report_version_not_found"
    assert held == []
    assert db.scalars(select(ReportJob)).all() == []


# --- one per person, N for the installation (§7.1) ---------------------------------


def test_one_pdf_in_flight_per_person(
    client: TestClient,
    analyst: User,
    other_analyst: User,
    db: Session,
    held: list[Any],
) -> None:
    analysis = seed_done_analysis(db, [make_finding(1)])
    mine = login(client, analyst.username)
    first = _start(client, analysis.id, mine)
    assert first.status_code == 202 and first.json()["status"] == "queued"

    second = _start(client, analysis.id, mine)
    assert second.status_code == 409
    assert second.json()["code"] == "report_job_in_flight"
    # The refusal names the job in flight, so the screen can follow it.
    assert second.json()["context"] == {"job": first.json()["id"]}

    # Someone else's export is not blocked by mine: it waits behind it.
    theirs = _start(client, analysis.id, login(client, other_analyst.username))
    assert theirs.status_code == 202
    assert theirs.json()["ahead"] == 1
    assert [job_id for job_id, _ in held] == [
        uuid.UUID(first.json()["id"]),
        uuid.UUID(theirs.json()["id"]),
    ]


def test_the_database_holds_the_one_per_person_rule(db: Session, analyst: User) -> None:
    analysis = seed_done_analysis(db, [])

    def job(status: ReportJobStatus) -> ReportJob:
        return ReportJob(
            analysis_id=analysis.id, requested_by_username=analyst.username, status=status
        )

    db.add(job(ReportJobStatus.QUEUED))
    db.commit()
    db.add(job(ReportJobStatus.RUNNING))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    # Finished jobs do not hold the slot, however many there are.
    db.add_all(
        [job(ReportJobStatus.DONE), job(ReportJobStatus.ERRORED), job(ReportJobStatus.EXPIRED)]
    )
    db.commit()
    # And the status is stored as the value the index predicate spells.
    raw = db.execute(select(ReportJob.__table__.c.status)).scalars().all()
    assert set(raw) == {"queued", "done", "errored", "expired"}


def test_the_cap_defers_a_job_instead_of_running_it(
    client: TestClient,
    analyst: User,
    other_analyst: User,
    db: Session,
    held: list[Any],
    fake_render: list[int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "max_concurrent_report_jobs", 1)
    analysis = seed_done_analysis(db, [])
    busy = ReportJob(
        analysis_id=analysis.id,
        requested_by_username=other_analyst.username,
        status=ReportJobStatus.RUNNING,
        started_at=utc_now(),
    )
    waiting = ReportJob(analysis_id=analysis.id, requested_by_username=analyst.username)
    db.add_all([busy, waiting])
    db.commit()

    jobs.run_report_job(str(waiting.id))
    db.refresh(waiting)
    assert waiting.status is ReportJobStatus.QUEUED
    assert fake_render == []
    assert held == [(waiting.id, jobs.DEFER_SECONDS)]

    busy.status = ReportJobStatus.DONE
    db.commit()
    jobs.run_report_job(str(waiting.id))
    db.refresh(waiting)
    finished = db.get(ReportJob, waiting.id)
    assert finished is not None
    assert finished.status.value == "done" and fake_render == [1]


# --- who may see and take a job (§7.2) ----------------------------------------------


def test_only_the_requester_or_the_admin_sees_a_job(
    client: TestClient,
    analyst: User,
    other_analyst: User,
    admin: User,
    db: Session,
    fake_render: list[int],
) -> None:
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = _start(client, analysis.id, login(client, analyst.username)).json()["id"]

    stranger = login(client, other_analyst.username)
    for suffix in ("", "/download"):
        response = client.get(f"/api/v1/report-jobs/{job_id}{suffix}", headers=stranger)
        # 404, not 403: a job id is not an existence oracle.
        assert response.status_code == 404
        assert response.json()["code"] == "report_job_not_found"
    denials = _rows(db, "authz.denied")
    assert len(denials) == 2
    assert all(row.actor_username == other_analyst.username for row in denials)
    assert all(job_id in (row.target or "") for row in denials)
    assert (_spool() / f"{job_id}.pdf").is_file()  # the stranger took nothing

    boss = login(client, admin.username)
    assert client.get(f"/api/v1/report-jobs/{job_id}", headers=boss).status_code == 200
    taken = client.get(f"/api/v1/report-jobs/{job_id}/download", headers=boss)
    assert taken.status_code == 200 and taken.content == FAKE_PDF

    unknown = client.get(f"/api/v1/report-jobs/{uuid.uuid4()}", headers=stranger)
    assert unknown.status_code == 404


def test_mine_recovers_the_job_after_a_reload(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    headers = login(client, analyst.username)
    assert client.get("/api/v1/report-jobs/mine", headers=headers).json() is None
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = _start(client, analysis.id, headers).json()["id"]
    mine = client.get("/api/v1/report-jobs/mine", headers=headers).json()
    assert mine["id"] == job_id and mine["status"] == "queued"


def test_an_unwanted_download_is_not_ready(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    headers = login(client, analyst.username)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = _start(client, analysis.id, headers).json()["id"]
    early = client.get(f"/api/v1/report-jobs/{job_id}/download", headers=headers)
    assert early.status_code == 409 and early.json()["code"] == "report_job_not_ready"


# --- the worker -----------------------------------------------------------------------


@pytest.mark.parametrize("argument", ["not-a-uuid", "../../etc/passwd", ""])
def test_a_malformed_job_argument_is_refused(
    argument: str, session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jobs, "get_session_factory", lambda: session_factory)
    before = {entry.name for entry in _spool().iterdir()} if _spool().is_dir() else set()
    jobs.run_report_job(argument)  # never raises
    after = {entry.name for entry in _spool().iterdir()} if _spool().is_dir() else set()
    assert before == after


def test_a_render_failure_is_a_row_not_a_crash(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> bytes:
        raise RuntimeError("WeasyPrint fell over")

    monkeypatch.setattr(engine, "render_pdf", broken)
    analysis = seed_done_analysis(db, [make_finding(1)])
    headers = login(client, analyst.username)
    job = _start(client, analysis.id, headers).json()
    assert job["status"] == "errored" and job["detail"] == "render_failed"
    assert not (_spool() / f"{job['id']}.pdf").exists()
    rows = _rows(db, "report.export")
    assert len(rows) == 1 and rows[0].outcome is AuditOutcome.ERROR
    # A failed job frees its requester at once.
    assert client.get("/api/v1/report-jobs/mine", headers=headers).json() is None


def test_a_full_spool_refuses_to_write(
    client: TestClient,
    analyst: User,
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "report_spool_max_bytes", 1024 * 1024)
    monkeypatch.setattr(engine, "render_pdf", lambda *_a, **_k: b"%PDF" + b"x" * 2 * 1024 * 1024)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job = _start(client, analysis.id, login(client, analyst.username)).json()
    assert job["status"] == "errored" and job["detail"] == "spool_full"
    assert not (_spool() / f"{job['id']}.pdf").exists()


def test_a_broker_outage_does_not_leave_the_person_blocked(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(*_args: Any, **_kwargs: Any) -> None:
        raise ConnectionError("valkey is down")

    monkeypatch.setattr(queue, "enqueue_report", down)
    analysis = seed_done_analysis(db, [make_finding(1)])
    headers = login(client, analyst.username)
    response = _start(client, analysis.id, headers)
    assert response.status_code == 503
    assert response.json()["code"] == "report_enqueue_failed"
    row = db.scalars(select(ReportJob)).one()
    db.refresh(row)
    assert row.status is ReportJobStatus.ERRORED and row.detail == "enqueue_failed"
    monkeypatch.undo()
    monkeypatch.setattr(queue, "enqueue_report", lambda *_a, **_k: None)
    assert _start(client, analysis.id, headers).status_code == 202


def test_each_worker_has_its_own_allowlist() -> None:
    # The socket-holding worker keeps its four; the PDF render lives apart.
    assert {
        queue.PIPELINE_JOB,
        queue.VERIFY_JOB,
        queue.SYNC_JOB,
        queue.IMPORT_JOB,
    } == queue.ALLOWED_JOBS
    assert {"app.reports.jobs.run_report_job"} == queue.REPORT_WORKER_JOBS


# --- the sweep (§7.3) -------------------------------------------------------------------


def test_the_sweep_frees_abandoned_jobs_and_removes_old_files(
    db: Session, analyst: User, other_analyst: User
) -> None:
    settings = get_settings()
    spool = settings.report_spool_dir
    spool.mkdir(parents=True, exist_ok=True)
    analysis = seed_done_analysis(db, [])
    long_ago = utc_now() - timedelta(hours=settings.report_job_retention_hours + 1)
    dead = ReportJob(
        analysis_id=analysis.id,
        requested_by_username=analyst.username,
        status=ReportJobStatus.RUNNING,
        created_at=long_ago,
        started_at=long_ago,
    )
    fresh = ReportJob(
        analysis_id=analysis.id,
        requested_by_username=other_analyst.username,
        status=ReportJobStatus.RUNNING,
        started_at=utc_now(),
    )
    old_done = ReportJob(
        analysis_id=analysis.id,
        requested_by_username=analyst.username,
        status=ReportJobStatus.DONE,
        finished_at=long_ago,
    )
    kept_done = ReportJob(
        analysis_id=analysis.id,
        requested_by_username=other_analyst.username,
        status=ReportJobStatus.DONE,
        finished_at=utc_now(),
    )
    db.add_all([dead, fresh, old_done, kept_done])
    db.commit()
    for job in (old_done, kept_done):
        jobs.artefact_path(settings, job.id).write_bytes(FAKE_PDF)
    stray_old = spool / f"{uuid.uuid4()}.pdf"
    stray_young = spool / f"{uuid.uuid4()}.pdf"
    stray_old.write_bytes(b"x")
    stray_young.write_bytes(b"x")
    ancient = time.time() - 3 * 3600
    os.utime(stray_old, (ancient, ancient))

    stats = jobs.sweep(db, settings)
    db.commit()
    for job in (dead, fresh, old_done, kept_done):
        db.refresh(job)
    assert dead.status is ReportJobStatus.ERRORED and dead.detail == "abandoned"
    assert fresh.status is ReportJobStatus.RUNNING
    assert old_done.status is ReportJobStatus.EXPIRED
    assert not jobs.artefact_path(settings, old_done.id).exists()
    assert kept_done.status is ReportJobStatus.DONE
    assert jobs.artefact_path(settings, kept_done.id).exists()
    assert not stray_old.exists()
    # A young file may be a job a moment away from its DONE row.
    assert stray_young.exists()
    assert stats.abandoned == 1 and stats.expired == 1 and stats.strays == 1
    stray_young.unlink()
    jobs.artefact_path(settings, kept_done.id).unlink()


def test_a_render_the_sweep_abandoned_stays_abandoned(
    client: TestClient,
    analyst: User,
    db: Session,
    session_factory: sessionmaker[Session],
    held: list[Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A job swept while it rendered is not turned back into DONE (phase-8 panel)."""
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = uuid.UUID(_start(client, analysis.id, login(client, analyst.username)).json()["id"])

    def render_while_swept(*_args: Any, **_kwargs: Any) -> bytes:
        with session_factory() as other:
            row = other.get(ReportJob, job_id)
            assert row is not None and row.status is ReportJobStatus.RUNNING
            row.status = ReportJobStatus.ERRORED
            row.detail = "abandoned"
            other.commit()
        return FAKE_PDF

    monkeypatch.setattr(engine, "render_pdf", render_while_swept)
    jobs.run_report_job(str(job_id))
    row = db.get(ReportJob, job_id)
    assert row is not None
    db.refresh(row)
    assert row.status is ReportJobStatus.ERRORED and row.detail == "abandoned"
    assert not jobs.artefact_path(get_settings(), job_id).exists()
    assert _rows(db, "report.export") == []


def test_the_stale_threshold_cannot_undercut_a_render() -> None:
    from pydantic import ValidationError

    from app.core.config import Settings

    floor = queue.REPORT_JOB_TIMEOUT_SECONDS // 60
    with pytest.raises(ValidationError):
        Settings(report_job_stale_minutes=floor)  # type: ignore[call-arg]
    assert get_settings().report_job_stale_minutes * 60 > queue.REPORT_JOB_TIMEOUT_SECONDS


# --- regressions the phase-8 coverage adversary proved missing ----------------------


def test_a_lost_insert_race_is_the_typed_refusal(
    client: TestClient,
    analyst: User,
    db: Session,
    held: list[Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two requests pass the pre-check; the index refuses the second one."""
    analysis = seed_done_analysis(db, [make_finding(1)])
    headers = login(client, analyst.username)
    first = _start(client, analysis.id, headers).json()["id"]
    real = jobs.in_flight_for
    calls: list[int] = []

    def blind_once(session: Session, username: str) -> ReportJob | None:
        calls.append(1)
        return None if len(calls) == 1 else real(session, username)

    monkeypatch.setattr(jobs, "in_flight_for", blind_once)
    second = _start(client, analysis.id, headers)
    assert second.status_code == 409, second.text
    assert second.json()["code"] == "report_job_in_flight"
    assert second.json()["context"] == {"job": first}
    assert len(_rows(db, "report.export.request")) == 1


def _job(db: Session, username: str, **fields: Any) -> ReportJob:
    analysis = seed_done_analysis(db, [])
    row = ReportJob(analysis_id=analysis.id, requested_by_username=username, **fields)
    db.add(row)
    db.commit()
    return row


def test_the_sweep_judges_each_state_by_its_own_clock(db: Session, analyst: User) -> None:
    settings = get_settings()
    two_hours = utc_now() - timedelta(hours=2)
    a_day_and_more = utc_now() - timedelta(hours=settings.report_job_retention_hours + 1)
    waiting = _job(db, analyst.username, created_at=two_hours, enqueued_at=two_hours)
    rendering = _job(
        db,
        "jlopez",
        status=ReportJobStatus.RUNNING,
        created_at=two_hours,
        started_at=utc_now(),
    )
    forgotten = _job(db, "cperez", created_at=a_day_and_more, enqueued_at=a_day_and_more)
    stats = jobs.sweep(db, settings)
    db.commit()
    for row in (waiting, rendering, forgotten):
        db.refresh(row)
    # Waiting in a long queue is not being abandoned: its message may be lost,
    # so it is enqueued again, once per stale window (mmarin, phase-8 panel).
    assert waiting.status is ReportJobStatus.QUEUED
    assert stats.requeued == (waiting.id,)
    assert waiting.enqueued_at > two_hours
    assert jobs.sweep(db, settings).requeued == ()
    # A render is aged from when it STARTED, not from when it was asked for.
    assert rendering.status is ReportJobStatus.RUNNING
    # Only a whole retention window in the queue abandons a waiting job.
    assert forgotten.status is ReportJobStatus.ERRORED and forgotten.detail == "abandoned"
    assert forgotten.finished_at is not None
    assert stats.abandoned == 1


def test_the_sweep_keeps_an_old_live_file_and_never_follows_a_link(
    db: Session, analyst: User, tmp_path: Path
) -> None:
    settings = get_settings()
    settings.report_spool_dir.mkdir(parents=True, exist_ok=True)
    live = _job(
        db,
        analyst.username,
        status=ReportJobStatus.DONE,
        finished_at=utc_now() - timedelta(hours=1),
    )
    path = jobs.artefact_path(settings, live.id)
    path.write_bytes(FAKE_PDF)
    hour_ago = time.time() - 3600
    os.utime(path, (hour_ago, hour_ago))
    target = tmp_path / "outside.txt"
    target.write_text("not ours")
    link = settings.report_spool_dir / f"{uuid.uuid4()}.pdf"
    link.symlink_to(target)
    ancient = time.time() - 3 * 3600
    # Old on BOTH sides: stat() follows a link, so a fresh target would hide a
    # sweep that forgot to skip links behind the "too young" guard.
    os.utime(target, (ancient, ancient))
    os.utime(link, (ancient, ancient), follow_symlinks=False)
    try:
        stats = jobs.sweep(db, settings)
        db.commit()
        assert stats.strays == 0
        assert path.exists() and link.is_symlink() and target.exists()
    finally:
        path.unlink(missing_ok=True)
        link.unlink(missing_ok=True)


def test_an_early_download_leaves_the_job_alone(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    headers = login(client, analyst.username)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = _start(client, analysis.id, headers).json()["id"]
    assert client.get(f"/api/v1/report-jobs/{job_id}/download", headers=headers).status_code == 409
    assert client.get(f"/api/v1/report-jobs/{job_id}", headers=headers).json()["status"] == "queued"


def test_the_first_download_expires_the_job(
    client: TestClient, analyst: User, db: Session, fake_render: list[int]
) -> None:
    headers = login(client, analyst.username)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = _start(client, analysis.id, headers).json()["id"]
    assert client.get(f"/api/v1/report-jobs/{job_id}/download", headers=headers).status_code == 200
    row = db.get(ReportJob, uuid.UUID(job_id))
    assert row is not None
    db.refresh(row)
    assert row.status is ReportJobStatus.EXPIRED and row.detail is None


def test_a_redelivered_job_is_not_rendered_twice(
    db: Session,
    analyst: User,
    fake_render: list[int],
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(jobs, "get_session_factory", lambda: session_factory)
    done = _job(db, analyst.username, status=ReportJobStatus.DONE, finished_at=utc_now())
    jobs.run_report_job(str(done.id))
    assert fake_render == []


def test_the_spool_cap_counts_what_is_already_there(
    client: TestClient,
    analyst: User,
    db: Session,
    fake_render: list[int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cap = 1024 * 1024
    monkeypatch.setattr(get_settings(), "report_spool_max_bytes", cap)
    spool = _spool()
    spool.mkdir(parents=True, exist_ok=True)
    filler = spool / f"{uuid.uuid4()}.pdf"
    filler.write_bytes(b"x" * (cap - 5))
    try:
        analysis = seed_done_analysis(db, [make_finding(1)])
        job = _start(client, analysis.id, login(client, analyst.username)).json()
        assert job["status"] == "errored" and job["detail"] == "spool_full"
    finally:
        filler.unlink()


def test_the_queue_position_counts_running_jobs_ahead(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    ahead_one = _job(db, "jlopez", status=ReportJobStatus.RUNNING, started_at=utc_now())
    _job(db, "cperez", status=ReportJobStatus.RUNNING, started_at=utc_now())
    analysis = seed_done_analysis(db, [make_finding(1)])
    job = _start(client, analysis.id, login(client, analyst.username)).json()
    assert job["ahead"] == 2
    assert jobs.queue_position(db, ahead_one) == 0


def test_mine_returns_a_finished_job_not_yet_taken(
    client: TestClient, analyst: User, db: Session, fake_render: list[int]
) -> None:
    headers = login(client, analyst.username)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = _start(client, analysis.id, headers).json()["id"]
    mine = client.get("/api/v1/report-jobs/mine", headers=headers).json()
    assert mine is not None and mine["id"] == job_id and mine["status"] == "done"


def test_a_request_sweeps_before_it_checks_the_slot(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    settings = get_settings()
    long_ago = utc_now() - timedelta(hours=settings.report_job_retention_hours + 1)
    _job(db, analyst.username, created_at=long_ago, enqueued_at=long_ago)
    analysis = seed_done_analysis(db, [make_finding(1)])
    assert _start(client, analysis.id, login(client, analyst.username)).status_code == 202


def test_a_job_whose_message_was_lost_is_enqueued_again(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    """A broker restart must not strand a job: the next request re-enqueues it."""
    two_hours = utc_now() - timedelta(hours=2)
    lost = _job(db, analyst.username, created_at=two_hours, enqueued_at=two_hours)
    headers = login(client, analyst.username)
    mine = client.get("/api/v1/report-jobs/mine", headers=headers).json()
    assert mine["id"] == str(lost.id) and mine["status"] == "queued"
    assert held == [(lost.id, 0)]
    # Still the person's job in flight: waiting is not a reason to free the slot.
    analysis = seed_done_analysis(db, [make_finding(1)])
    assert _start(client, analysis.id, headers).status_code == 409
    assert held == [(lost.id, 0)]  # once per stale window, not once per request


def test_a_deferral_counts_as_an_enqueue(
    db: Session,
    analyst: User,
    other_analyst: User,
    held: list[Any],
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(jobs, "get_session_factory", lambda: session_factory)
    monkeypatch.setattr(get_settings(), "max_concurrent_report_jobs", 1)
    _job(db, other_analyst.username, status=ReportJobStatus.RUNNING, started_at=utc_now())
    two_hours = utc_now() - timedelta(hours=2)
    waiting = _job(db, analyst.username, created_at=two_hours, enqueued_at=two_hours)
    jobs.run_report_job(str(waiting.id))
    db.refresh(waiting)
    # One message: the deferral itself, never a second chain from the sweep.
    assert held == [(waiting.id, jobs.DEFER_SECONDS)]
    assert waiting.enqueued_at > two_hours


def test_an_existing_file_is_never_overwritten(
    client: TestClient,
    analyst: User,
    db: Session,
    held: list[Any],
    fake_render: list[int],
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(jobs, "get_session_factory", lambda: session_factory)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = uuid.UUID(_start(client, analysis.id, login(client, analyst.username)).json()["id"])
    planted = jobs.artefact_path(get_settings(), job_id)
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes(b"planted")
    try:
        jobs.run_report_job(str(job_id))
        row = db.get(ReportJob, job_id)
        assert row is not None
        db.refresh(row)
        assert row.status is ReportJobStatus.ERRORED and row.detail == "write_failed"
        assert planted.read_bytes() == b"planted"
    finally:
        planted.unlink(missing_ok=True)


# --- phase-8 mutmut pass: the survivors that were real gaps -------------------------


@pytest.fixture
def rendered_versions(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int | None, int]]:
    """Replace WeasyPrint; remember WHICH version each render was asked for, and
    how many versions it was given for the report's version-control table."""
    seen: list[tuple[int | None, int]] = []

    def render(*_args: Any, version: Any = None, versions: Any = (), **_kwargs: Any) -> bytes:
        seen.append((version.number if version is not None else None, len(versions)))
        return FAKE_PDF

    monkeypatch.setattr(engine, "render_pdf", render)
    return seen


def _three_versions(db: Session, analysis: Any, analyst: User) -> None:
    """v1 baseline, v2 and v3 edited: with only two, `history[1]` IS the newest."""
    from app.reports import versions

    for text in ("Texto propio del analista.", "Segunda redacción del analista."):
        versions.save_sections(
            db,
            analysis=analysis,
            actor=analyst,
            sections={"introduction": text},
            change_summary="Edición de la introducción.",
            source_ip=None,
        )
    db.commit()


def test_the_worker_renders_the_version_it_was_asked_for(
    client: TestClient,
    analyst: User,
    db: Session,
    rendered_versions: list[tuple[int | None, int]],
) -> None:
    analysis = seed_done_analysis(db, [make_finding(1)])
    _three_versions(db, analysis, analyst)
    headers = login(client, analyst.username)

    pinned = client.post(
        f"/api/v1/analyses/{analysis.id}/report/jobs", json={"version": 1}, headers=headers
    ).json()
    assert pinned["version"] == 1 and pinned["format"] == "pdf"
    taken = client.get(f"/api/v1/report-jobs/{pinned['id']}/download", headers=headers)
    assert taken.status_code == 200
    current = _start(client, analysis.id, headers).json()
    assert current["version"] is None

    # The pinned job renders v1; "the current one" resolves to the NEWEST, v3.
    # Both get the whole history for the version-control table.
    assert rendered_versions == [(1, 3), (3, 3)]
    targets = [row.target for row in _rows(db, "report.export")]
    assert targets == [
        f"{analysis.id} job={pinned['id']} v=1",
        f"{analysis.id} job={current['id']} v=3",
    ]
    requests = [row.target for row in _rows(db, "report.export.request")]
    assert requests == [f"{analysis.id} pdf v=1", f"{analysis.id} pdf v=current"]


def test_every_audit_row_names_its_actor_fully(
    client: TestClient, analyst: User, other_analyst: User, db: Session, fake_render: list[int]
) -> None:
    analysis = seed_done_analysis(db, [make_finding(1)])
    headers = login(client, analyst.username)
    job_id = _start(client, analysis.id, headers).json()["id"]
    stranger = login(client, other_analyst.username)
    assert client.get(f"/api/v1/report-jobs/{job_id}", headers=stranger).status_code == 404
    taking = client.get(f"/api/v1/report-jobs/{job_id}/download", headers=stranger)
    assert taking.status_code == 404
    download = client.get(f"/api/v1/report-jobs/{job_id}/download", headers=headers)
    assert download.headers["content-disposition"].endswith('.pdf"')

    (request,) = _rows(db, "report.export.request")
    (worker,) = _rows(db, "report.export")
    (taken,) = _rows(db, "report.export.download")
    denials = _rows(db, "authz.denied")
    assert len(denials) == 2  # the peek and the attempt to take it
    for row in (request, taken):
        assert row.actor_id == analyst.id and row.actor_role == "analyst"
        assert row.source_ip == "testclient"
    assert taken.target == f"{analysis.id} job={job_id}"
    # The worker's row takes the actor from the job ROW.
    assert worker.actor_username == analyst.username and worker.actor_id == analyst.id
    for denied in denials:
        assert denied.actor_id == other_analyst.id and denied.actor_role == "analyst"
        assert denied.outcome is AuditOutcome.DENIED and denied.source_ip == "testclient"


def test_a_failed_render_row_says_what_failed_and_nothing_else(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> bytes:
        raise RuntimeError("boom")

    monkeypatch.setattr(engine, "render_pdf", broken)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job = _start(client, analysis.id, login(client, analyst.username)).json()
    (row,) = _rows(db, "report.export")
    assert row.target == f"{analysis.id} job={job['id']} render_failed"
    stored = db.get(ReportJob, uuid.UUID(job["id"]))
    assert stored is not None
    db.refresh(stored)
    assert stored.finished_at is not None and stored.started_at is not None


def test_mine_is_the_callers_newest_and_only_the_callers(
    client: TestClient,
    analyst: User,
    other_analyst: User,
    db: Session,
    held: list[Any],
) -> None:
    _job(db, other_analyst.username)
    headers = login(client, analyst.username)
    assert client.get("/api/v1/report-jobs/mine", headers=headers).json() is None
    older = _job(
        db,
        analyst.username,
        status=ReportJobStatus.DONE,
        created_at=utc_now() - timedelta(minutes=5),
        finished_at=utc_now() - timedelta(minutes=4),
    )
    analysis = seed_done_analysis(db, [make_finding(1)])
    newest = _start(client, analysis.id, headers).json()
    assert newest["ahead"] == 1  # the other analyst's queued job is ahead
    mine = client.get("/api/v1/report-jobs/mine", headers=headers).json()
    assert mine["id"] == newest["id"] != str(older.id)


def test_a_lone_queued_job_has_nobody_ahead(
    client: TestClient, analyst: User, db: Session, held: list[Any]
) -> None:
    _job(db, "jlopez", status=ReportJobStatus.DONE, created_at=utc_now() - timedelta(hours=1))
    analysis = seed_done_analysis(db, [make_finding(1)])
    job = _start(client, analysis.id, login(client, analyst.username)).json()
    assert job["status"] == "queued" and job["ahead"] == 0


def test_a_broker_outage_closes_only_its_own_job(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = _job(db, "jlopez")

    def down(*_args: Any, **_kwargs: Any) -> None:
        raise ConnectionError("valkey is down")

    monkeypatch.setattr(queue, "enqueue_report", down)
    analysis = seed_done_analysis(db, [make_finding(1)])
    assert _start(client, analysis.id, login(client, analyst.username)).status_code == 503
    mine = db.scalars(
        select(ReportJob).where(ReportJob.requested_by_username == analyst.username)
    ).one()
    db.refresh(other)
    db.refresh(mine)
    assert other.status is ReportJobStatus.QUEUED
    assert mine.status is ReportJobStatus.ERRORED and mine.finished_at is not None


def test_finishing_one_render_leaves_the_others_running(
    db: Session,
    analyst: User,
    fake_render: list[int],
    held: list[Any],
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(jobs, "get_session_factory", lambda: session_factory)
    elsewhere = _job(db, "jlopez", status=ReportJobStatus.RUNNING, started_at=utc_now())
    two_hours = utc_now() - timedelta(hours=2)
    lost = _job(db, "cperez", created_at=two_hours, enqueued_at=two_hours)
    mine = _job(db, analyst.username)
    jobs.run_report_job(str(mine.id))
    for row in (elsewhere, mine):
        db.refresh(row)
    assert mine.status is ReportJobStatus.DONE and mine.finished_at is not None
    assert elsewhere.status is ReportJobStatus.RUNNING
    # The claim's sweep found the lost job, and the worker enqueued it again.
    assert held == [(lost.id, 0)]


def test_the_sweep_touches_only_what_each_rule_names(db: Session, analyst: User) -> None:
    settings = get_settings()
    long_ago = utc_now() - timedelta(hours=settings.report_job_retention_hours + 1)
    fresh = _job(db, analyst.username)
    two_hours = utc_now() - timedelta(hours=2)
    lost = _job(db, "jlopez", created_at=two_hours, enqueued_at=two_hours)
    old_error = _job(
        db, "cperez", status=ReportJobStatus.ERRORED, detail="render_failed", finished_at=long_ago
    )
    # A DONE job whose file is already gone must not crash the sweep.
    fileless = _job(db, "amedina", status=ReportJobStatus.DONE, finished_at=long_ago)
    before = fresh.enqueued_at
    jobs.sweep(db, settings)
    db.commit()
    for row in (fresh, lost, old_error, fileless):
        db.refresh(row)
    assert fresh.enqueued_at == before  # only the lost one is re-stamped
    assert lost.enqueued_at > two_hours
    assert old_error.status is ReportJobStatus.ERRORED and old_error.detail == "render_failed"
    assert fileless.status is ReportJobStatus.EXPIRED


def test_a_missing_artefact_is_said_and_recorded(
    client: TestClient, analyst: User, db: Session, fake_render: list[int]
) -> None:
    headers = login(client, analyst.username)
    analysis = seed_done_analysis(db, [make_finding(1)])
    job_id = _start(client, analysis.id, headers).json()["id"]
    jobs.artefact_path(get_settings(), uuid.UUID(job_id)).unlink()
    response = client.get(f"/api/v1/report-jobs/{job_id}/download", headers=headers)
    assert response.status_code == 409 and response.json()["code"] == "report_job_not_ready"
    row = db.get(ReportJob, uuid.UUID(job_id))
    assert row is not None
    db.refresh(row)
    assert row.status is ReportJobStatus.EXPIRED and row.detail == "artefact_missing"


def test_the_spool_is_created_private_and_the_cap_is_inclusive(
    client: TestClient,
    analyst: User,
    db: Session,
    fake_render: list[int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool = tmp_path / "not" / "yet" / "there"
    monkeypatch.setattr(get_settings(), "report_spool_dir", spool)
    # Exactly at the cap is allowed; only past it is refused.
    monkeypatch.setattr(get_settings(), "report_spool_max_bytes", max(len(FAKE_PDF), 1024 * 1024))
    filler_size = get_settings().report_spool_max_bytes - len(FAKE_PDF)
    spool.mkdir(parents=True, mode=0o700)
    (spool / "filler").write_bytes(b"x" * filler_size)
    target = tmp_path / "outside.bin"
    target.write_bytes(b"y" * 4096)
    (spool / "link").symlink_to(target)  # a link is not counted as spool content
    analysis = seed_done_analysis(db, [make_finding(1)])
    job = _start(client, analysis.id, login(client, analyst.username)).json()
    assert job["status"] == "done", job

    fresh = tmp_path / "fresh" / "spool"
    monkeypatch.setattr(get_settings(), "report_spool_dir", fresh)
    other = seed_done_analysis(db, [make_finding(1)])
    client.get(f"/api/v1/report-jobs/{job['id']}/download", headers=login(client, analyst.username))
    assert _start(client, other.id, login(client, analyst.username)).json()["status"] == "done"
    assert oct(fresh.stat().st_mode & 0o777) == "0o700"


def test_elapsed_time_stops_when_the_job_finishes() -> None:
    start = utc_now() - timedelta(minutes=2)
    finished = ReportJob(started_at=start, finished_at=start + timedelta(seconds=50))
    assert jobs.elapsed_seconds(finished) == 50
    instant = ReportJob(started_at=start, finished_at=start)
    assert jobs.elapsed_seconds(instant) == 0
    running = ReportJob(started_at=start)
    assert jobs.elapsed_seconds(running, now=start + timedelta(seconds=7)) == 7


def test_the_sweep_counts_every_stray_and_none_without_a_spool(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "report_spool_dir", tmp_path / "absent")
    assert jobs.sweep(db, settings).strays == 0
    spool = tmp_path / "spool"
    spool.mkdir()
    monkeypatch.setattr(settings, "report_spool_dir", spool)
    ancient = time.time() - 3 * 3600
    for _ in range(3):
        stray = spool / f"{uuid.uuid4()}.pdf"
        stray.write_bytes(b"x")
        os.utime(stray, (ancient, ancient))
    assert jobs.sweep(db, settings).strays == 3
    assert list(spool.iterdir()) == []


def test_the_spool_cap_adds_up_every_file(
    client: TestClient,
    analyst: User,
    db: Session,
    fake_render: list[int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cap = 1024 * 1024
    monkeypatch.setattr(get_settings(), "report_spool_max_bytes", cap)
    spool = _spool()
    spool.mkdir(parents=True, exist_ok=True)
    # Neither file alone reaches the cap; together, with the new PDF, they pass it.
    for _ in range(2):
        (spool / f"{uuid.uuid4()}.pdf").write_bytes(b"x" * (cap // 2 - 2))
    analysis = seed_done_analysis(db, [make_finding(1)])
    job = _start(client, analysis.id, login(client, analyst.username)).json()
    assert job["status"] == "errored" and job["detail"] == "spool_full"
