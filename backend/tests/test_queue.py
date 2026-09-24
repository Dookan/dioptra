"""The worker executes exactly one callable, whatever the broker says."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core.queue import (
    IMPORT_JOB,
    PIPELINE_JOB,
    REPORT_JOB,
    SYNC_JOB,
    VERIFY_JOB,
    PipelineJob,
    ReportWorkerJob,
)


def _job(func_name: str, job_class: type[PipelineJob] = PipelineJob) -> PipelineJob:
    job = job_class(id="job-1", connection=MagicMock())
    job._func_name = func_name  # noqa: SLF001 — what a hostile broker write would set
    return job


def test_only_the_pipeline_callable_resolves() -> None:
    assert _job(PIPELINE_JOB).func.__name__ == "run_pipeline"
    assert _job(VERIFY_JOB).func.__name__ == "run_verification_job"
    # P5: the mirror's sync and import are the only other callables — a
    # reverted allowlist would make the scheduled chain die with PermissionError.
    assert _job(SYNC_JOB).func.__name__ == "run_sync_job"
    assert _job(IMPORT_JOB).func.__name__ == "run_import_job"


def test_callbacks_and_webhooks_from_the_broker_are_ignored() -> None:
    job = _job(PIPELINE_JOB)
    job._success_callback_name = "os.system"  # noqa: SLF001
    job._failure_callback_name = "os.system"  # noqa: SLF001
    job._stopped_callback_name = "os.system"  # noqa: SLF001
    sent: list[str] = []

    class _Hook:
        job_status = "finished"

        def send(self, *_args: object, **_kwargs: object) -> None:
            sent.append("sent")

    job.webhooks = [_Hook()]  # type: ignore[list-item]  # what a hostile hash would restore
    assert job.success_callback is None
    assert job.failure_callback is None
    assert job.stopped_callback is None
    job.send_webhooks("finished")
    assert sent == []


@pytest.mark.parametrize("name", ["subprocess.Popen", "os.system", "app.seed.seed", ""])
def test_any_other_callable_is_refused(name: str) -> None:
    with pytest.raises(PermissionError):
        _ = _job(name).func


def test_the_socket_holding_worker_refuses_the_pdf_render() -> None:
    """Phase 8: WeasyPrint shapes hostile text in native code; never beside the socket."""
    with pytest.raises(PermissionError):
        _ = _job(REPORT_JOB).func


def test_the_report_worker_runs_the_pdf_render_and_nothing_else() -> None:
    assert _job(REPORT_JOB, ReportWorkerJob).func.__name__ == "run_report_job"
    for name in (PIPELINE_JOB, VERIFY_JOB, SYNC_JOB, IMPORT_JOB, "os.system"):
        with pytest.raises(PermissionError):
            _ = _job(name, ReportWorkerJob).func
    # Same broker hygiene as the pipeline worker: it inherits the refusals.
    job = _job(REPORT_JOB, ReportWorkerJob)
    job._success_callback_name = "os.system"  # noqa: SLF001
    assert job.success_callback is None


def test_the_pdf_job_goes_to_its_own_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    import uuid

    from app.core import queue
    from app.core.config import get_settings

    seen: list[tuple[str, type[object]]] = []

    class _Queue:
        def enqueue(self, *_args: object, **_kwargs: object) -> None:
            return None

    def fake_queue(name: str = queue.QUEUE_NAME, job_class: type[object] = PipelineJob) -> _Queue:
        seen.append((name, job_class))
        return _Queue()

    monkeypatch.setattr(get_settings(), "queue_inline", False)
    monkeypatch.setattr(queue, "_queue", fake_queue)
    queue.enqueue_report(uuid.uuid4())
    assert seen == [("reports", ReportWorkerJob)]
