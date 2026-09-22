"""The worker executes exactly one callable, whatever the broker says."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core.queue import PIPELINE_JOB, PipelineJob


def _job(func_name: str) -> PipelineJob:
    job = PipelineJob(id="job-1", connection=MagicMock())
    job._func_name = func_name  # noqa: SLF001 — what a hostile broker write would set
    return job


def test_only_the_pipeline_callable_resolves() -> None:
    assert _job(PIPELINE_JOB).func.__name__ == "run_pipeline"


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
