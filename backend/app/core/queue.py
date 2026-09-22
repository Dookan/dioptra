"""Job queue boundary.

The API never runs a tool itself: it enqueues ``run_pipeline`` and the worker
service picks it up. ``DIOPTRA_QUEUE_INLINE=true`` collapses that into a direct
call for the test suite and single-process development.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import Any

from rq.job import Job

from app.core.config import get_settings

logger = logging.getLogger("dioptra.queue")

PIPELINE_JOB = "app.analysis.pipeline.run_pipeline"
VERIFY_JOB = "app.workflow.verify_job.run_verification_job"
#: The ONLY callables the worker may execute. Adding one here is a security
#: decision: the worker is the process holding the Docker socket.
ALLOWED_JOBS = frozenset({PIPELINE_JOB, VERIFY_JOB})
QUEUE_NAME = "analysis"


class PipelineJob(Job):
    """The only jobs the worker executes (``ALLOWED_JOBS``).

    RQ resolves a job's callable from a dotted path stored in the broker, so
    anything able to write to Valkey could otherwise make the worker — the one
    process holding the Docker socket — import and call an arbitrary function.
    The worker is started with ``--job-class app.core.queue.PipelineJob`` and
    ``--serializer json`` (no pickle); this class refuses every other callable.
    """

    @property
    def func(self) -> Callable[..., Any]:
        if self.func_name not in ALLOWED_JOBS:
            allowed = ", ".join(sorted(ALLOWED_JOBS))
            message = f"refusing job {self.func_name!r}: only {allowed} may run here"
            raise PermissionError(message)
        parent: Callable[..., Any] = super().func
        return parent

    # RQ also resolves callbacks and webhooks from hash fields any broker
    # writer can set; the platform enqueues none, so none may ever run.
    @property
    def success_callback(self) -> None:
        return None

    @property
    def failure_callback(self) -> None:
        return None

    @property
    def stopped_callback(self) -> None:
        return None

    def send_webhooks(self, status: Any, *, exc_string: str | None = None) -> None:
        """No outbound request ever leaves the worker on a broker's say-so."""
        del status, exc_string


def enqueue_pipeline(analysis_id: uuid.UUID) -> None:
    """Schedule the pipeline for one analysis. The row MUST be committed already."""
    settings = get_settings()
    if settings.queue_inline:
        from app.analysis.pipeline import run_pipeline

        run_pipeline(analysis_id)
        return

    from redis import Redis
    from rq import Queue
    from rq.serializers import JSONSerializer

    connection = Redis.from_url(settings.redis_url)
    # JSON: the payload is one UUID string; pickle would let a broker write
    # execute code on deserialization, before the job class even looks at it.
    queue = Queue(
        QUEUE_NAME, connection=connection, serializer=JSONSerializer, job_class=PipelineJob
    )
    # One pipeline runs every tool sequentially, each with its own timeout;
    # the job timeout is the sum plus slack so RQ never kills a healthy run.
    job_timeout = settings.runner_timeout_seconds * 8 + settings.git_clone_timeout_seconds
    queue.enqueue(PIPELINE_JOB, str(analysis_id), job_timeout=job_timeout, result_ttl=0)
    logger.info("enqueued analysis=%s", analysis_id)


def enqueue_verification(analysis_id: uuid.UUID, actor_username: str) -> None:
    """Schedule the E7 run for one analysis. The rows MUST be committed already.

    Like the pipeline, this starts containers, so it never happens inside a
    request handler (tasks/phase4-survey.md §4).
    """
    settings = get_settings()
    if settings.queue_inline:
        from app.workflow.verify_job import run_verification_job

        run_verification_job(str(analysis_id), actor_username)
        return

    from redis import Redis
    from rq import Queue
    from rq.serializers import JSONSerializer

    connection = Redis.from_url(settings.redis_url)
    queue = Queue(
        QUEUE_NAME, connection=connection, serializer=JSONSerializer, job_class=PipelineJob
    )
    # One attempt per planned function, each bounded by the sandbox timeout.
    job_timeout = settings.sandbox_timeout_seconds * 32
    queue.enqueue(
        VERIFY_JOB, str(analysis_id), actor_username, job_timeout=job_timeout, result_ttl=0
    )
    logger.info("enqueued verification analysis=%s", analysis_id)
