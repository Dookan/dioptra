"""A subprocess that a person can stop, not only a clock (phase 12).

``subprocess.run(timeout=…)`` blocks the worker until the tool ends: a cancel
checked between pipeline steps could wait the whole of a 381 s Semgrep run.
Here the process is waited on in short slices, and between slices a
``should_stop`` predicate is asked; when it answers yes the process is killed
and the caller is told it was STOPPED, which is not a timeout and not a
failure (`tasks/phase12-survey.md` §1, §3.3).

The process starts in its own session and the kill reaches the whole group:
killing ``git`` alone leaves ``git-remote-https`` writing into a clone the
caller is about to remove (survey §9.3). An ``on_kill`` hook runs first — for
a container that is ``docker kill <name>``, because killing the docker CLIENT
does not stop the container — and says whether the kill is confirmed.

Callers that pass no ``should_stop`` keep using ``subprocess.run`` directly:
the E7 sandbox and every existing path are unchanged.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

#: How often the predicate is asked. A cancel takes effect within this plus
#: the kill; the predicate is one indexed read.
POLL_SECONDS = 2.0
#: Once killed, how long the process is given to exit and release its pipes.
DRAIN_SECONDS = 30.0

logger = logging.getLogger("dioptra.process")

StopCheck = Callable[[], bool]
KillHook = Callable[[], bool]


class Stopped(Exception):  # noqa: N818 — a control-flow signal, not an error
    """Raised by a stoppable step (the clone, the extraction) when asked to stop.

    Deliberately NOT an ``AppError``: it is never shown to anyone, and every
    ``except Exception`` cleanup on the way (the jail removed by
    ``archive.extract_zip``, the half clone) still runs. The pipeline turns it
    into a cancelled analysis.
    """


class Ending(StrEnum):
    EXITED = "exited"
    TIMED_OUT = "timed_out"
    STOPPED = "stopped"


@dataclass(frozen=True)
class Stoppable:
    ending: Ending
    returncode: int | None
    stdout: bytes
    stderr: bytes
    #: False only when a kill hook could not confirm the kill (a container
    #: that may still hold its mounts): the caller must not remove them.
    kill_confirmed: bool = True


def run_stoppable(
    argv: list[str],
    *,
    timeout_seconds: float,
    should_stop: StopCheck,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    on_kill: KillHook | None = None,
    poll_seconds: float = POLL_SECONDS,
) -> Stoppable:
    """Run ``argv`` until it exits, times out, or ``should_stop()`` says so."""
    process = subprocess.Popen(  # noqa: S603 — argv is built by our callers, never from input
        argv,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            try:
                stdout, stderr = process.communicate(timeout=max(0.0, min(poll_seconds, remaining)))
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    ending = Ending.TIMED_OUT
                elif _asks_to_stop(should_stop):
                    ending = Ending.STOPPED
                else:
                    continue
                confirmed = _kill(process, on_kill)
                stdout, stderr = _drain(process)
                return Stoppable(ending, None, stdout, stderr, kill_confirmed=confirmed)
            return Stoppable(Ending.EXITED, process.returncode, stdout, stderr)
    except BaseException:
        # Whatever interrupts the wait (RQ's job timeout, a KeyboardInterrupt,
        # a bug), the process group and its container must not outlive it:
        # this loop IS their timeout (security panel, phase 12).
        if process.poll() is None:
            _kill(process, on_kill)
            _drain(process)
        raise


def _asks_to_stop(should_stop: StopCheck) -> bool:
    """A predicate that fails (the database restarting) means "keep waiting".

    The deadline still bounds the run; an error here must never leave the
    process running unwatched.
    """
    try:
        return should_stop()
    except Exception:  # noqa: BLE001 — logged; the next slice asks again
        logger.warning("stop check failed; the process keeps its deadline", exc_info=True)
        return False


def _kill(process: subprocess.Popen[bytes], on_kill: KillHook | None) -> bool:
    confirmed = True
    if on_kill is not None:
        confirmed = on_kill()
    with contextlib.suppress(ProcessLookupError, PermissionError):  # the group is gone
        os.killpg(process.pid, signal.SIGKILL)
    return confirmed


def _drain(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    try:
        return process.communicate(timeout=DRAIN_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        return b"", b""
