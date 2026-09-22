"""Running one verification attempt inside the sandbox container.

This is the P1 analysis executor's discipline with three deliberate changes,
each of them the reason the E7 sandbox is a different container and not just
another tool run (tasks/phase4-survey.md §2):

- the attempt directory is mounted READ-WRITE, and it is the ONLY writable
  mount; the audited jail is not mounted at all, because everything the test
  needs was copied in;
- the limits are tighter and the timeout shorter — a test that needs two
  minutes is a test that is not going to pass;
- three declared result files come back instead of one, each capped and parsed
  as data.

Everything else — no network, read-only root, all capabilities dropped,
no-new-privileges, a non-root user, and a NAMED container so the timeout can
kill the container rather than just the docker client — is unchanged, and must
stay that way: the audited code executing in here is the thing the whole
threat model is about.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass

from app.analysis.models import ToolStatus
from app.analysis.runners.executor import read_output, run_argv
from app.core.config import Settings
from app.sandbox.errors import SandboxTimedOut, SandboxUnavailable
from app.sandbox.workspace import (
    COVERAGE_FILE,
    JUNIT_FILE,
    MUTATION_FILE,
    RUN_DIR,
    Attempt,
)

#: The wrapper each runner is invoked through. It lives in the IMAGE, not in
#: the attempt directory, so the audited tree can never replace it.
ENTRYPOINTS = {"pytest": "dioptra-run-python", "vitest": "dioptra-run-js"}


@dataclass(frozen=True)
class SandboxResult:
    """The raw bytes of the declared result files, plus how the process ended.

    ``None`` means the file was NOT WRITTEN, which is never the same as "the
    run measured nothing": an empty coverage document reads as 100 %, an
    absent JUnit as "no test failed" and an absent mutation document as "no
    mutant survived". `verify.verify_function` refuses to score that.
    """

    exit_code: int | None
    stderr: str
    duration_ms: int
    coverage: bytes | None
    junit: bytes | None
    mutation: bytes | None

    @property
    def missing(self) -> list[str]:
        """Declared files the container did not produce."""
        return [
            name
            for name, blob in (
                (COVERAGE_FILE, self.coverage),
                (JUNIT_FILE, self.junit),
                (MUTATION_FILE, self.mutation),
            )
            if blob is None
        ]


def command(settings: Settings, attempt: Attempt, *, container_name: str) -> list[str]:
    """The exact ``docker run`` argv. Exposed so the tests can assert every flag."""
    entrypoint = ENTRYPOINTS[attempt.runner]
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        # The runners exec from /tmp, so it cannot be noexec; it is sized and
        # thrown away with the container.
        "--tmpfs",
        "/tmp:rw,size=256m",  # noqa: S108 — the container's own tmpfs, not a host path
        "--memory",
        settings.sandbox_memory,
        "--memory-swap",
        settings.sandbox_memory,  # equal to --memory: no swap at all
        "--cpus",
        settings.sandbox_cpus,
        "--pids-limit",
        str(settings.sandbox_pids_limit),
        # Bounds any SINGLE file the sandbox writes, including into the one
        # writable mount. The filesystem behind that mount is the operator's
        # to size; this holds even when they did not.
        "--ulimit",
        f"fsize={settings.sandbox_max_file_bytes}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        settings.runner_user,
        # The ONE writable mount, and the only thing of the host in here.
        "-v",
        f"{attempt.run_dir}:{RUN_DIR}:rw",
        "-w",
        RUN_DIR,
        "-e",
        "HOME=/tmp",  # noqa: S108 — the container's own tmpfs
        "-e",
        f"DIOPTRA_OUT={RUN_DIR}",
        settings.sandbox_image,
        entrypoint,
        attempt.test_file,
        attempt.module_file,
    ]


def run(settings: Settings, attempt: Attempt) -> SandboxResult:
    """Execute the attempt and read back only the declared files."""
    if shutil.which("docker") is None:
        raise SandboxUnavailable("docker binary not found on the worker")
    name = f"dioptra-sandbox-{uuid.uuid4().hex[:12]}"
    docker = shutil.which("docker") or "docker"

    def kill_container() -> None:
        subprocess.run(  # noqa: S603 — fixed argv, our own container name
            [docker, "kill", name], capture_output=True, check=False, timeout=30
        )

    outcome = run_argv(
        command(settings, attempt, container_name=name),
        cwd=None,
        timeout_seconds=settings.sandbox_timeout_seconds,
        on_timeout=kill_container,
    )
    if outcome.status is ToolStatus.TIMEOUT:
        raise SandboxTimedOut(outcome.detail or "timeout")
    if outcome.status is ToolStatus.MISSING:
        raise SandboxUnavailable(outcome.detail or "sandbox image unavailable")

    cap = settings.max_sandbox_result_bytes
    coverage, _ = read_output(attempt.run_dir / COVERAGE_FILE, cap)
    junit, _ = read_output(attempt.run_dir / JUNIT_FILE, cap)
    mutation, _ = read_output(attempt.run_dir / MUTATION_FILE, cap)
    return SandboxResult(
        exit_code=outcome.exit_code,
        stderr=outcome.stderr,
        duration_ms=outcome.duration_ms,
        coverage=coverage,
        junit=junit,
        mutation=mutation,
    )
