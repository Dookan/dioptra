"""Executors: where a runner spec actually runs.

``DockerExecutor`` is production: an ephemeral container with no network, a
read-only root, dropped capabilities, CPU/RAM/pids limits and exactly two bind
mounts (the audited tree read-only, the output directory writable). A tool
that needs the network is misconfigured, not an exception
(docs/analysis-pipeline.md).

``LocalExecutor`` runs the same argv on the host. It exists for development
machines and for the test suite; it applies the timeout but no other
isolation, which is why ``runner_mode`` defaults to ``docker``.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.analysis.models import ToolStatus
from app.analysis.runners.base import OUT_DIR, WORK_DIR, ExecutionResult, Executor, RunnerSpec
from app.core.config import Settings

# The container user is ``Settings.runner_user`` (10001:10001 as in the
# analysis image; the settings pattern refuses root).
STDERR_CAP = 64 * 1024
DETAIL_TAIL = 200


def _stderr_text(raw: bytes | None) -> str:
    if not raw:
        return ""
    return raw[-STDERR_CAP:].decode("utf-8", errors="replace")


def read_output(path: Path, cap: int) -> tuple[bytes | None, bool]:
    """Read the report file back, never more than ``cap`` bytes."""
    if not path.is_file():
        return None, False
    with path.open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        return data[:cap], True
    return data, False


def _finish(
    spec: RunnerSpec,
    *,
    exit_code: int | None,
    stderr: str,
    out_dir: Path,
    started: float,
    cap: int,
) -> ExecutionResult:
    """Classify a completed process: RAN when the exit code is normal AND the report exists."""
    duration_ms = int((time.monotonic() - started) * 1000)
    output, truncated = read_output(out_dir / spec.output_file, cap)
    if exit_code in spec.ok_exit_codes and output is not None:
        return ExecutionResult(
            status=ToolStatus.RAN,
            exit_code=exit_code,
            stderr=stderr,
            output=output,
            truncated=truncated,
            duration_ms=duration_ms,
            detail=None,
        )
    if output is None and exit_code in spec.ok_exit_codes:
        detail = f"exit {exit_code} but no report written ({spec.output_file})"
    else:
        tail = stderr.strip()[-DETAIL_TAIL:]
        detail = f"exit {exit_code}: {tail}" if tail else f"exit {exit_code}"
    return ExecutionResult(
        status=ToolStatus.FAILED,
        exit_code=exit_code,
        stderr=stderr,
        output=output,
        truncated=truncated,
        duration_ms=duration_ms,
        detail=detail[:500],
    )


@dataclass(frozen=True)
class ProcessOutcome:
    """What running one argv produced, before any tool-specific interpretation.

    ``status`` is already classified for the two cases that are not about the
    tool at all: it never started (MISSING) or it was killed (TIMEOUT).
    """

    status: ToolStatus | None
    exit_code: int | None
    stderr: str
    duration_ms: int
    detail: str | None


def run_argv(
    argv: list[str],
    *,
    cwd: Path | None,
    timeout_seconds: int,
    on_timeout: Callable[[], None] | None = None,
) -> ProcessOutcome:
    """Run ``argv`` with a timeout and a kill hook. Shared with the E7 sandbox.

    The E7 sandbox needs exactly this and a different result contract (three
    files instead of one), so the process handling lives here once rather than
    being written a second time (tasks/phase4-survey.md → Verdict).
    """
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 — argv is built from our own specs, never from input
            argv,
            cwd=cwd,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        if on_timeout is not None:
            on_timeout()
        return ProcessOutcome(
            status=ToolStatus.TIMEOUT,
            exit_code=None,
            stderr=_stderr_text(exc.stderr),
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=f"killed after {timeout_seconds}s",
        )
    except FileNotFoundError:
        return ProcessOutcome(
            status=ToolStatus.MISSING,
            exit_code=None,
            stderr="",
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=f"{argv[0]} not found",
        )
    return ProcessOutcome(
        status=None,
        exit_code=completed.returncode,
        stderr=_stderr_text(completed.stderr),
        duration_ms=int((time.monotonic() - started) * 1000),
        detail=None,
    )


def _run_process(
    spec: RunnerSpec,
    argv: list[str],
    *,
    cwd: Path | None,
    out_dir: Path,
    cap: int,
    on_timeout: Callable[[], None] | None = None,
) -> ExecutionResult:
    started = time.monotonic()
    # A report left by an earlier run (a retry, a sibling spec writing the same
    # name) must never be read back as this run's result.
    (out_dir / spec.output_file).unlink(missing_ok=True)
    outcome = run_argv(argv, cwd=cwd, timeout_seconds=spec.timeout_seconds, on_timeout=on_timeout)
    if outcome.status is not None:
        return ExecutionResult(
            status=outcome.status,
            exit_code=None,
            stderr=outcome.stderr,
            output=None,
            truncated=False,
            duration_ms=outcome.duration_ms,
            detail=outcome.detail,
        )
    return _finish(
        spec,
        exit_code=outcome.exit_code,
        stderr=outcome.stderr,
        out_dir=out_dir,
        started=started,
        cap=cap,
    )


class DockerExecutor:
    """One ephemeral container per tool run, no network, hard limits."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._container_name: str | None = None

    def command(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> list[str]:
        """The exact ``docker run`` argv. Exposed so tests can assert every flag."""
        settings = self._settings
        container_name = self._container_name or f"dioptra-{spec.tool}-{uuid.uuid4().hex[:12]}"
        argv = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            # cwd on the tmpfs, never the audited tree: tools that read a config
            # file from the working directory must not find a hostile one.
            "-w",
            "/tmp",  # noqa: S108 — the container's own tmpfs
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=256m",  # noqa: S108 — the container's own tmpfs, not a host path
            "--memory",
            settings.runner_memory,
            "--memory-swap",
            settings.runner_memory,  # equal to --memory: no swap at all
            "--cpus",
            settings.runner_cpus,
            "--pids-limit",
            str(settings.runner_pids_limit),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            settings.runner_user,
            "-v",
            f"{workspace}:{WORK_DIR}:ro",
            "-v",
            f"{out_dir}:{OUT_DIR}:rw",
        ]
        for host_path, container_path in spec.extra_ro_mounts:
            argv += ["-v", f"{host_path}:{container_path}:ro"]
        argv += ["-e", "HOME=/tmp", settings.analysis_image, *spec.argv]
        return argv

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        if shutil.which("docker") is None:
            return ExecutionResult(
                status=ToolStatus.MISSING,
                exit_code=None,
                stderr="",
                output=None,
                truncated=False,
                duration_ms=0,
                detail="docker binary not found on the worker",
            )
        # The timeout kills the docker CLIENT; the container would keep burning
        # CPU until the tool finishes on its own. Name it so it can be killed.
        self._container_name = f"dioptra-{spec.tool}-{uuid.uuid4().hex[:12]}"
        name = self._container_name
        argv = self.command(spec, workspace=workspace, out_dir=out_dir)
        self._container_name = None

        docker = shutil.which("docker") or "docker"

        def kill_container() -> None:
            subprocess.run(  # noqa: S603 — fixed argv, our own container name
                [docker, "kill", name], capture_output=True, check=False, timeout=30
            )

        return _run_process(
            spec,
            argv,
            cwd=None,
            out_dir=out_dir,
            cap=self._settings.max_tool_output_bytes,
            on_timeout=kill_container,
        )


class LocalExecutor:
    """Same argv on the host: ``/work`` and ``/out`` are rewritten to real paths."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @staticmethod
    def translate(spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> list[str]:
        """Rewrite the container path conventions and mount targets for the host."""
        replacements = [(WORK_DIR, str(workspace)), (OUT_DIR, str(out_dir))]
        replacements += [(target, str(source)) for source, target in spec.extra_ro_mounts]
        translated: list[str] = []
        for arg in spec.argv:
            value = arg
            for container_path, host_path in replacements:
                value = value.replace(container_path, host_path)
            translated.append(value)
        return translated

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        argv = self.translate(spec, workspace=workspace, out_dir=out_dir)
        if shutil.which(argv[0]) is None:
            return ExecutionResult(
                status=ToolStatus.MISSING,
                exit_code=None,
                stderr="",
                output=None,
                truncated=False,
                duration_ms=0,
                detail=f"{argv[0]} not found on PATH",
            )
        return _run_process(
            spec, argv, cwd=workspace, out_dir=out_dir, cap=self._settings.max_tool_output_bytes
        )


def build_executor(settings: Settings) -> Executor:
    """Pick the executor the deployment asked for."""
    if settings.runner_mode == "docker":
        return DockerExecutor(settings)
    return LocalExecutor(settings)
