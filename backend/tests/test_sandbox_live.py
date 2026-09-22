"""The E7 sandbox, for real: containers start, tests run, escapes are attempted.

Marked ``sandbox`` and skipped where Docker or ``dioptra-sandbox:latest`` is
absent. These are the only tests in the suite that need either, and they are
what the plan's release blocker is about: "a positive escape test means no
release" (CLAUDE.md → Release rules).

The escape probes run with the EXACT argv the executor ships, with only the
command swapped, so what is proven here is the flag set in production.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from app.analysis.models import Analysis
from app.core.config import Settings, get_settings
from app.sandbox import executor, results, workspace
from app.sandbox.errors import SandboxTimedOut
from app.workflow.scaffold import ScaffoldCase, ScaffoldFile

pytestmark = pytest.mark.sandbox

MODULE = """def obtener_edad(anio):
    if anio <= 0:
        raise ValueError("anio")
    edad = 2026 - anio
    if edad >= 18:
        return "mayor"
    return "menor"
"""

THOROUGH = """from edad import obtener_edad

import pytest


def test_c1_mayor():
    assert obtener_edad(2000) == "mayor"


def test_c2_menor():
    assert obtener_edad(2020) == "menor"


def test_c3_borde():
    assert obtener_edad(2008) == "mayor"
    assert obtener_edad(2009) == "menor"


def test_c4_malicioso():
    with pytest.raises(ValueError):
        obtener_edad(0)
    with pytest.raises(ValueError):
        obtener_edad(-1)
"""

WEAK = """from edad import obtener_edad


def test_c1_mayor():
    assert obtener_edad(2000) == "mayor"
"""


def _scaffold() -> ScaffoldFile:
    return ScaffoldFile(
        filename="test_edad_obtener_edad_abc123_dioptra.py",
        language="python",
        runner="pytest",
        import_specifier="edad",
        content="",
        cases=[
            ScaffoldCase(id=f"C{i}", name=f"test_c{i}_x", title="x", covers=[]) for i in range(1, 5)
        ],
    )


@pytest.fixture
def live(sandbox_available: bool, tmp_path: Path) -> Settings:
    if not sandbox_available:
        pytest.skip("Docker or dioptra-sandbox:latest is not available here")
    # The container writes into the attempt directory, which this process
    # created: the uid has to match, exactly as the deployment note on
    # `runner_user` says (the shipped images run as 10001).
    return get_settings().model_copy(
        update={
            "sandbox_runs_root": tmp_path / "runs",
            "runner_user": f"{os.getuid()}:{os.getgid()}",
        }
    )


def _attempt(settings: Settings, tmp_path: Path, content: str) -> workspace.Attempt:
    jail = tmp_path / "jail"
    jail.mkdir(exist_ok=True)
    (jail / "edad.py").write_text(MODULE)
    analysis = Analysis(workspace_path=str(jail))
    return workspace.build_attempt(
        settings,
        analysis=analysis,
        scaffold=_scaffold(),
        source_path="edad.py",
        test_content=content,
    )


def test_a_thorough_suite_runs_green_with_full_coverage(live: Settings, tmp_path: Path) -> None:
    attempt = _attempt(live, tmp_path, THOROUGH)
    try:
        result = executor.run(live, attempt)
        # A container that wrote NOTHING would satisfy every assertion below:
        # `EMPTY_COVERAGE` is 100 % by the "no measurable line" branch. Require
        # real output first, or this test certifies the sandbox works while
        # proving it never ran.
        assert result.coverage is not None and result.junit is not None
        coverage = results.parse_coverage(
            result.coverage, language="python", module_file=attempt.module_file
        )
        assert coverage.executed_lines, "no line was recorded as executed"
        assert results.parse_failed_cases(result.junit) == []
        assert coverage.missing_lines == frozenset()
        assert coverage.partial_branch_lines == frozenset()
        assert coverage.statement_percent == 100.0
        assert coverage.total_branches > 0
    finally:
        workspace.discard(attempt)


def test_a_weak_suite_leaves_surviving_mutants(live: Settings, tmp_path: Path) -> None:
    """The plan's release criterion, on a real run: a survivor is visible and named."""
    attempt = _attempt(live, tmp_path, WEAK)
    try:
        result = executor.run(live, attempt)
        mutation = results.parse_mutation(result.mutation)
        coverage = results.parse_coverage(
            result.coverage, language="python", module_file=attempt.module_file
        )
        assert mutation.tool == "mutmut"
        assert mutation.survived, "a one-assertion suite must leave mutants alive"
        assert coverage.missing_lines, "the raise path is never executed by this suite"
    finally:
        workspace.discard(attempt)


def _probe(settings: Settings, tmp_path: Path, script: str) -> subprocess.CompletedProcess[bytes]:
    """Run ``script`` with the EXACT flags the executor ships, command swapped.

    Note what IS swapped besides the command: `--user`, because the `live`
    fixture sets it to this process's uid so the container can write the
    attempt directory this process created. Both values are non-root.
    """
    attempt = _attempt(settings, tmp_path, WEAK)
    name = "dioptra-escape-probe"
    argv = executor.command(settings, attempt, container_name=name)
    argv = argv[: argv.index(settings.sandbox_image) + 1] + ["sh", "-c", script]
    try:
        return subprocess.run(  # noqa: S603 — our own argv
            argv, capture_output=True, timeout=180, check=False
        )
    finally:
        # A probe that hangs would otherwise leave a container running: the
        # subprocess timeout kills the docker CLIENT, never the container.
        docker = shutil.which("docker") or "docker"
        subprocess.run(  # noqa: S603 — fixed argv, our own container name
            [docker, "kill", name], capture_output=True, check=False, timeout=60
        )
        workspace.discard(attempt)


ESCAPES: list[tuple[str, str]] = [
    # (name, shell probe that must NOT succeed)
    #
    # Every probe here has been checked to fail FOR ITS STATED REASON: removing
    # the flag it targets makes it succeed. Three earlier probes did not, and
    # passed for free — `capsh` is not installed in the image, `mount -t proc`
    # is refused even when privileged because /proc is already mounted, and a
    # fork bomb written with literal backslash-n died of a SyntaxError before
    # forking anything. A negative control that cannot go positive is not
    # evidence (docs/threat-model.md → Sandbox escape tests).
    (
        "outbound network",
        "python3 -c \"import socket;socket.create_connection(('1.1.1.1',53),3)\"",
    ),
    ("write outside the workspace", "touch /etc/dioptra-pwned"),
    ("write to the image's own tree", "touch /usr/local/bin/dioptra-pwned"),
    ("write to /proc", "echo 1 > /proc/sys/kernel/core_uses_pid"),
    ("read the docker socket", "test -S /var/run/docker.sock"),
    (
        "gain capabilities",
        # `capsh` is absent on purpose; the capability sets are read straight
        # off the kernel. Every set must be empty, so any non-zero digit fails.
        "grep -E '^Cap(Prm|Eff|Bnd):' /proc/self/status | grep -qv '0000000000000000'",
    ),
    ("keep the right to gain privileges", "grep -q 'NoNewPrivs:\t0' /proc/self/status"),
    ("become root", 'python3 -c "import os;os.setuid(0)"'),
    ("mount a filesystem", "mount -t tmpfs tmpfs /mnt && test -w /mnt"),
]


@pytest.mark.parametrize(("name", "script"), ESCAPES, ids=[name for name, _ in ESCAPES])
def test_the_sandbox_refuses_every_escape(
    live: Settings, tmp_path: Path, name: str, script: str
) -> None:
    probe = _probe(live, tmp_path, script)
    assert probe.returncode != 0, f"{name} SUCCEEDED: {probe.stdout!r} {probe.stderr!r}"


# Written as a file the shell heredocs in. The first version of this probe was
# an inline `python3 -c "…\\n…"`, whose literal backslash-n made Python die of a
# SyntaxError before forking anything — the assertion passed for the wrong
# reason. Exit 7 is the probe's OWN OSError branch, so it can only happen when
# a fork was actually refused: a missing binary or a syntax error gives 1 or 2.
FORK_BOMB = """cat > /tmp/bomb.py <<'EOF'
import os

n = 0
try:
    while n < 5000:
        os.fork()
        n += 1
except OSError:
    raise SystemExit(7)
raise SystemExit(0)
EOF
python3 /tmp/bomb.py"""

MEMORY_BALLOON = """cat > /tmp/balloon.py <<'EOF'
chunks = []
while True:
    chunks.append(bytearray(64 * 1024 * 1024))
EOF
python3 /tmp/balloon.py
"""

#: A "test" that never returns. It is the developer's file, so it goes through
#: the ordinary entrypoint rather than a command swap.
SPINNING_TEST = """def test_c1_spin():
    while True:
        pass
"""


def test_a_fork_bomb_is_refused_by_the_pids_limit(live: Settings, tmp_path: Path) -> None:
    """Exit 7 is the probe's own OSError branch: a fork was refused."""
    probe = _probe(live, tmp_path, FORK_BOMB)
    assert probe.returncode == 7, (probe.returncode, probe.stdout, probe.stderr)


def test_a_memory_balloon_is_killed_by_the_memory_limit(live: Settings, tmp_path: Path) -> None:
    """The allocator gives up or the kernel kills it; either way it does not win."""
    probe = _probe(live, tmp_path, MEMORY_BALLOON)
    assert probe.returncode != 0, (probe.returncode, probe.stdout, probe.stderr)


def test_a_cpu_spin_is_killed_with_its_container(live: Settings, tmp_path: Path) -> None:
    """An endless loop must not outlive its attempt.

    This goes through `executor.run`, not a bare `subprocess.run`, on purpose:
    the timeout kills the docker CLIENT, and the container would keep burning
    a core until the loop ended on its own. Verified — a raw invocation of the
    same script was still spinning two minutes later. What stops it is the
    named container and the `docker kill` hook, so that is what is tested.
    """
    quick = live.model_copy(update={"sandbox_timeout_seconds": 15})
    attempt = _attempt(quick, tmp_path, WEAK)
    (attempt.run_dir / attempt.test_file).write_text(SPINNING_TEST)
    started = time.monotonic()
    try:
        with pytest.raises(SandboxTimedOut):
            executor.run(quick, attempt)
    finally:
        workspace.discard(attempt)
    elapsed = time.monotonic() - started
    assert elapsed < 90, f"the attempt took {elapsed:.0f}s to come back"

    # And no container the executor started is left running. Filtered by the
    # executor's own name prefix rather than by image: the suite is
    # sequential, and `docker rm` finishes a moment after the kill returns.
    docker = shutil.which("docker") or "docker"
    running = subprocess.CompletedProcess([""], 0, "", "")
    for _ in range(20):
        running = subprocess.run(  # noqa: S603 — fixed argv, resolved binary
            [docker, "ps", "--filter", "name=dioptra-sandbox-", "--quiet"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if running.stdout.strip() == "":
            break
        time.sleep(0.5)
    assert running.stdout.strip() == "", "the spinning container outlived its attempt"


def test_only_the_declared_files_are_read_back(live: Settings, tmp_path: Path) -> None:
    """A test can write anything into the attempt directory; we read three names."""
    attempt = _attempt(live, tmp_path, WEAK)
    try:
        secret = "dioptra-exfiltration-canary-8f3a"
        (attempt.run_dir / "secret-exfiltration.json").write_text(json.dumps({"a": secret}))
        result = executor.run(live, attempt)
        assert result.coverage is not None
        # The canary is in the attempt directory but in none of the three files
        # we read back, and in nothing else that leaves the container.
        blobs: list[bytes | None] = [result.coverage, result.junit, result.mutation]
        for blob in blobs:
            assert blob is None or secret.encode() not in blob
        assert secret not in result.stderr
    finally:
        workspace.discard(attempt)


def test_the_run_directory_is_gone_afterwards(live: Settings, tmp_path: Path) -> None:
    attempt = _attempt(live, tmp_path, WEAK)
    executor.run(live, attempt)
    workspace.discard(attempt)
    if shutil.which("docker") is not None:
        assert not attempt.run_dir.exists()
