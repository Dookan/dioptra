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


def _probe(
    settings: Settings,
    tmp_path: Path,
    script: str,
    *,
    attempt: workspace.Attempt | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run ``script`` with the EXACT flags the executor ships, command swapped.

    Note what IS swapped besides the command: `--user`, because the `live`
    fixture sets it to this process's uid so the container can write the
    attempt directory this process created. Both values are non-root.

    ``attempt`` chooses the IMAGE, because the executor picks it from the
    attempt's runner — pass a PHP attempt to probe the PHP image.
    """
    attempt = attempt if attempt is not None else _attempt(settings, tmp_path, WEAK)
    name = "dioptra-escape-probe"
    argv = executor.command(settings, attempt, container_name=name)
    # Which image, from the SAME selector production uses — one image per
    # language since phase 7a, chosen by the scaffold's runner.
    image = executor.image_for(settings, attempt.runner)
    argv = argv[: argv.index(image) + 1] + ["sh", "-c", script]
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


# --------------------------------------------------------------------------
# PHP (phase 7a): a SECOND image, and therefore a second escape suite.
#
# The flags are shared by construction — `executor.command` is one function and
# only the image string differs — but P4's lesson is that a negative control
# which cannot go positive is not evidence, so every probe is re-run HERE and
# each one is expressed in something this image actually has.
#
# What this image does NOT have, measured 2026-09-23: no `python3` (four of the
# wave-1 probes use it and would have failed for the wrong reason), no `pcntl`
# (so `pcntl_fork` cannot be the fork bomb), no `sockets` extension. What it
# does have: `php` with `posix`, stream functions (`fsockopen`), and `perl`
# from the Debian base — which is what forks here.
# --------------------------------------------------------------------------

PHP_MODULE = """<?php

class Edad
{
    public static function obtener(int $anio): string
    {
        if ($anio <= 0) {
            throw new InvalidArgumentException('anio');
        }
        $edad = 2026 - $anio;
        if ($edad >= 18) {
            return 'mayor';
        }
        return 'menor';
    }
}
"""

PHP_WEAK = """<?php

declare(strict_types=1);

use PHPUnit\\Framework\\TestCase;

require_once __DIR__ . '/' . 'Edad.php';

final class EdadDioptraTest extends TestCase
{
    public function testC1_mayor(): void
    {
        $this->assertSame('mayor', Edad::obtener(2000));
    }
}
"""


def _php_scaffold() -> ScaffoldFile:
    return ScaffoldFile(
        filename="EdadDioptraTest.php",
        language="php",
        runner="phpunit",
        import_specifier="Edad.php",
        content="",
        cases=[ScaffoldCase(id="C1", name="testC1_mayor", title="mayor", covers=[])],
    )


def _php_attempt(settings: Settings, tmp_path: Path, content: str) -> workspace.Attempt:
    jail = tmp_path / "phpjail"
    jail.mkdir(exist_ok=True)
    (jail / "Edad.php").write_text(PHP_MODULE)
    analysis = Analysis(workspace_path=str(jail))
    return workspace.build_attempt(
        settings,
        analysis=analysis,
        scaffold=_php_scaffold(),
        source_path="Edad.php",
        test_content=content,
    )


@pytest.fixture
def php_live(php_sandbox_available: bool, tmp_path: Path) -> Settings:
    if not php_sandbox_available:
        pytest.skip("Docker or dioptra-sandbox-php:latest is not available here")
    return get_settings().model_copy(
        update={
            "sandbox_runs_root": tmp_path / "runs",
            "runner_user": f"{os.getuid()}:{os.getgid()}",
        }
    )


#: `memory_limit` is 512M in this image's php.ini, so a balloon would hit PHP's
#: own limit instead of the container's `--memory` — and pass for the wrong
#: reason. Lifting it first is what makes the probe attributable.
PHP_BALLOON = (
    'php -r \'ini_set("memory_limit", -1); $c = []; while (true) { '
    '$c[] = str_repeat("x", 64 * 1024 * 1024); }\''
)

#: No `pcntl` here, so the fork comes from perl (Debian base). Exit 7 is the
#: probe's OWN refused-fork branch, exactly as the Python version's is: a
#: missing binary or a syntax error gives a different code.
PHP_FORK_BOMB = """cat > /tmp/bomb.pl <<'EOF'
my $n = 0;
while ($n < 5000) {
    my $pid = fork();
    exit(7) unless defined $pid;
    $n++;
}
exit(0);
EOF
perl /tmp/bomb.pl"""

PHP_ESCAPES: list[tuple[str, str]] = [
    # Shell-only probes: identical to wave 1, and every binary they use exists
    # in this image (checked).
    ("write outside the workspace", "touch /etc/dioptra-pwned"),
    ("write to the image's own tree", "touch /usr/local/bin/dioptra-pwned"),
    ("write to /proc", "echo 1 > /proc/sys/kernel/core_uses_pid"),
    ("read the docker socket", "test -S /var/run/docker.sock"),
    (
        "gain capabilities",
        "grep -E '^Cap(Prm|Eff|Bnd):' /proc/self/status | grep -qv '0000000000000000'",
    ),
    ("keep the right to gain privileges", "grep -q 'NoNewPrivs:\t0' /proc/self/status"),
    ("mount a filesystem", "mount -t tmpfs tmpfs /mnt && test -w /mnt"),
    # Re-expressed for this image: PHP where wave 1 used python3.
    (
        "outbound network",
        "php -r '$e=null;$m=null;exit(@fsockopen(\"1.1.1.1\", 53, $e, $m, 3) ? 0 : 1);'",
    ),
    ("become root", "php -r 'exit(@posix_setuid(0) ? 0 : 1);'"),
]


@pytest.mark.parametrize(("name", "script"), PHP_ESCAPES, ids=[name for name, _ in PHP_ESCAPES])
def test_the_php_sandbox_refuses_every_escape(
    php_live: Settings, tmp_path: Path, name: str, script: str
) -> None:
    attempt = _php_attempt(php_live, tmp_path, PHP_WEAK)
    try:
        probe = _probe(php_live, tmp_path, script, attempt=attempt)
    finally:
        workspace.discard(attempt)
    assert probe.returncode != 0, f"{name} SUCCEEDED: {probe.stdout!r} {probe.stderr!r}"


def test_the_php_sandbox_refuses_a_fork_bomb(php_live: Settings, tmp_path: Path) -> None:
    """Exit 7 is the probe's own refused-fork branch — proof a fork WAS refused."""
    attempt = _php_attempt(php_live, tmp_path, PHP_WEAK)
    try:
        probe = _probe(php_live, tmp_path, PHP_FORK_BOMB, attempt=attempt)
    finally:
        workspace.discard(attempt)
    assert probe.returncode == 7, f"no fork was refused: {probe.returncode} {probe.stderr!r}"


def test_the_php_sandbox_kills_a_memory_balloon(php_live: Settings, tmp_path: Path) -> None:
    attempt = _php_attempt(php_live, tmp_path, PHP_WEAK)
    try:
        probe = _probe(php_live, tmp_path, PHP_BALLOON, attempt=attempt)
    finally:
        workspace.discard(attempt)
    assert probe.returncode != 0, "the balloon was never stopped"


def test_a_weak_php_suite_leaves_surviving_mutants(php_live: Settings, tmp_path: Path) -> None:
    """The phase's own acceptance: a surviving mutant must be able to reject the gate.

    One assertion over one path, so Infection has plenty to escape with. This
    is the PHP half of `test_a_weak_suite_leaves_surviving_mutants`; what it
    guards is the wiring, because three separate defects in this chain each
    produced "no survivors" from a suite that proves nothing — a duplicated
    `--configuration`, an invalid `pathCoverage` attribute, and a missing
    bootstrap that made every mutant die in PHPUnit's own startup and count as
    killed (tasks/phase7a-php.md).
    """
    attempt = _php_attempt(php_live, tmp_path, PHP_WEAK)
    try:
        result = executor.run(php_live, attempt)
        assert not result.missing, f"the run produced nothing to score: {result.missing}"
        mutation = results.parse_mutation(result.mutation)
        coverage = results.parse_coverage(
            result.coverage, language="php", module_file=attempt.module_file
        )
        assert mutation.tool == "infection"
        assert mutation.total, "zero mutants is not a measurement (verify.py refuses it)"
        assert mutation.survived, "a one-assertion suite must leave mutants alive"
        assert coverage.total_branches, "branch coverage is what the E4 criterion needs"
        assert coverage.partial_branch_lines, "this suite takes one side of each branch"
    finally:
        workspace.discard(attempt)
