"""Runner specs, executors and the own Semgrep rule contract.

The runners are exercised without any real tool: a fake binary on PATH proves
the executor's caps and classification, and the Docker argv is asserted flag
by flag because those flags ARE the isolation.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# PyYAML arrives transitively with uvicorn[standard]; it ships no stubs. Only the
# rule-contract tests need a YAML reader, so it stays out of the runtime graph.
import yaml  # type: ignore[import-untyped]

from app.analysis.models import ToolCategory, ToolStatus
from app.analysis.runners import DockerExecutor, LocalExecutor, RunnerSpec, build_executor
from app.analysis.runners.tools import (
    ClocRunner,
    GitleaksRunner,
    LizardRunner,
    OsvRunner,
    SemgrepRunner,
    SyftRunner,
    default_runners,
)
from app.core.config import Settings, get_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_TREE = REPO_ROOT / "rules"
RULES_DIR = RULES_TREE / "semgrep"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    get_settings.cache_clear()
    values = get_settings().model_dump()
    values.update(
        runner_mode="local",
        max_tool_output_bytes=2048,
        runner_timeout_seconds=30,
        rules_dir=RULES_TREE,
        osv_db_dir=tmp_path / "osvdb",
    )
    (tmp_path / "osvdb").mkdir()
    return Settings(**values)


@pytest.fixture
def fake_tool(tmp_path: Path) -> Iterator[Path]:
    """A ``faketool`` binary on PATH that writes its first argument's worth of bytes.

    ``faketool <out_file> <byte_count> <exit_code> [sleep_seconds]``
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "faketool"
    script.write_text(
        "#!/bin/sh\n"
        'if [ -n "$4" ]; then sleep "$4"; fi\n'
        'if [ "$2" -gt 0 ]; then head -c "$2" /dev/zero | tr "\\0" "x" > "$1"; fi\n'
        'echo "faketool stderr line" >&2\n'
        'exit "$3"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    original = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{bin_dir}{os.pathsep}{original}"
    try:
        yield bin_dir
    finally:
        os.environ["PATH"] = original


def _spec(argv: tuple[str, ...], *, ok: frozenset[int] = frozenset({0})) -> RunnerSpec:
    return RunnerSpec(
        tool="faketool",
        category=ToolCategory.SAST,
        argv=argv,
        output_file="report.txt",
        timeout_seconds=2,
        ok_exit_codes=ok,
    )


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "work"
    out_dir = tmp_path / "out"
    workspace.mkdir()
    out_dir.mkdir()
    return workspace, out_dir


# --- LocalExecutor --------------------------------------------------------------


def test_local_executor_translates_work_and_out(
    settings: Settings, fake_tool: Path, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    spec = _spec(("faketool", "/out/report.txt", "10", "0"))
    result = LocalExecutor(settings).run(spec, workspace=workspace, out_dir=out_dir)
    assert result.status is ToolStatus.RAN
    assert result.exit_code == 0
    assert result.output == b"x" * 10
    assert result.truncated is False
    assert "faketool stderr line" in result.stderr
    assert result.duration_ms >= 0
    translated = LocalExecutor.translate(
        RunnerSpec(
            tool="t",
            category=ToolCategory.SAST,
            argv=("tool", "/work", "/out/x", "/rules"),
            output_file="x",
            timeout_seconds=1,
            extra_ro_mounts=((Path("/host/rules"), "/rules"),),
        ),
        workspace=workspace,
        out_dir=out_dir,
    )
    assert translated == ["tool", str(workspace), f"{out_dir}/x", "/host/rules"]


def test_local_executor_caps_output_and_flags_truncation(
    settings: Settings, fake_tool: Path, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    spec = _spec(("faketool", "/out/report.txt", "5000", "0"))
    result = LocalExecutor(settings).run(spec, workspace=workspace, out_dir=out_dir)
    assert result.status is ToolStatus.RAN
    assert result.output is not None
    assert len(result.output) == settings.max_tool_output_bytes
    assert result.truncated is True


def test_local_executor_reports_timeout(
    settings: Settings, fake_tool: Path, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    spec = _spec(("faketool", "/out/report.txt", "1", "0", "5"))
    result = LocalExecutor(settings).run(spec, workspace=workspace, out_dir=out_dir)
    assert result.status is ToolStatus.TIMEOUT
    assert result.exit_code is None
    assert result.output is None
    assert result.detail == "killed after 2s"


def test_local_executor_reports_missing_binary(settings: Settings, dirs: tuple[Path, Path]) -> None:
    workspace, out_dir = dirs
    spec = _spec(("definitely-not-installed-tool", "/out/report.txt"))
    result = LocalExecutor(settings).run(spec, workspace=workspace, out_dir=out_dir)
    assert result.status is ToolStatus.MISSING
    assert result.detail == "definitely-not-installed-tool not found on PATH"


def test_ok_exit_codes_are_honored(
    settings: Settings, fake_tool: Path, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    executor = LocalExecutor(settings)
    # Exit 1 with a report: "findings present" for a scanner that declares it.
    found = executor.run(
        _spec(("faketool", "/out/report.txt", "3", "1"), ok=frozenset({0, 1})),
        workspace=workspace,
        out_dir=out_dir,
    )
    assert found.status is ToolStatus.RAN
    assert found.exit_code == 1
    # The same exit code for a tool that does NOT declare it is a failure.
    crashed = executor.run(
        _spec(("faketool", "/out/report.txt", "3", "1")), workspace=workspace, out_dir=out_dir
    )
    assert crashed.status is ToolStatus.FAILED
    assert crashed.detail == "exit 1: faketool stderr line"
    # A normal exit code without the report is still a failure: nothing to normalize.
    silent = executor.run(
        _spec(("faketool", "/out/report.txt", "0", "0")), workspace=workspace, out_dir=out_dir
    )
    assert silent.status is ToolStatus.FAILED
    assert silent.detail == "exit 0 but no report written (report.txt)"


# --- DockerExecutor -------------------------------------------------------------


def test_docker_command_is_isolated(settings: Settings, dirs: tuple[Path, Path]) -> None:
    workspace, out_dir = dirs
    spec = SemgrepRunner().spec(settings, workspace=workspace, out_dir=out_dir)
    argv = DockerExecutor(settings).command(spec, workspace=workspace, out_dir=out_dir)
    joined = " ".join(argv)
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "--network none" in joined
    assert "--read-only" in argv
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert f"--pids-limit {settings.runner_pids_limit}" in joined
    assert f"--memory {settings.runner_memory}" in joined
    assert f"--memory-swap {settings.runner_memory}" in joined
    assert f"--cpus {settings.runner_cpus}" in joined
    assert "--user 10001:10001" in joined
    assert f"-v {workspace}:/work:ro" in joined
    assert f"-v {out_dir}:/out:rw" in joined
    assert f"-v {RULES_TREE}:/rules:ro" in joined
    assert "docker.sock" not in joined
    assert "--privileged" not in joined
    # Image, then the tool argv verbatim.
    image_index = argv.index(settings.analysis_image)
    assert tuple(argv[image_index + 1 :]) == spec.argv


def test_runner_user_is_configurable_but_never_root(
    settings: Settings, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    custom = Settings(**{**settings.model_dump(), "runner_user": "1000:1000"})
    spec = SemgrepRunner().spec(custom, workspace=workspace, out_dir=out_dir)
    joined = " ".join(DockerExecutor(custom).command(spec, workspace=workspace, out_dir=out_dir))
    assert "--user 1000:1000" in joined and "10001" not in joined.split("--user")[1][:12]
    for forbidden in ("0:0", "root", "0", "1000", "1000:0", "1000:1000:1"):
        with pytest.raises(ValueError, match="runner_user"):
            Settings(**{**settings.model_dump(), "runner_user": forbidden})


def test_docker_executor_runs_the_built_command(
    settings: Settings, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    spec = _spec(("faketool", "/out/report.txt"))
    calls: list[list[str]] = []

    class _Completed:
        returncode = 0
        stderr = b""

    def fake_run(argv: list[str], **kwargs: Any) -> _Completed:
        calls.append(argv)
        assert kwargs["timeout"] == spec.timeout_seconds
        # The "container" writes its report, exactly like a real tool would.
        (out_dir / "report.txt").write_bytes(b"{}")
        return _Completed()

    with (
        patch("app.analysis.runners.executor.shutil.which", return_value="/usr/bin/docker"),
        patch("app.analysis.runners.executor.subprocess.run", side_effect=fake_run),
    ):
        result = DockerExecutor(settings).run(spec, workspace=workspace, out_dir=out_dir)
    assert result.status is ToolStatus.RAN
    assert result.output == b"{}"
    assert calls and calls[0][:2] == ["docker", "run"]


def test_docker_executor_without_docker_is_missing(
    settings: Settings, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    with patch("app.analysis.runners.executor.shutil.which", return_value=None):
        result = DockerExecutor(settings).run(
            _spec(("faketool",)), workspace=workspace, out_dir=out_dir
        )
    assert result.status is ToolStatus.MISSING
    assert result.detail == "docker binary not found on the worker"


def test_build_executor_follows_runner_mode(settings: Settings) -> None:
    assert isinstance(build_executor(settings), LocalExecutor)
    docker_settings = Settings(**{**settings.model_dump(), "runner_mode": "docker"})
    assert isinstance(build_executor(docker_settings), DockerExecutor)


# --- Runner specs ---------------------------------------------------------------


def test_default_runner_order_and_categories() -> None:
    runners = default_runners()
    assert [r.name for r in runners] == [
        "semgrep",
        "gitleaks",
        "osv-scanner",
        "syft",
        "lizard",
        "cloc",
    ]
    assert [r.category for r in runners] == [
        ToolCategory.SAST,
        ToolCategory.SECRET,
        ToolCategory.SCA,
        ToolCategory.SBOM,
        ToolCategory.METRICS,
        ToolCategory.METRICS,
    ]


def test_every_spec_is_offline_and_writes_under_out(
    settings: Settings, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    specs = {
        r.name: r.spec(settings, workspace=workspace, out_dir=out_dir) for r in default_runners()
    }
    semgrep = " ".join(specs["semgrep"].argv)
    assert "--metrics=off" in semgrep
    assert "--disable-version-check" in semgrep
    assert "--no-git-ignore" in semgrep
    assert "--x-ignore-semgrepignore-files" in semgrep
    assert "--config /rules/semgrep" in semgrep
    assert specs["semgrep"].extra_ro_mounts == ((RULES_TREE, "/rules"),)
    osv = " ".join(specs["osv-scanner"].argv)
    assert "--offline-vulnerabilities" in osv
    assert "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osvdb" in osv
    assert (settings.osv_db_dir, "/osvdb") in specs["osv-scanner"].extra_ro_mounts
    gitleaks = " ".join(specs["gitleaks"].argv)
    assert "--redact" in gitleaks
    assert "--report-format sarif" in gitleaks
    assert " ".join(specs["syft"].argv).startswith("syft scan dir:/work -o cyclonedx-json@1.6=")
    for name, spec in specs.items():
        joined = " ".join(spec.argv)
        assert f"/out/{spec.output_file}" in joined, name
        assert "/work" in joined, name
        assert spec.timeout_seconds == settings.runner_timeout_seconds
        for host_path, container_path in spec.extra_ro_mounts:
            assert host_path.is_absolute()
            assert container_path.startswith("/")
    # Scanners exit 1 when they find something; the metric tools do not.
    assert specs["semgrep"].ok_exit_codes == {0, 1}
    assert specs["gitleaks"].ok_exit_codes == {0, 1}
    assert specs["osv-scanner"].ok_exit_codes == {0, 1}
    assert specs["syft"].ok_exit_codes == {0}
    assert specs["lizard"].ok_exit_codes == {0}
    assert specs["cloc"].ok_exit_codes == {0}
    # Scanner policy is OURS: config files inside the audited tree never apply.
    assert "--config /rules/gitleaks/gitleaks.toml" in gitleaks
    assert "--ignore-gitleaks-allow" in gitleaks
    assert (RULES_TREE, "/rules") in specs["gitleaks"].extra_ro_mounts
    assert "--config /rules/osv-scanner/osv-scanner.toml" in osv
    assert (RULES_TREE, "/rules") in specs["osv-scanner"].extra_ro_mounts
    assert "-w /tmp" in " ".join(
        DockerExecutor(settings).command(specs["syft"], workspace=workspace, out_dir=out_dir)
    )


def test_gitleaks_history_spec(settings: Settings, dirs: tuple[Path, Path]) -> None:
    workspace, out_dir = dirs
    spec = GitleaksRunner().spec_git_history(settings, workspace=workspace, out_dir=out_dir)
    assert spec.tool == "gitleaks-git"
    assert spec.argv[:3] == ("gitleaks", "git", "/work")
    assert spec.output_file == "gitleaks-git.sarif"


def test_osv_runner_is_a_coverage_gap_without_a_database(
    settings: Settings, dirs: tuple[Path, Path]
) -> None:
    workspace, out_dir = dirs
    runner = OsvRunner()
    assert runner.unavailable_reason(settings) is None
    unset = Settings(**{**settings.model_dump(), "osv_db_dir": None})
    assert unset.osv_db_dir is None
    assert runner.unavailable_reason(unset) == "OSV database not configured (DIOPTRA_OSV_DB_DIR)"
    with pytest.raises(ValueError, match="without an OSV database"):
        runner.spec(unset, workspace=workspace, out_dir=out_dir)
    missing = Settings(**{**settings.model_dump(), "osv_db_dir": workspace / "nope"})
    assert runner.unavailable_reason(missing) is not None
    assert runner.unavailable_reason(missing) is not None
    assert "missing" in str(runner.unavailable_reason(missing))


def test_semgrep_runner_needs_the_rules_directory(
    settings: Settings, dirs: tuple[Path, Path]
) -> None:
    workspace, _ = dirs
    assert SemgrepRunner().unavailable_reason(settings) is None
    gone = Settings(**{**settings.model_dump(), "rules_dir": workspace / "no-rules"})
    assert "missing" in str(SemgrepRunner().unavailable_reason(gone))


def test_always_available_runners(settings: Settings) -> None:
    for runner in (GitleaksRunner(), SyftRunner(), LizardRunner(), ClocRunner()):
        assert runner.unavailable_reason(settings) is None


def test_runner_paths_must_be_absolute(settings: Settings, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        SemgrepRunner().spec(settings, workspace=Path("relative"), out_dir=tmp_path)


# --- Own Semgrep rules: the contract every rule file must satisfy ----------------

RULE_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CWE_TAG = re.compile(r"^CWE-\d{1,4}$")
OWASP_TAG = re.compile(r"^A(0[1-9]|10):2021$")


def _rule_files() -> list[Path]:
    return sorted(RULES_DIR.glob("*.yml"))


def test_rule_files_exist() -> None:
    assert len(_rule_files()) >= 12


@pytest.mark.parametrize("rule_file", _rule_files(), ids=lambda p: p.stem)
def test_rule_metadata_contract(rule_file: Path) -> None:
    document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
    rules = document["rules"]
    assert rules, rule_file
    for rule in rules:
        assert RULE_ID.match(rule["id"]), rule["id"]
        assert rule["message"].strip(), rule["id"]
        assert rule["severity"] in {"INFO", "WARNING", "ERROR"}, rule["id"]
        assert rule["languages"], rule["id"]
        metadata = rule["metadata"]
        assert CWE_TAG.match(metadata["cwe"]), rule["id"]
        assert OWASP_TAG.match(metadata["owasp"]), rule["id"]
        assert metadata["category"] == "security", rule["id"]
        assert metadata["confidence"] in {"LOW", "MEDIUM", "HIGH"}, rule["id"]


def test_rule_ids_are_unique_across_families() -> None:
    seen: set[str] = set()
    for rule_file in _rule_files():
        for rule in yaml.safe_load(rule_file.read_text(encoding="utf-8"))["rules"]:
            assert rule["id"] not in seen, rule["id"]
            seen.add(rule["id"])


@pytest.mark.parametrize("rule_file", _rule_files(), ids=lambda p: p.stem)
def test_every_family_ships_a_positive_and_negative_pair(rule_file: Path) -> None:
    tests_dir = RULES_DIR / "tests" / rule_file.stem
    positives = list(tests_dir.glob("positive.*"))
    negatives = list(tests_dir.glob("negative.*"))
    assert positives, f"{rule_file.stem}: no positive test file"
    assert negatives, f"{rule_file.stem}: no negative test file"
    ids = {rule["id"] for rule in yaml.safe_load(rule_file.read_text(encoding="utf-8"))["rules"]}
    annotated_positive = set()
    for positive in positives:
        annotated_positive |= set(re.findall(r"ruleid:\s*([a-z0-9-]+)", positive.read_text()))
    assert annotated_positive == ids, f"{rule_file.stem}: every rule needs a ruleid: case"
    for negative in negatives:
        assert "ok:" in negative.read_text(), f"{negative}: needs at least one ok: case"


def test_no_cdn_rule_maps_to_cwe_829() -> None:
    """Factory norm, Hard Rule level 2: the CDN rule exists and is classified right."""
    document = yaml.safe_load((RULES_DIR / "no-cdn.yml").read_text(encoding="utf-8"))
    for rule in document["rules"]:
        assert rule["metadata"]["cwe"] == "CWE-829"
        assert rule["metadata"]["owasp"] == "A08:2021"
