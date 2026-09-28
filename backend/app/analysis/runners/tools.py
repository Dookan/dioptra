"""Concrete runners. Every argv is offline by construction.

Tool authority: CLAUDE.md → Analysis Tool Source Authority. Each runner writes
ONE report under ``/out`` and declares which exit codes are normal, because
scanners conventionally exit 1 when they find something.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.analysis.models import ToolCategory
from app.analysis.runners.base import OUT_DIR, WORK_DIR, Runner, RunnerSpec
from app.core.config import Settings

#: Where our rules tree (semgrep/, gitleaks/, osv-scanner/) is mounted, read-only.
RULES_DIR = "/rules"
SEMGREP_RULES = f"{RULES_DIR}/semgrep"
GITLEAKS_CONFIG = f"{RULES_DIR}/gitleaks/gitleaks.toml"
OSV_CONFIG = f"{RULES_DIR}/osv-scanner/osv-scanner.toml"
#: Where the local OSV database is mounted inside the container.
OSV_DB_DIR = "/osvdb"


_MEMORY_UNITS = {"b": 1 / (1024 * 1024), "k": 1 / 1024, "m": 1, "g": 1024}
#: Below this per-job share a scan is not worth parallelising: jobs are cut
#: until each gets at least this much, so jobs × share never exceeds the box.
_MIN_JOB_MIB = 512


def _memory_mib(raw: str) -> int:
    """Docker's memory spelling (`2g`, `2gb`, `512m`, bare bytes) in MiB; 0 if unreadable."""
    text = raw.strip().lower()
    if len(text) >= 2 and text.endswith("b") and text[-2] in "kmg":
        text = text[:-1]  # `2gb` is docker's other spelling of `2g`
    unit = _MEMORY_UNITS.get(text[-1:])
    number = text[:-1] if unit is not None else text
    try:
        return int(float(number) * (unit if unit is not None else _MEMORY_UNITS["b"]))
    except ValueError:
        return 0


def semgrep_budget(settings: Settings) -> tuple[int, int]:
    """(jobs, max-memory MiB per file) that fit INSIDE the runner's limits.

    Found by the phase-10 walk (2026-09-28): on a 1.4 GiB tree Semgrep died
    with `semgrep-core exited with -9` — the kernel's OOM kill — because it
    sizes its parallelism from the HOST's cores (it saw 8 and ran 7 jobs) while
    the container is capped at `runner_cpus` and `runner_memory` (2 and 2 GiB).
    So: one job per CPU the container actually has, but never more jobs than
    the memory can give `_MIN_JOB_MIB` each, and a per-file memory cap that
    leaves every job its share plus one share of headroom. A rule that would
    pass the cap on one pathological file (minified bundles) is dropped FOR
    THAT FILE — Semgrep notes it in its raw output, which is stored — instead
    of the kernel killing the whole scan and the layer becoming a coverage gap.
    """
    try:
        cpus = max(1, int(float(settings.runner_cpus)))
    except ValueError:
        cpus = 1
    memory_mib = _memory_mib(settings.runner_memory)
    jobs = max(1, min(cpus, memory_mib // _MIN_JOB_MIB))
    return jobs, max(128, memory_mib // (jobs + 1))


def _paths_are_translated_by_executor(workspace: Path, out_dir: Path) -> None:
    """Runners receive the real paths but never embed them.

    Specs always speak ``/work`` and ``/out`` so the same spec is byte-identical
    in the container and on the host; the executor does the translation. The
    paths stay in the ``Runner`` contract so a future tool that must inspect the
    tree (e.g. to pick a lockfile) can, without changing the protocol.
    """
    if not workspace.is_absolute() or not out_dir.is_absolute():
        message = "runner paths must be absolute"
        raise ValueError(message)


@dataclass(frozen=True)
class SemgrepRunner:
    """SAST with OUR rules only; ``--metrics=off`` and no version check keep it offline."""

    name: str = "semgrep"
    category: ToolCategory = ToolCategory.SAST
    ok_exit_codes: frozenset[int] = frozenset({0, 1})

    def unavailable_reason(self, settings: Settings) -> str | None:
        if not (settings.rules_dir / "semgrep").is_dir():
            return f"Semgrep rules directory missing ({settings.rules_dir / 'semgrep'})"
        return None

    def spec(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec:
        _paths_are_translated_by_executor(workspace, out_dir)
        jobs, max_memory = semgrep_budget(settings)
        return RunnerSpec(
            tool=self.name,
            category=self.category,
            argv=(
                "semgrep",
                "scan",
                "--config",
                SEMGREP_RULES,
                "--sarif",
                "--output",
                f"{OUT_DIR}/semgrep.sarif",
                "--metrics=off",
                # The audited tree is hostile: a .gitignore or .semgrepignore it
                # ships must not be able to hide files from the scan. The second
                # flag is marked internal upstream; the analysis image pins the
                # semgrep version, and test_runners asserts the flag is present.
                "--no-git-ignore",
                "--x-ignore-semgrepignore-files",
                "--timeout",
                "30",
                "--max-target-bytes",
                "2000000",
                "--jobs",
                str(jobs),
                "--max-memory",
                str(max_memory),
                "--disable-version-check",
                WORK_DIR,
            ),
            output_file="semgrep.sarif",
            timeout_seconds=settings.runner_timeout_seconds,
            extra_ro_mounts=((settings.rules_dir, RULES_DIR),),
            ok_exit_codes=self.ok_exit_codes,
        )


@dataclass(frozen=True)
class GitleaksRunner:
    """Secrets over the working tree. ``--redact`` keeps the secret out of the report.

    History scanning is a second spec (:meth:`spec_git_history`) the pipeline
    runs only when ``/work/.git`` exists — a ZIP has no history to scan.
    """

    name: str = "gitleaks"
    category: ToolCategory = ToolCategory.SECRET
    ok_exit_codes: frozenset[int] = frozenset({0, 1})

    def unavailable_reason(self, settings: Settings) -> str | None:
        if not (settings.rules_dir / "gitleaks" / "gitleaks.toml").is_file():
            return f"gitleaks rule set missing ({settings.rules_dir / 'gitleaks'})"
        return None

    def spec(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec:
        _paths_are_translated_by_executor(workspace, out_dir)
        return RunnerSpec(
            tool=self.name,
            category=self.category,
            argv=(
                "gitleaks",
                "dir",
                WORK_DIR,
                # OUR rule set, always: a .gitleaks.toml inside the audited tree
                # would otherwise allowlist itself (threat-model → Analysis containers).
                "--config",
                GITLEAKS_CONFIG,
                "--report-format",
                "sarif",
                "--report-path",
                f"{OUT_DIR}/gitleaks.sarif",
                "--no-banner",
                "--redact",
                # An inline `gitleaks:allow` comment is the audited code's
                # opinion, not the analyst's.
                "--ignore-gitleaks-allow",
                "--exit-code",
                "1",
            ),
            output_file="gitleaks.sarif",
            timeout_seconds=settings.runner_timeout_seconds,
            extra_ro_mounts=((settings.rules_dir, RULES_DIR),),
            ok_exit_codes=self.ok_exit_codes,
        )

    def spec_git_history(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec:
        _paths_are_translated_by_executor(workspace, out_dir)
        """Scan every commit: a secret removed later is still a secret."""
        return RunnerSpec(
            tool=f"{self.name}-git",
            category=self.category,
            argv=(
                "gitleaks",
                "git",
                WORK_DIR,
                "--config",
                GITLEAKS_CONFIG,
                "--report-format",
                "sarif",
                "--report-path",
                f"{OUT_DIR}/gitleaks-git.sarif",
                "--no-banner",
                "--redact",
                # An inline `gitleaks:allow` comment is the audited code's
                # opinion, not the analyst's.
                "--ignore-gitleaks-allow",
                "--exit-code",
                "1",
            ),
            output_file="gitleaks-git.sarif",
            timeout_seconds=settings.runner_timeout_seconds,
            extra_ro_mounts=((settings.rules_dir, RULES_DIR),),
            ok_exit_codes=self.ok_exit_codes,
        )


@dataclass(frozen=True)
class OsvRunner:
    """SCA against the LOCAL OSV database only — never a live query (Hard Rule, level 3)."""

    name: str = "osv-scanner"
    category: ToolCategory = ToolCategory.SCA
    ok_exit_codes: frozenset[int] = frozenset({0, 1})

    def unavailable_reason(self, settings: Settings) -> str | None:
        if settings.osv_db_dir is None:
            return "OSV database not configured (DIOPTRA_OSV_DB_DIR)"
        if not settings.osv_db_dir.is_dir():
            return f"OSV database directory missing ({settings.osv_db_dir})"
        return None

    def spec(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec:
        _paths_are_translated_by_executor(workspace, out_dir)
        db_dir = settings.osv_db_dir
        if db_dir is None:
            message = "OsvRunner.spec called without an OSV database; check unavailable_reason"
            raise ValueError(message)
        return RunnerSpec(
            tool=self.name,
            category=self.category,
            # osv-scanner 2.x reads the offline database from this variable
            # (layout ``<dir>/osv-scanner/<Ecosystem>/all.zip``); the 1.x
            # ``--local-db-dir`` flag no longer exists. ``env`` keeps the spec a
            # plain argv so both executors translate the path the same way.
            argv=(
                "env",
                f"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={OSV_DB_DIR}",
                "osv-scanner",
                "scan",
                "source",
                # OUR (empty) config: an osv-scanner.toml next to a lockfile in
                # the audited tree could list IgnoredVulns.
                "--config",
                OSV_CONFIG,
                "--offline-vulnerabilities",
                "--format",
                "sarif",
                "--output",
                f"{OUT_DIR}/osv.sarif",
                "--recursive",
                WORK_DIR,
            ),
            output_file="osv.sarif",
            timeout_seconds=settings.runner_timeout_seconds,
            extra_ro_mounts=((db_dir, OSV_DB_DIR), (settings.rules_dir, RULES_DIR)),
            ok_exit_codes=self.ok_exit_codes,
        )


@dataclass(frozen=True)
class SyftRunner:
    """SBOM (CycloneDX 1.6) from lockfiles and manifests.

    Metadata only: syft catalogs files, it never installs anything and never
    executes a package script. Combined with ``--network none`` this is what
    makes the SBOM safe to build from a hostile tree.
    """

    name: str = "syft"
    category: ToolCategory = ToolCategory.SBOM
    ok_exit_codes: frozenset[int] = frozenset({0})

    def unavailable_reason(self, settings: Settings) -> str | None:  # noqa: ARG002
        return None

    def spec(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec:
        _paths_are_translated_by_executor(workspace, out_dir)
        return RunnerSpec(
            tool=self.name,
            category=self.category,
            argv=(
                "syft",
                "scan",
                f"dir:{WORK_DIR}",
                "-o",
                f"cyclonedx-json@1.6={OUT_DIR}/sbom.cdx.json",
                "--quiet",
            ),
            output_file="sbom.cdx.json",
            timeout_seconds=settings.runner_timeout_seconds,
            ok_exit_codes=self.ok_exit_codes,
        )


@dataclass(frozen=True)
class LizardRunner:
    """Cyclomatic complexity per function. Writes to stdout, hence the shell redirect."""

    name: str = "lizard"
    category: ToolCategory = ToolCategory.METRICS
    ok_exit_codes: frozenset[int] = frozenset({0})

    def unavailable_reason(self, settings: Settings) -> str | None:  # noqa: ARG002
        return None

    def spec(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec:
        _paths_are_translated_by_executor(workspace, out_dir)
        command = (
            # ``exec`` so a timeout kills lizard itself, not just the shell.
            "exec lizard --csv -l javascript -l typescript -l python -l php -l java "
            f"{WORK_DIR} > {OUT_DIR}/lizard.csv"
        )
        return RunnerSpec(
            tool=self.name,
            category=self.category,
            argv=("sh", "-c", command),
            output_file="lizard.csv",
            timeout_seconds=settings.runner_timeout_seconds,
            ok_exit_codes=self.ok_exit_codes,
        )


@dataclass(frozen=True)
class ClocRunner:
    """Lines of code per language, for the report's sizing and E4."""

    name: str = "cloc"
    category: ToolCategory = ToolCategory.METRICS
    ok_exit_codes: frozenset[int] = frozenset({0})

    def unavailable_reason(self, settings: Settings) -> str | None:  # noqa: ARG002
        return None

    def spec(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec:
        _paths_are_translated_by_executor(workspace, out_dir)
        return RunnerSpec(
            tool=self.name,
            category=self.category,
            argv=("cloc", "--json", "--quiet", f"--out={OUT_DIR}/cloc.json", WORK_DIR),
            output_file="cloc.json",
            timeout_seconds=settings.runner_timeout_seconds,
            ok_exit_codes=self.ok_exit_codes,
        )


def default_runners() -> tuple[Runner, ...]:
    """The pipeline's tool order: security first, then the SBOM, then metrics."""
    return (
        SemgrepRunner(),
        GitleaksRunner(),
        OsvRunner(),
        SyftRunner(),
        LizardRunner(),
        ClocRunner(),
    )
