"""Contracts shared by every runner and executor.

A *runner* knows how to invoke one tool: the argv, where it writes its report
and which exit codes are normal for it. An *executor* knows how to run that
argv somewhere safe. The two never mix, so the same spec is exercised by the
test suite on the host and by production inside a container with no network.

Path conventions inside a spec are fixed: the audited tree is at ``/work``
(read-only) and every report goes to ``/out``. Executors translate.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from app.analysis.models import ToolCategory, ToolStatus
from app.core.config import Settings

#: Where the audited tree is visible to the tool. Always read-only.
WORK_DIR = "/work"
#: Where the tool writes its report. The only writable bind mount.
OUT_DIR = "/out"


@dataclass(frozen=True)
class RunnerSpec:
    """Everything an executor needs to run one tool once."""

    tool: str
    category: ToolCategory
    #: Command as seen INSIDE the container (or on the host after translation).
    argv: tuple[str, ...]
    #: File name under ``/out`` the tool writes; read back capped by the executor.
    output_file: str
    timeout_seconds: int
    #: Extra read-only bind mounts: ``(host_path, container_path)``.
    extra_ro_mounts: tuple[tuple[Path, str], ...] = ()
    #: Exit codes that mean "the tool did its job" — for scanners, "findings
    #: present" is usually 1 and must not be mistaken for a crash.
    ok_exit_codes: frozenset[int] = frozenset({0})


@dataclass(frozen=True)
class ExecutionResult:
    """What came back from one run.

    ``output`` is the report as STORED (capped, ``truncated`` says so);
    ``document`` is the whole report, read once from the same descriptor, and
    is what the normalizer parses. An executor that cut ``output`` always sets
    ``document`` or refuses the run: a cut document is never parsed.
    """

    status: ToolStatus
    exit_code: int | None
    stderr: str
    output: bytes | None
    truncated: bool
    duration_ms: int
    detail: str | None
    document: bytes | None = None

    @property
    def parseable(self) -> bytes | None:
        """The bytes the normalizer may read: the whole document, never a cut copy."""
        if self.document is not None:
            return self.document
        return None if self.truncated else self.output


class Executor(Protocol):
    """Runs a spec. Implementations decide the isolation; the spec never does."""

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult: ...


class Runner(Protocol):
    """Describes one tool. Stateless: everything comes from settings and paths."""

    # Read-only on purpose: the concrete runners are frozen dataclasses, and a
    # mutable protocol attribute would not accept them.
    @property
    def name(self) -> str: ...

    @property
    def category(self) -> ToolCategory: ...

    @property
    def ok_exit_codes(self) -> frozenset[int]: ...

    def unavailable_reason(self, settings: Settings) -> str | None:
        """``None`` when the tool can run; otherwise the coverage-gap text."""
        ...

    def spec(self, settings: Settings, *, workspace: Path, out_dir: Path) -> RunnerSpec: ...
