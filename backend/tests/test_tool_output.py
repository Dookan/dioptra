"""A tool's report is parsed WHOLE or not at all (hardening 1.5.1, item 5).

The storage cap used to be the parse cap: on a 1.4 GiB tree Semgrep's SARIF
passed 32 MiB, was cut, did not parse, and the SAST layer was lost; Lizard's
CSV was cut the same way and parsed SHORT with nothing saying so
(`tasks/hardening-1.5.1-survey.md` §1, §11.2). And the report file sits in a
directory the analysis container can write, so it is opened without following
a link (§11.6).
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, AnalysisStatus, ToolCategory, ToolStatus
from app.analysis.runners.base import ExecutionResult, RunnerSpec
from app.analysis.runners.executor import _finish, read_output, read_report
from app.auth.models import User
from app.core.config import Settings
from tests.test_pipeline import FixtureExecutor, _ingest, login

SPEC = RunnerSpec(
    tool="semgrep",
    category=ToolCategory.SAST,
    argv=("semgrep",),
    output_file="report.sarif",
    timeout_seconds=10,
    ok_exit_codes=frozenset({0, 1}),
)


def _write(path: Path, size: int) -> bytes:
    data = bytes((i * 7) % 251 for i in range(size))
    path.write_bytes(data)
    return data


# --- read_report --------------------------------------------------------------


def test_a_small_report_is_stored_and_parsed_whole(tmp_path: Path) -> None:
    data = _write(tmp_path / "r", 100)
    report = read_report(tmp_path / "r", store_cap=100, parse_cap=200)
    assert report is not None
    assert (report.stored, report.truncated, report.document, report.size) == (
        data,
        False,
        data,
        100,
    )


def test_a_report_over_the_storage_cap_is_still_parsed_whole(tmp_path: Path) -> None:
    data = _write(tmp_path / "r", 150)
    report = read_report(tmp_path / "r", store_cap=100, parse_cap=200)
    assert report is not None
    assert report.stored == data[:100]
    assert report.truncated is True
    assert report.document == data
    assert report.size == 150


def test_a_report_exactly_at_the_parse_cap_is_parsed(tmp_path: Path) -> None:
    data = _write(tmp_path / "r", 200)
    report = read_report(tmp_path / "r", store_cap=100, parse_cap=200)
    assert report is not None
    assert report.document == data


def test_a_report_over_the_parse_cap_is_never_parsed(tmp_path: Path) -> None:
    data = _write(tmp_path / "r", 201)
    report = read_report(tmp_path / "r", store_cap=100, parse_cap=200)
    assert report is not None
    assert report.document is None
    assert report.stored == data[:100]
    assert report.truncated is True
    assert report.size == 201


def test_a_symlinked_report_is_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "worker-file"
    secret.write_bytes(b"what the worker can read")
    (tmp_path / "r").symlink_to(secret)
    assert read_report(tmp_path / "r", store_cap=100, parse_cap=200) is None
    assert read_output(tmp_path / "r", 100) == (None, False)


def test_a_fifo_or_a_directory_is_no_report_and_never_blocks(tmp_path: Path) -> None:
    """A FIFO with no writer blocks a plain open forever: the read must not.

    Run in a thread so a regression FAILS here instead of hanging the suite
    (the mutation pass found exactly that: a dropped ``O_NONBLOCK`` hung).
    """
    os.mkfifo(tmp_path / "fifo")
    (tmp_path / "dir").mkdir()
    outcome: list[object] = []
    reader = threading.Thread(
        target=lambda: outcome.append(read_report(tmp_path / "fifo", store_cap=10, parse_cap=10)),
        daemon=True,
    )
    reader.start()
    reader.join(5)
    if reader.is_alive():  # release it, then fail
        os.close(os.open(tmp_path / "fifo", os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail("reading a FIFO blocked")
    assert outcome == [None]
    assert read_report(tmp_path / "dir", store_cap=10, parse_cap=10) is None


def test_a_missing_report_is_no_report(tmp_path: Path) -> None:
    assert read_report(tmp_path / "nothing", store_cap=10, parse_cap=10) is None


def test_read_output_keeps_its_capped_contract(tmp_path: Path) -> None:
    data = _write(tmp_path / "r", 50)
    assert read_output(tmp_path / "r", 50) == (data, False)
    data = _write(tmp_path / "r", 51)
    assert read_output(tmp_path / "r", 50) == (data[:50], True)


# --- _finish -------------------------------------------------------------------


def _finish_on(tmp_path: Path, size: int, exit_code: int = 0) -> ExecutionResult:
    _write(tmp_path / SPEC.output_file, size)
    return _finish(
        SPEC,
        exit_code=exit_code,
        stderr="",
        out_dir=tmp_path,
        started=time.monotonic(),
        cap=100,
        parse_cap=2 * 1024 * 1024,
    )


def test_a_report_between_the_caps_runs_and_carries_the_whole_document(tmp_path: Path) -> None:
    result = _finish_on(tmp_path, 1000)
    assert result.status is ToolStatus.RAN
    assert result.truncated is True
    assert result.output is not None
    assert len(result.output) == 100
    assert result.document is not None
    assert len(result.document) == 1000
    assert result.parseable == result.document


def test_a_report_over_the_parse_cap_fails_and_says_its_size(tmp_path: Path) -> None:
    result = _finish_on(tmp_path, 3 * 1024 * 1024 + 5, exit_code=1)
    assert result.status is ToolStatus.FAILED
    assert result.detail == "output too large: 3 MiB > 2 MiB"
    assert result.document is None
    assert result.parseable is None
    assert result.output is not None
    assert len(result.output) == 100  # the evidence copy is kept


def test_a_bad_exit_code_is_still_a_failure_whatever_the_report(tmp_path: Path) -> None:
    result = _finish_on(tmp_path, 10, exit_code=2)
    assert result.status is ToolStatus.FAILED
    assert result.detail == "exit 2"
    assert (result.exit_code, result.stderr) == (2, "")
    assert 0 <= result.duration_ms < 60_000


def _finish_without(tmp_path: Path, exit_code: int, stderr: str) -> ExecutionResult:
    return _finish(
        SPEC,
        exit_code=exit_code,
        stderr=stderr,
        out_dir=tmp_path,
        started=time.monotonic(),
        cap=100,
        parse_cap=200,
    )


def test_a_tool_that_exits_well_but_writes_nothing_failed(tmp_path: Path) -> None:
    result = _finish_without(tmp_path, 0, "")
    assert result.status is ToolStatus.FAILED
    assert result.detail == "exit 0 but no report written (report.sarif)"
    assert (result.output, result.truncated, result.document) == (None, False, None)
    assert (result.exit_code, result.stderr) == (0, "")


def test_a_crash_with_no_report_says_the_tail_of_its_stderr(tmp_path: Path) -> None:
    result = _finish_without(tmp_path, 2, "first line\n" + "x" * 300 + "boom  \n")
    assert result.status is ToolStatus.FAILED
    assert result.detail is not None
    assert result.detail.startswith("exit 2: ")
    assert result.detail.endswith("boom")
    assert len(result.detail) == len("exit 2: ") + 200  # the tail, never the head
    assert result.stderr.startswith("first line")
    assert _finish_without(tmp_path, 3, "   ").detail == "exit 3"


def test_a_report_that_runs_carries_its_process_fields(tmp_path: Path) -> None:
    _write(tmp_path / SPEC.output_file, 10)
    result = _finish(
        SPEC,
        exit_code=1,
        stderr="warn",
        out_dir=tmp_path,
        started=time.monotonic(),
        cap=100,
        parse_cap=200,
    )
    assert result.status is ToolStatus.RAN
    assert (result.exit_code, result.stderr, result.detail) == (1, "warn", None)
    assert 0 <= result.duration_ms < 60_000


def test_a_cut_output_without_its_document_is_never_parseable() -> None:
    cut = ExecutionResult(ToolStatus.RAN, 0, "", b"{", True, 1, None)
    assert cut.parseable is None
    whole = ExecutionResult(ToolStatus.RAN, 0, "", b"{}", False, 1, None)
    assert whole.parseable == b"{}"


def test_the_parse_cap_may_equal_the_storage_cap() -> None:
    Settings(max_tool_output_bytes=4096, max_tool_parse_bytes=4096)  # type: ignore[call-arg]


def test_the_parse_cap_may_not_be_below_the_storage_cap() -> None:
    with pytest.raises(ValueError, match="MAX_TOOL_PARSE_BYTES"):
        Settings(max_tool_output_bytes=4096, max_tool_parse_bytes=2048)  # type: ignore[call-arg]


# --- the pipeline parses the document, never the stored copy -----------------


class CutExecutor(FixtureExecutor):
    """Every report comes back STORED cut to 64 bytes, as a real large run would."""

    with_document = True

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        result = super().run(spec, workspace=workspace, out_dir=out_dir)
        if result.output is None:
            return result
        return ExecutionResult(
            ToolStatus.RAN,
            0,
            "",
            result.output[:64],
            True,
            5,
            None,
            document=result.output if self.with_document else None,
        )


@pytest.fixture
def cut_executor(monkeypatch: pytest.MonkeyPatch) -> CutExecutor:
    executor = CutExecutor()
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _settings, **_kw: executor)
    return executor


def test_the_pipeline_parses_the_whole_document_of_a_large_report(
    client: TestClient, analyst: User, db: Session, cut_executor: CutExecutor
) -> None:
    analysis = db.get(Analysis, uuid.UUID(_ingest(client, login(client, analyst.username))))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE, analysis.failure_code
    runs = {run.tool: run.status for run in analysis.tool_runs}
    assert runs["semgrep"] is ToolStatus.RAN
    assert runs["lizard"] is ToolStatus.RAN
    assert analysis.findings, "the SARIF was parsed whole, not from its 64-byte copy"
    assert analysis.metrics is not None
    assert analysis.metrics.functions
    stored = {raw.tool: raw for raw in analysis.raw_outputs}
    assert stored["semgrep"].truncated is True
    assert stored["semgrep"].output is not None
    assert len(stored["semgrep"].output) == 64


def test_the_pipeline_never_parses_a_cut_copy(
    client: TestClient, analyst: User, db: Session, cut_executor: CutExecutor
) -> None:
    cut_executor.with_document = False
    analysis = db.get(Analysis, uuid.UUID(_ingest(client, login(client, analyst.username))))
    assert analysis is not None
    rows = {run.tool: run for run in analysis.tool_runs}
    for tool in ("semgrep", "lizard", "cloc", "syft"):
        assert rows[tool].status is ToolStatus.FAILED, tool
        assert rows[tool].detail == "output truncated and not parsed"
    # No security tool ran whole, so the analysis fails closed.
    assert analysis.status is AnalysisStatus.FAILED
