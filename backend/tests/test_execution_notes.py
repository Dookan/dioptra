"""A scanner that dropped files says so in the coverage table (hardening 1.5.1, item 2).

Semgrep writes each drop into its SARIF's `toolExecutionNotifications` — 96 of
them on a real 1.4 GiB tree — and the coverage row used to read RAN with
nothing beside it (`tasks/hardening-1.5.1-survey.md` §3). The note carries
COUNTS only: a file name from the audited tree never reaches it.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, ToolStatus
from app.analysis.normalizer import MAX_NOTIFICATIONS, execution_notes
from app.analysis.runners.base import ExecutionResult, RunnerSpec
from app.auth.models import User
from app.reports.context import tool_detail_text
from tests.test_pipeline import FIXTURES, FixtureExecutor, _ingest, login


def _note(kind: str, text: str, level: str = "warning") -> dict[str, Any]:
    return {"descriptor": {"id": kind}, "level": level, "message": {"text": text}}


def _sarif(*notes: object) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"invocations": [{"toolExecutionNotifications": list(notes)}], "results": []}],
    }


def test_a_document_that_declares_no_drop_gets_no_note() -> None:
    assert execution_notes({"version": "2.1.0", "runs": []}) is None
    assert execution_notes({"runs": [{"results": []}]}) is None
    assert execution_notes(_sarif()) is None
    assert execution_notes(_sarif(_note("Info", "fine", level="note"))) is None


def test_each_drop_is_counted_by_kind_and_files_are_counted_once() -> None:
    note = execution_notes(
        _sarif(
            _note("Syntax error", "Syntax error at line /work/a.js:3:\n `x` was unexpected"),
            _note("Other syntax error", "Other syntax error at line /work/a.js:9:\n y"),
            _note("Out of memory", "Out of memory at line /work/b.js:1:\n Exceeded"),
            _note("Timeout", "Timeout when running rules.x on /work/c.js\n "),
            _note("Fixpoint timeout", "on /work/c.js"),
            _note("Something new", "no path here"),
            _note("Info", "ignored", level="note"),
        )
    )
    assert note == "partial: 4 files; syntax=2 memory=1 timeout=2 other=1"


def test_a_hostile_file_name_never_reaches_the_note() -> None:
    note = execution_notes(
        _sarif(_note("Syntax error", "at line /work/<img src=x onerror=alert(1)>.js:1:\n"))
    )
    assert note == "partial: 1 files; syntax=1 memory=0 timeout=0 other=0"
    assert note is not None
    assert "<" not in note
    assert "work" not in note


def test_the_notifications_read_are_bounded() -> None:
    notes = [_note("Timeout", f"on /work/f{i}.js") for i in range(MAX_NOTIFICATIONS + 5)]
    assert execution_notes(_sarif(*notes)) == (
        f"partial: {MAX_NOTIFICATIONS} files; syntax=0 memory=0 timeout={MAX_NOTIFICATIONS} other=0"
    )


@pytest.mark.parametrize(
    "document",
    [
        {"runs": "x"},
        {"runs": [None, 3, {"invocations": {"a": 1}}]},
        {"runs": [{"invocations": [None, {"toolExecutionNotifications": "x"}]}]},
        _sarif(None, 7, "text", {"descriptor": "x", "message": 5}),
        _sarif({"descriptor": {"id": 12}, "message": {"text": ["a"]}}),
    ],
)
def test_a_malformed_notification_block_never_raises(document: dict[str, Any]) -> None:
    note = execution_notes(document)
    assert note is None or note.startswith("partial: ")


def test_a_very_long_message_is_bounded_before_it_is_read() -> None:
    long = "x" * 100_000 + " /work/late.js"
    assert execution_notes(_sarif(_note("Timeout", long))) == (
        "partial: 1 files; syntax=0 memory=0 timeout=1 other=0"
    )


# --- the pipeline writes it, the report words it --------------------------------


class NotedExecutor(FixtureExecutor):
    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        if spec.output_file != "semgrep.sarif":
            return super().run(spec, workspace=workspace, out_dir=out_dir)
        document = json.loads((FIXTURES / "semgrep.sarif.json").read_bytes())
        document["runs"][0]["invocations"] = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    _note("Syntax error", "Syntax error at line /work/src/a.js:1:\n x"),
                    _note("Timeout", "Timeout when running rules.r on /work/index.js\n"),
                ],
            }
        ]
        self.specs.append(spec)
        return ExecutionResult(ToolStatus.RAN, 0, "", json.dumps(document).encode(), False, 5, None)


def test_the_coverage_row_carries_the_note_and_stays_ran(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _s, **_kw: NotedExecutor())
    headers = login(client, analyst.username)
    analysis = db.get(Analysis, uuid.UUID(_ingest(client, headers)))
    assert analysis is not None
    semgrep = next(run for run in analysis.tool_runs if run.tool == "semgrep")
    assert semgrep.status is ToolStatus.RAN
    assert semgrep.detail == "partial: 2 files; syntax=1 memory=0 timeout=1 other=0"
    assert analysis.findings, "the results are still read"
    gitleaks = next(run for run in analysis.tool_runs if run.tool == "gitleaks")
    assert gitleaks.detail is None

    html = client.get(
        f"/api/v1/analyses/{analysis.id}/report", params={"format": "html"}, headers=headers
    ).text
    assert "cobertura parcial: 2 archivos con reglas omitidas" in html
    assert "partial: 2 files" not in html


def test_the_report_words_every_machine_detail_and_passes_the_rest() -> None:
    assert tool_detail_text(None) == ""
    assert tool_detail_text("") == ""
    assert tool_detail_text("partial: 96 files; syntax=90 memory=6 timeout=0 other=0") == (
        "cobertura parcial: 96 archivos con reglas omitidas (90 por error de sintaxis, "
        "6 por memoria, 0 por tiempo, 0 por otra causa); los archivos de más de 2 MB no "
        "se analizan y esta nota no los cuenta"
    )
    assert tool_detail_text("output too large: 300 MiB > 256 MiB") == (
        "la salida de la herramienta pesa 300 MiB, más que el tope de 256 MiB, y no se interpretó"
    )
    assert tool_detail_text("output truncated and not parsed") == (
        "la salida de la herramienta llegó recortada y no se interpretó"
    )
    # Near misses and a tool's own message stay as they are.
    for other in (
        "exit 2: boom",
        "partial: x files",
        "output too large: 3 MiB",
        "partial: 2 files; syntax=1 memory=0 timeout=0 other=1 and more",
        "output too large: 3 MiB > 2 MiB, then some",
    ):
        assert tool_detail_text(other) == other


# --- mutation pass (1.5.1) ---------------------------------------------------------


def test_every_kind_is_counted_past_one_and_a_leading_note_is_only_skipped() -> None:
    note = execution_notes(
        _sarif(
            _note("Info", "ignored", level="note"),
            _note("Out of memory", "at /work/m1.js:1"),
            _note("Out of memory", "at /work/m2.js:1"),
            _note("Parse error", "at /work/p.js:1"),
            _note("Weird", "at /work/o1.js"),
            _note("Weird", "at /work/o2.js"),
            _note("Weird", "no path, first"),
            _note("Weird", "no path, second"),
        )
    )
    assert note == "partial: 7 files; syntax=1 memory=2 timeout=0 other=4"


def test_only_the_first_line_of_a_message_names_the_file() -> None:
    later = "Timeout on a rule\n/work/p.js\nmore"
    assert execution_notes(_sarif(_note("Timeout", later), _note("Timeout", later))) == (
        "partial: 2 files; syntax=0 memory=0 timeout=2 other=0"
    )


class RecordingExecutor(FixtureExecutor):
    """Semgrep and OSV declare drops; semgrep's raw row carries an exit code and stderr."""

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        result = super().run(spec, workspace=workspace, out_dir=out_dir)
        if spec.output_file in {"semgrep.sarif", "osv.sarif"}:
            document = json.loads(result.output or b"{}")
            document["runs"][0]["invocations"] = [
                {"toolExecutionNotifications": [_note("Timeout", f"on /work/{spec.tool}.js")]}
            ]
            body = json.dumps(document).encode()
            return ExecutionResult(ToolStatus.RAN, 1, "semgrep says hi", body, False, 7, None)
        if spec.output_file == "gitleaks.sarif":
            return ExecutionResult(ToolStatus.RAN, 0, "", b'{"not": "sarif"}', False, 3, None)
        if spec.output_file == "cloc.json":
            # A FAILED run whose document is present is still never collected.
            return ExecutionResult(
                ToolStatus.FAILED, 2, "", result.output, False, 4, "exit 2", document=result.output
            )
        return result


def test_the_raw_row_and_the_coverage_row_carry_the_run_as_it_was(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.analysis.pipeline.build_executor", lambda _s, **_kw: RecordingExecutor()
    )
    analysis = db.get(Analysis, uuid.UUID(_ingest(client, login(client, analyst.username))))
    assert analysis is not None
    runs = {run.tool: run for run in analysis.tool_runs}
    raw = {row.tool: row for row in analysis.raw_outputs}
    assert (raw["semgrep"].exit_code, raw["semgrep"].stderr) == (1, "semgrep says hi")
    assert raw["gitleaks"].stderr is None  # empty stderr is stored as nothing
    assert runs["semgrep"].duration_ms == 7
    assert runs["semgrep"].detail == "partial: 1 files; syntax=0 memory=0 timeout=1 other=0"
    # A report that is not SARIF is refused by name, never parsed as one.
    assert runs["gitleaks"].status is ToolStatus.FAILED
    assert runs["gitleaks"].detail == "output rejected: NormalizationError"
    # A failed run keeps its own detail, and its document is never read.
    assert (runs["cloc"].status, runs["cloc"].detail) == (ToolStatus.FAILED, "exit 2")
    assert analysis.metrics is None or not analysis.metrics.lines
    # Only Semgrep's drops are worded; the note never lands on another tool.
    for tool in ("osv-scanner", "syft", "lizard"):
        assert runs[tool].detail is None, tool
