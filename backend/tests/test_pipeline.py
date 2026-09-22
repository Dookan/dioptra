"""The whole pipeline over fixture tool outputs, with a fake executor.

Proves the invariants of docs/analysis-pipeline.md end to end: raw output
persisted, coverage rows for every tool, findings normalized and deduplicated,
the SBOM validated and stored once, metrics parsed, the report rendered with
the hostile snippet escaped.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.models import SEVERITY_ORDER, Analysis, AnalysisStatus, ToolStatus
from app.analysis.runners.base import ExecutionResult, RunnerSpec
from app.auth.models import User
from tests.conftest import SEED_PASSWORD

FIXTURES = Path(__file__).parent / "fixtures"

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {"type": "library", "name": "express", "version": "4.18.2"},
        {"type": "library", "name": "<img src=x onerror=alert(1)>", "version": "0.0.1"},
    ],
}


class FixtureExecutor:
    """Returns the committed fixture for each tool instead of running anything."""

    outputs: dict[str, bytes] = {
        "semgrep.sarif": (FIXTURES / "semgrep.sarif.json").read_bytes(),
        "gitleaks.sarif": (FIXTURES / "gitleaks.sarif.json").read_bytes(),
        "osv.sarif": (FIXTURES / "osv.sarif.json").read_bytes(),
        "sbom.cdx.json": json.dumps(SBOM).encode(),
        "lizard.csv": (FIXTURES / "lizard.csv").read_bytes(),
        "cloc.json": (FIXTURES / "cloc.json").read_bytes(),
    }

    def __init__(self) -> None:
        self.specs: list[RunnerSpec] = []

    def run(self, spec: RunnerSpec, *, workspace: Path, out_dir: Path) -> ExecutionResult:
        del workspace, out_dir
        self.specs.append(spec)
        output = self.outputs.get(spec.output_file)
        if output is None:
            return ExecutionResult(ToolStatus.FAILED, 2, "boom", None, False, 1, "exit 2")
        return ExecutionResult(ToolStatus.RAN, 0, "", output, False, 5, None)


def login(client: TestClient, username: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": SEED_PASSWORD}
    )
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def fixture_executor(monkeypatch: pytest.MonkeyPatch) -> FixtureExecutor:
    executor = FixtureExecutor()
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _settings: executor)
    return executor


def _ingest(client: TestClient, headers: dict[str, str]) -> str:
    project = client.post(
        "/api/v1/projects",
        json={"name": "fixture-project", "system": {"name": "sistema-fixture"}},
        headers=headers,
    ).json()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("index.js", "// const a = 1;\n// return b;\n// if (x) {\n")
        archive.writestr("package.json", "{}")
        # A scanned tree's own ignore file must never reach the scanner.
        archive.writestr(".gitleaksignore", "/work/index.js:generic-api-key:1\n")
    response = client.post(
        f"/api/v1/projects/{project['id']}/ingest",
        files={"file": ("src.zip", buffer.getvalue(), "application/zip")},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    analysis_id: str = response.json()["id"]
    return analysis_id


def test_pipeline_persists_everything(
    client: TestClient, analyst: User, db: Session, fixture_executor: FixtureExecutor
) -> None:
    headers = login(client, analyst.username)
    analysis_id = _ingest(client, headers)
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE, analysis.failure_code

    ran = {run.tool for run in analysis.tool_runs if run.status is ToolStatus.RAN}
    assert {"semgrep", "gitleaks", "syft", "lizard", "cloc"} <= ran
    # Raw output is stored for every tool that produced one, untouched.
    assert {raw.tool for raw in analysis.raw_outputs} >= {"semgrep", "gitleaks"}
    assert any(raw.output and b'"version"' in raw.output for raw in analysis.raw_outputs)

    assert analysis.findings, "fixture SARIF must yield findings"
    assert analysis.findings[0].ordinal == 0
    ranks = [SEVERITY_ORDER[finding.severity] for finding in analysis.findings]
    assert ranks == sorted(ranks)
    assert any(finding.cwe == 798 for finding in analysis.findings)

    assert analysis.sbom is not None
    assert analysis.sbom.spec_version == "1.6"
    assert analysis.sbom.component_count == 2
    assert analysis.metrics is not None
    assert analysis.metrics.functions
    assert analysis.metrics.commented_code_files == ["index.js"]

    # Every default runner spec is offline by construction.
    joined = " ".join(" ".join(spec.argv) for spec in fixture_executor.specs)
    assert "--metrics=off" in joined
    assert "--offline-vulnerabilities" in joined or "osv-scanner" not in joined


def test_report_escapes_hostile_content_from_the_tools(
    client: TestClient, analyst: User, fixture_executor: FixtureExecutor
) -> None:
    del fixture_executor
    headers = login(client, analyst.username)
    analysis_id = _ingest(client, headers)
    html = client.get(f"/api/v1/analyses/{analysis_id}/report?format=html", headers=headers)
    assert html.status_code == 200
    assert "<script>" not in html.text
    assert "HALLAZGOS DE VULNERABILIDADES" in html.text.upper()
    sbom = client.get(f"/api/v1/analyses/{analysis_id}/sbom", headers=headers)
    assert sbom.status_code == 200
    assert sbom.json()["specVersion"] == "1.6"
    findings = client.get(f"/api/v1/analyses/{analysis_id}/findings", headers=headers)
    assert findings.status_code == 200 and findings.json()


def test_raw_outputs_are_durable_before_normalization(
    client: TestClient,
    analyst: User,
    db: Session,
    fixture_executor: FixtureExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash INSIDE normalize() that is not an Exception (SIGKILL, OOM) must not lose
    the raw tool outputs or the coverage rows: they were committed before it ran."""
    del fixture_executor
    from app.analysis.pipeline import run_pipeline

    def explode(_reports: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("app.analysis.pipeline.normalize", explode)
    # Ingest without running: the job is invoked by hand so the interrupt does
    # not tear down the HTTP test client's portal.
    monkeypatch.setattr("app.ingest.service.enqueue_pipeline", lambda _id: None)
    headers = login(client, analyst.username)
    analysis_id = _ingest(client, headers)
    with pytest.raises(KeyboardInterrupt):
        run_pipeline(analysis_id)
    db.expire_all()
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.RUNNING
    assert {raw.tool for raw in analysis.raw_outputs} >= {"semgrep", "gitleaks"}
    assert len(analysis.tool_runs) >= 6


def test_no_security_tool_running_fails_closed(
    client: TestClient, analyst: User, db: Session, fixture_executor: FixtureExecutor
) -> None:
    """A deployment where every scanner is missing must not produce an empty DONE report."""
    fixture_executor.outputs = {
        "sbom.cdx.json": FixtureExecutor.outputs["sbom.cdx.json"],
        "cloc.json": FixtureExecutor.outputs["cloc.json"],
    }
    headers = login(client, analyst.username)
    analysis_id = _ingest(client, headers)
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.FAILED
    assert analysis.failure_code == "no_tool_ran"
    # Coverage rows and the SBOM survive the failure: nothing is lost.
    assert len(analysis.tool_runs) >= 6
    report = client.get(f"/api/v1/analyses/{analysis_id}/report", headers=headers)
    assert report.status_code == 409


def test_failed_tool_is_a_coverage_gap_not_a_crash(
    client: TestClient, analyst: User, db: Session, fixture_executor: FixtureExecutor
) -> None:
    fixture_executor.outputs = {
        "semgrep.sarif": b"{not sarif",
        "gitleaks.sarif": FixtureExecutor.outputs["gitleaks.sarif"],
    }
    headers = login(client, analyst.username)
    analysis_id = _ingest(client, headers)
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE
    statuses = {run.tool: run.status for run in analysis.tool_runs}
    assert statuses["semgrep"] is ToolStatus.FAILED
    assert statuses["gitleaks"] is ToolStatus.RAN
    assert statuses["syft"] is ToolStatus.FAILED
    assert all(finding.tools == ["gitleaks"] for finding in analysis.findings)


def test_findings_are_capped_worst_first_and_recorded(
    client: TestClient,
    analyst: User,
    db: Session,
    fixture_executor: FixtureExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tree built to hit a rule on every line must not produce an unbounded report."""
    del fixture_executor
    from app.analysis.models import Severity, ToolCategory
    from app.analysis.normalizer import NormalizedFinding
    from app.core.config import get_settings

    def flood(_reports: object) -> list[NormalizedFinding]:
        levels = [Severity.HIGH] * 120 + [Severity.LOW] * 30
        return [
            NormalizedFinding(
                category=ToolCategory.SAST,
                tools=("semgrep",),
                rule_id="flood",
                cwe=79,
                owasp="A03:2021",
                title="flood",
                severity=level,
                cvss_score=None,
                cvss_vector=None,
                path="a.js",
                line=index,
                snippet=None,
                message=None,
                advisory=None,
                references=(),
                fingerprint=f"{index:064x}",
            )
            for index, level in enumerate(levels)
        ]

    monkeypatch.setattr("app.analysis.pipeline.normalize", flood)
    capped = get_settings().model_copy(update={"max_findings_per_analysis": 100})
    monkeypatch.setattr("app.analysis.pipeline.get_settings", lambda: capped)
    headers = login(client, analyst.username)
    analysis_id = _ingest(client, headers)
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE
    assert len(analysis.findings) == 100
    assert all(finding.severity is Severity.HIGH for finding in analysis.findings)
    cap_row = next(run for run in analysis.tool_runs if run.tool == "normalizer")
    assert cap_row.detail is not None and "100 of 150" in cap_row.detail


def test_tree_level_scanner_override_files_are_removed_before_scanning(
    client: TestClient, analyst: User, db: Session, fixture_executor: FixtureExecutor
) -> None:
    del fixture_executor
    headers = login(client, analyst.username)
    analysis_id = _ingest(client, headers)
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None and analysis.workspace_path is not None
    assert not (Path(analysis.workspace_path) / ".gitleaksignore").exists()
    assert (Path(analysis.workspace_path) / "index.js").exists()
