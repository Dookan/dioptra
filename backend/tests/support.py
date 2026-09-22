"""Shared builders for API tests that need a finished analysis with findings.

Rows are written straight to the database: the pipeline is exercised in
``test_pipeline.py``; here the subject is what happens AFTER it.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.models import (
    Analysis,
    AnalysisStatus,
    CodeMetrics,
    Finding,
    Severity,
    SourceKind,
    ToolCategory,
    ToolRun,
    ToolStatus,
)
from app.projects.models import Project, System
from tests.conftest import SEED_PASSWORD

HOSTILE_TITLE = "<script>alert('title')</script>"
HOSTILE_SNIPPET = "<img src=x onerror=alert(1)>"


def login(client: TestClient, username: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": SEED_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def make_finding(ordinal: int, **overrides: object) -> Finding:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "ordinal": ordinal,
        "category": ToolCategory.SAST,
        "tools": ["semgrep"],
        "rule_id": f"dioptra.rule-{ordinal}",
        "cwe": 79,
        "owasp": "A03:2021",
        "title": f"Hallazgo {ordinal}",
        "severity": Severity.HIGH,
        "path": f"src/file-{ordinal}.js",
        "line": 10 + ordinal,
        "snippet": None,
        "message": None,
        "advisory": None,
        "references": [],
        "fingerprint": f"{ordinal:064x}",
    }
    base.update(overrides)
    return Finding(**base)


FUNCTIONS: list[dict[str, object]] = [
    {"path": "src/file-0.js", "function": "validateForm", "line": 10, "nloc": 40, "ccn": 12},
    {"path": "src/billing.js", "function": "calculateDiscount", "line": 20, "nloc": 18, "ccn": 5},
    {"path": "src/utils.js", "function": "formatDate", "line": 3, "nloc": 6, "ccn": 2},
]


def write_stub_sources(jail: Path, functions: list[dict[str, object]]) -> None:
    """One trivial function per Lizard row, at its line, so E4 can parse what it plans."""
    by_path: dict[str, list[dict[str, object]]] = {}
    for row in functions:
        by_path.setdefault(str(row["path"]), []).append(row)
    for path, rows in by_path.items():
        lines: list[str] = []
        for row in sorted(rows, key=lambda r: int(str(r.get("line") or 1))):
            name = str(row["function"]).rsplit("::", 1)[-1]
            start = int(str(row.get("line") or 1))
            while len(lines) < start - 1:
                lines.append("")
            if path.endswith(".py"):
                lines += [f"def {name}(x):", "    return x", ""]
            else:
                lines += [f"function {name}(x) {{", "  return x;", "}", ""]
        target = jail / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines))


def seed_done_analysis(
    db: Session,
    findings: list[Finding],
    *,
    status: AnalysisStatus = AnalysisStatus.DONE,
    functions: list[dict[str, object]] | None = None,
    jail: Path | None = None,
) -> Analysis:
    """A project with one analysis carrying ``findings``, three RAN tools and Lizard rows.

    With ``jail``, stub sources for every Lizard row are written there and the
    analysis points at it, so a test plan can be saved (E4 parses its functions).
    """
    project = Project(name=f"proyecto-{uuid.uuid4().hex[:8]}")
    project.system = System(name="Sistema de prueba", framework="Express")
    db.add(project)
    db.flush()
    analysis = Analysis(
        project_id=project.id,
        source_kind=SourceKind.ZIP,
        source_ref="src.zip",
        status=status,
        languages={"JavaScript": 3},
        frameworks=["Express"],
        lockfiles=["package-lock.json"],
    )
    analysis.findings = findings
    analysis.tool_runs = [
        ToolRun(tool="semgrep", category=ToolCategory.SAST, status=ToolStatus.RAN),
        ToolRun(tool="gitleaks", category=ToolCategory.SECRET, status=ToolStatus.RAN),
        ToolRun(tool="osv-scanner", category=ToolCategory.SCA, status=ToolStatus.RAN),
    ]
    rows = FUNCTIONS if functions is None else functions
    analysis.metrics = CodeMetrics(functions=rows, lines={}, commented_code_files=[])
    if jail is not None:
        write_stub_sources(jail, rows)
        analysis.workspace_path = str(jail)
    db.add(analysis)
    db.commit()
    return analysis
