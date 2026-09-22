"""Shared builders for API tests that need a finished analysis with findings.

Rows are written straight to the database: the pipeline is exercised in
``test_pipeline.py``; here the subject is what happens AFTER it.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.models import (
    Analysis,
    AnalysisStatus,
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


def seed_done_analysis(db: Session, findings: list[Finding]) -> Analysis:
    """A project with one DONE analysis carrying ``findings`` and three RAN tools."""
    project = Project(name=f"proyecto-{uuid.uuid4().hex[:8]}")
    project.system = System(name="Sistema de prueba", framework="Express")
    db.add(project)
    db.flush()
    analysis = Analysis(
        project_id=project.id,
        source_kind=SourceKind.ZIP,
        source_ref="src.zip",
        status=AnalysisStatus.DONE,
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
    db.add(analysis)
    db.commit()
    return analysis
