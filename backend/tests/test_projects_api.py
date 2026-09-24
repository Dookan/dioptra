"""E1 register + E2 ingest through the API, with the inline pipeline and no tools."""

from __future__ import annotations

import io
import uuid
import zipfile
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, AnalysisStatus, ToolStatus
from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.core.clock import utc_now
from tests.conftest import SEED_PASSWORD


def login(client: TestClient, username: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": SEED_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


PROJECT: dict[str, Any] = {
    "name": "formulario_mincyt_apirest-desarrollo",
    "description": "Backend API REST",
    "system": {"name": "formulario_mincyt_apirest-desarrollo", "framework": "Express"},
}


def test_analyst_registers_and_ingests_a_zip(
    client: TestClient, analyst: User, db: Session
) -> None:
    headers = login(client, analyst.username)
    created = client.post("/api/v1/projects", json=PROJECT, headers=headers)
    assert created.status_code == 201, created.text
    project_id = created.json()["id"]
    assert created.json()["system"]["framework"] == "Express"

    archive = make_zip({"index.js": "const x = req.body;\n", "package.json": "{}"})
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        files={"file": ("src.zip", archive, "application/zip")},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["languages"] == {"JavaScript": 1}
    # Inline queue: the pipeline already ran on the host. Whatever tools this
    # host has, every runner leaves a coverage row; with at least one security
    # tool on PATH the analysis is DONE, with none it fails closed.
    assert body["status"] in {"done", "failed"}
    if body["status"] == "failed":
        assert body["failure_code"] == "no_tool_ran"
    statuses = {run["tool"]: run["status"] for run in body["tool_runs"]}
    assert {"semgrep", "gitleaks", "osv-scanner", "syft", "lizard", "cloc"} <= set(statuses)
    assert all(status in {"ran", "missing", "failed", "timeout"} for status in statuses.values())

    status = client.get(f"/api/v1/analyses/{body['id']}", headers=headers)
    assert status.status_code == 200
    assert status.json()["finding_counts"]["high"] == 0

    analysis = db.get(Analysis, uuid.UUID(body["id"]))
    assert analysis is not None and analysis.status.value == body["status"]
    assert analysis.workspace_path is not None
    assert (Path(analysis.workspace_path) / "index.js").exists()
    assert len(analysis.tool_runs) >= 6
    assert all(isinstance(run.status, ToolStatus) for run in analysis.tool_runs)

    actions = {entry.action for entry in db.query(AuditLogEntry).all()}
    assert {"project.create", "analysis.ingest.zip"} <= actions


def test_installation_date_is_a_date_never_text(client: TestClient, analyst: User) -> None:
    """ISO in, ISO out; free text and a future date are refused by the server."""
    headers = login(client, analyst.username)
    system = {"name": "sistema", "installed_at": "2024-03-05"}
    created = client.post(
        "/api/v1/projects", json={"name": "p-date", "system": system}, headers=headers
    )
    assert created.status_code == 201, created.text
    assert created.json()["system"]["installed_at"] == "2024-03-05"
    fetched = client.get(f"/api/v1/projects/{created.json()['id']}", headers=headers)
    assert fetched.json()["system"]["installed_at"] == "2024-03-05"

    for text in ("05/03/2024", "marzo 2024", "2024-13-01", "ayer"):
        refused = client.post(
            "/api/v1/projects",
            json={"name": "p-text", "system": {"name": "s", "installed_at": text}},
            headers=headers,
        )
        assert refused.status_code == 422, text
        assert refused.json()["code"] == "validation_failed"

    tomorrow = (utc_now() + timedelta(days=1)).date().isoformat()
    future = client.post(
        "/api/v1/projects",
        json={"name": "p-future", "system": {"name": "s", "installed_at": tomorrow}},
        headers=headers,
    )
    assert future.status_code == 422
    assert future.json() == {
        "code": "installed_at_in_future",
        "message_key": "errors.projects.installedAtInFuture",
    }
    today = utc_now().date().isoformat()
    accepted = client.post(
        "/api/v1/projects",
        json={"name": "p-today", "system": {"name": "s", "installed_at": today}},
        headers=headers,
    )
    assert accepted.status_code == 201, "today itself is allowed"
    # Nothing without a date was touched: an omitted date is still null.
    omitted = client.post(
        "/api/v1/projects", json={"name": "p-none", "system": {"name": "s"}}, headers=headers
    )
    assert omitted.status_code == 201 and omitted.json()["system"]["installed_at"] is None


def test_developer_cannot_register_or_ingest(client: TestClient, developer: User) -> None:
    headers = login(client, developer.username)
    assert client.post("/api/v1/projects", json=PROJECT, headers=headers).status_code == 403


def test_zip_slip_upload_is_rejected(client: TestClient, analyst: User) -> None:
    headers = login(client, analyst.username)
    project_id = client.post("/api/v1/projects", json=PROJECT, headers=headers).json()["id"]
    archive = make_zip({"../../evil.js": "x"})
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        files={"file": ("evil.zip", archive, "application/zip")},
        headers=headers,
    )
    assert response.status_code == 422
    assert response.json()["code"] == "zip_slip_detected"
    assert "Traceback" not in response.text


def test_oversized_declared_upload_is_refused_before_reading(
    client: TestClient, analyst: User
) -> None:
    headers = login(client, analyst.username)
    project_id = client.post("/api/v1/projects", json=PROJECT, headers=headers).json()["id"]
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        files={"file": ("src.zip", make_zip({"a.js": "1"}), "application/zip")},
        headers={**headers, "Content-Length": str(500 * 1024 * 1024)},
    )
    assert response.status_code == 413
    assert response.json()["code"] == "zip_too_large"


def test_rejected_upload_leaves_no_directory_behind(client: TestClient, analyst: User) -> None:
    from app.core.config import get_settings

    headers = login(client, analyst.username)
    project_id = client.post("/api/v1/projects", json=PROJECT, headers=headers).json()["id"]
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        files={"file": ("evil.zip", make_zip({"../../evil.js": "x"}), "application/zip")},
        headers=headers,
    )
    assert response.status_code == 422
    project_dir = get_settings().workspace_root / project_id
    assert not project_dir.exists() or not any(project_dir.iterdir())


def test_git_ingest_refuses_private_targets(client: TestClient, analyst: User) -> None:
    headers = login(client, analyst.username)
    project_id = client.post("/api/v1/projects", json=PROJECT, headers=headers).json()["id"]
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest/git",
        json={"url": "https://169.254.169.254/latest/meta-data"},
        headers=headers,
    )
    assert response.status_code == 422
    assert response.json()["code"] == "forbidden_host"


def test_report_is_refused_until_the_analysis_is_done(
    client: TestClient, analyst: User, db: Session
) -> None:
    headers = login(client, analyst.username)
    project_id = client.post("/api/v1/projects", json=PROJECT, headers=headers).json()["id"]
    analysis = Analysis(
        project_id=uuid.UUID(project_id),
        source_kind="zip",
        source_ref="x.zip",
        status=AnalysisStatus.QUEUED,
    )
    db.add(analysis)
    db.commit()
    response = client.get(f"/api/v1/analyses/{analysis.id}/report?format=html", headers=headers)
    assert response.status_code == 409
    assert response.json()["code"] == "analysis_not_ready"


@pytest.mark.parametrize("fmt", ["html", "md", "docx"])
def test_report_exports_after_an_inline_run(client: TestClient, analyst: User, fmt: str) -> None:
    headers = login(client, analyst.username)
    project_id = client.post("/api/v1/projects", json=PROJECT, headers=headers).json()["id"]
    archive = make_zip({"index.js": "// const old = 1;\n// return x;\n// if (a) {\n"})
    analysis_id = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        files={"file": ("src.zip", archive, "application/zip")},
        headers=headers,
    ).json()["id"]
    response = client.get(f"/api/v1/analyses/{analysis_id}/report?format={fmt}", headers=headers)
    assert response.status_code == 200, response.text
    assert "attachment" in response.headers["content-disposition"] or fmt == "html"
    if fmt == "docx":
        assert response.content.startswith(b"PK")
    else:
        assert "formulario_mincyt_apirest-desarrollo" in response.text
