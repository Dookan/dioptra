"""Phase 10: the ZIP arrives as a raw body, after auth, under a streamed cap.

`tasks/phase10-survey.md`. Every cap here is set SMALL so the suite proves the
mechanism on any host; the real numbers (1 GiB / 8 GiB / 300 000) are only
settings, pinned against nginx in `test_upload_caps.py`.
"""

from __future__ import annotations

import asyncio
import io
import stat
import uuid
import zipfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from app.analysis.models import Analysis, AnalysisStatus
from app.analysis.pipeline import run_pipeline
from app.auth.models import User
from app.core.config import get_settings
from app.ingest import upload
from app.ingest.errors import UploadInterrupted, UploadMissing, UploadTooLarge
from tests.conftest import SEED_PASSWORD

ZIP = {"Content-Type": "application/zip"}


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


def new_project(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/api/v1/projects",
        json={"name": f"p-{uuid.uuid4().hex[:8]}", "system": {"name": "s"}},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    project_id: str = response.json()["id"]
    return project_id


def tree_under(project_id: str) -> list[Path]:
    root = get_settings().workspace_root / project_id
    return sorted(root.rglob("*")) if root.exists() else []


@pytest.fixture
def small_cap(monkeypatch: pytest.MonkeyPatch) -> int:
    cap = 64 * 1024
    monkeypatch.setattr(get_settings(), "max_zip_bytes", cap)
    return cap


# --- authentication before the body ----------------------------------------


def test_anonymous_and_developer_are_refused_before_anything_is_spooled(
    client: TestClient, analyst: User, developer: User, db: Session
) -> None:
    project_id = new_project(client, login(client, analyst.username))
    archive = make_zip({"a.js": "1"})
    anonymous = client.post(f"/api/v1/projects/{project_id}/ingest", content=archive, headers=ZIP)
    assert anonymous.status_code == 401
    as_developer = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=archive,
        headers={**login(client, developer.username), **ZIP},
    )
    assert as_developer.status_code == 403
    assert tree_under(project_id) == []
    assert db.query(Analysis).filter(Analysis.project_id == uuid.UUID(project_id)).count() == 0


def test_multipart_is_refused_with_a_typed_415(client: TestClient, analyst: User) -> None:
    """The 1.x contract change: `curl -F` stops working, and says why."""
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        files={"file": ("src.zip", make_zip({"a.js": "1"}), "application/zip")},
        headers=headers,
    )
    assert response.status_code == 415
    assert response.json() == {
        "code": "upload_media_type_unsupported",
        "message_key": "errors.ingest.uploadMediaType",
    }
    assert tree_under(project_id) == []


@pytest.mark.parametrize(
    "media", ["application/zip", "application/x-zip-compressed", "application/octet-stream"]
)
def test_the_three_zip_media_types_are_accepted(
    client: TestClient, analyst: User, media: str
) -> None:
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=make_zip({"a.js": "1"}),
        headers={**headers, "Content-Type": f"{media}; charset=binary"},
    )
    assert response.status_code == 202, response.text


# --- the streamed cap ------------------------------------------------------


def test_a_chunked_body_over_the_cap_is_refused_and_leaves_nothing(
    client: TestClient, analyst: User, db: Session, small_cap: int
) -> None:
    """No Content-Length at all: only the counter can stop it."""
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)

    def body() -> Iterator[bytes]:
        for _ in range(small_cap // 1024 + 8):
            yield b"x" * 1024

    response = client.post(
        f"/api/v1/projects/{project_id}/ingest", content=body(), headers={**headers, **ZIP}
    )
    assert response.status_code == 413
    assert response.json() == {
        "code": "zip_too_large",
        "message_key": "errors.ingest.uploadTooLarge",
        "context": {"limit_mib": "0"},
    }
    assert tree_under(project_id) == []
    assert db.query(Analysis).filter(Analysis.project_id == uuid.UUID(project_id)).count() == 0


def test_a_declared_length_over_the_cap_names_the_limit(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "max_zip_bytes", 1024 * 1024 * 1024)
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=b"PK",
        headers={**headers, **ZIP, "Content-Length": str(1024 * 1024 * 1024 + 1)},
    )
    assert response.status_code == 413
    assert response.json()["context"] == {"limit_mib": "1024"}


def test_a_body_exactly_at_the_cap_is_accepted(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = make_zip({"a.js": "1"})
    monkeypatch.setattr(get_settings(), "max_zip_bytes", len(archive))
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest", content=archive, headers={**headers, **ZIP}
    )
    assert response.status_code == 202, response.text


def test_the_defaults_are_the_signed_numbers() -> None:
    """tasks/phase10-survey.md §4, as mmarin signed it."""
    from app.core.config import Settings

    fields = Settings.model_fields
    assert fields["max_zip_bytes"].default == 1024**3
    assert fields["max_unpacked_bytes"].default == 8 * 1024**3
    assert fields["max_zip_entries"].default == 300_000
    assert fields["max_zip_ratio"].default == 100


# --- the spool and the worker's extraction ----------------------------------


def test_a_successful_ingest_leaves_the_jail_and_no_spool(
    client: TestClient, analyst: User, db: Session
) -> None:
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=make_zip({"index.js": "const a = 1;\n", "package.json": "{}"}),
        params={"filename": "src.zip"},
        headers={**headers, **ZIP},
    )
    assert response.status_code == 202, response.text
    body = response.json()
    # Inline queue: the worker's extraction already ran and detected the tree.
    assert body["languages"] == {"JavaScript": 1}
    assert body["source_ref"] == "src.zip"
    analysis = db.get(Analysis, uuid.UUID(body["id"]))
    assert analysis is not None and analysis.workspace_path is not None
    jail = Path(analysis.workspace_path)
    assert (jail / "index.js").is_file()
    assert not (jail.parent / upload.UPLOAD_NAME).exists()


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("../../etc/passwd.zip", "passwd.zip"),
        ("C:\\Users\\x\\código.zip", "código.zip"),
        ("a\x00b\x1b[31m.zip", "ab[31m.zip"),
        ("   ", "upload.zip"),
        ("", "upload.zip"),
    ],
)
def test_the_file_name_is_a_label_never_a_path(raw: str, shown: str) -> None:
    assert upload.display_name(raw) == shown


def test_the_file_name_label_is_capped() -> None:
    assert len(upload.display_name("n" * 900 + ".zip")) == 255


def test_an_overlong_file_name_query_is_refused(client: TestClient, analyst: User) -> None:
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=make_zip({"a.js": "1"}),
        params={"filename": "x" * 2000},
        headers={**headers, **ZIP},
    )
    assert response.status_code == 422
    assert tree_under(project_id) == []


def test_a_hostile_file_name_never_becomes_a_path(
    client: TestClient, analyst: User, db: Session
) -> None:
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=make_zip({"a.js": "1"}),
        params={"filename": "../../../../tmp/owned.zip"},
        headers={**headers, **ZIP},
    )
    assert response.status_code == 202, response.text
    assert response.json()["source_ref"] == "owned.zip"
    # The name reached no path: nothing called owned.zip exists anywhere
    # under the workspaces root, the only tree the route writes to.
    root = get_settings().workspace_root
    assert not any(path.name == "owned.zip" for path in root.rglob("*"))


def test_the_spool_is_created_private(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / upload.UPLOAD_NAME
    with upload._open_spool(target):
        pass
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        upload._open_spool(target)


async def _chunks(parts: list[bytes], *, then: BaseException | None = None) -> AsyncIterator[bytes]:
    for part in parts:
        yield part
    if then is not None:
        raise then


def test_spool_counts_what_arrives_and_removes_a_refused_file(tmp_path: Path) -> None:
    target = tmp_path / "d" / upload.UPLOAD_NAME
    with pytest.raises(UploadTooLarge) as caught:
        asyncio.run(upload.spool_body(_chunks([b"a" * 600, b"b" * 600]), target, 1000))
    assert caught.value.context == {"limit_mib": "0"}
    assert not target.exists()
    ok = tmp_path / "e" / upload.UPLOAD_NAME
    # Big enough to cross the write batch more than once, and exactly the cap.
    size = upload._WRITE_BATCH * 2 + 17
    parts = [b"z" * 4096] * (size // 4096) + [b"z" * (size % 4096)]
    assert asyncio.run(upload.spool_body(_chunks(parts), ok, size)) == size
    assert ok.stat().st_size == size


def test_a_client_that_leaves_mid_upload_is_a_typed_refusal(tmp_path: Path) -> None:
    target = tmp_path / "f" / upload.UPLOAD_NAME
    with pytest.raises(UploadInterrupted):
        asyncio.run(upload.spool_body(_chunks([b"x" * 10], then=ClientDisconnect()), target, 99))
    assert not target.exists()


def test_extraction_without_a_spool_is_a_typed_failure(tmp_path: Path) -> None:
    with pytest.raises(UploadMissing):
        upload.extract_upload(tmp_path / "an" / "src", get_settings())


def test_extraction_removes_the_spool_even_when_it_refuses(tmp_path: Path) -> None:
    jail = tmp_path / "an" / "src"
    jail.parent.mkdir(parents=True)
    spool = jail.parent / upload.UPLOAD_NAME
    spool.write_bytes(b"not a zip at all")
    with pytest.raises(Exception, match="not a zip"):
        upload.extract_upload(jail, get_settings())
    assert not spool.exists()
    assert not jail.exists()


def test_the_worker_records_a_missing_spool_on_the_row(
    client: TestClient, analyst: User, db: Session
) -> None:
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    workspace = get_settings().workspace_root / project_id / "x" / "src"
    analysis = Analysis(
        project_id=uuid.UUID(project_id),
        source_kind="zip",
        source_ref="lost.zip",
        status=AnalysisStatus.QUEUED,
        workspace_path=str(workspace),
    )
    db.add(analysis)
    db.commit()
    run_pipeline(analysis.id)
    db.refresh(analysis)
    assert analysis.status is AnalysisStatus.FAILED
    assert analysis.failure_code == "upload_missing"


@pytest.mark.parametrize(
    ("files", "code"),
    [
        ({"../x.js": "1"}, "zip_slip_detected"),
        ({f"f{i}.js": "1" for i in range(6)}, "zip_too_many_entries"),
    ],
)
def test_worker_side_guards_fail_the_row_and_clean_the_disk(
    client: TestClient,
    analyst: User,
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, str],
    code: str,
) -> None:
    monkeypatch.setattr(get_settings(), "max_zip_entries", 5)
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=make_zip(files),
        headers={**headers, **ZIP},
    )
    assert response.status_code == 202, response.text
    body: dict[str, Any] = response.json()
    assert (body["status"], body["failure_code"]) == ("failed", code)
    assert tree_under(project_id) == []


# --- the vulnerability-dump import: auth before the form ---------------------


def test_the_dump_import_refuses_an_anonymous_caller_before_reading_the_form(
    client: TestClient,
) -> None:
    spool_dir = get_settings().vulndb_spool_dir
    before = set(spool_dir.iterdir()) if spool_dir.exists() else set()
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("all.zip", b"PK", "application/zip")},
        data={"justification": "sin sesión, no debería llegar"},
    )
    assert response.status_code == 401
    after = set(spool_dir.iterdir()) if spool_dir.exists() else set()
    assert after == before


@pytest.mark.parametrize(
    "data",
    [
        {},  # no justification
        {"justification": "x" * 8001},  # over the cap Form() used to carry
    ],
)
def test_the_dump_import_still_validates_its_form(
    client: TestClient, analyst: User, data: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("all.zip", b"PK", "application/zip")},
        data=data,
        headers=login(client, analyst.username),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"


def test_the_dump_import_without_a_file_is_refused(client: TestClient, analyst: User) -> None:
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        data={"justification": "Falta el archivo del volcado"},
        headers=login(client, analyst.username),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"


# --- mutation pass (phase-10 close): behaviour the first suite left unpinned ---


def test_the_spool_opens_inside_a_directory_that_already_exists(tmp_path: Path) -> None:
    """The analysis directory may exist before the spool (the jail's parent)."""
    with upload._open_spool(tmp_path / upload.UPLOAD_NAME):
        pass
    assert (tmp_path / upload.UPLOAD_NAME).is_file()


def test_discarding_a_directory_that_never_existed_is_quiet(tmp_path: Path) -> None:
    """The route discards on EVERY failure, including before anything was written."""
    upload.discard(tmp_path / "never" / "created")


def test_a_jail_that_already_exists_is_refused_not_analysed(tmp_path: Path) -> None:
    """Only the worker extracts, once per claimed row: an existing jail is a half
    extraction a killed worker left behind, never a tree to analyse
    (`tasks/hardening-1.5.1-survey.md` §11.10b). The spool beside it is dropped."""
    jail = tmp_path / "an" / "src"
    jail.mkdir(parents=True)
    (jail / "index.js").write_text("const a = 1;\n", encoding="utf-8")
    spool = jail.parent / upload.UPLOAD_NAME
    spool.write_bytes(b"PK")
    with pytest.raises(UploadMissing, match="already exists"):
        upload.extract_upload(jail, get_settings())
    assert not spool.exists()


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (  # two file parts where one is allowed
            b'--B\r\nContent-Disposition: form-data; name="file"; filename="a.zip"\r\n\r\nPK\r\n'
            b'--B\r\nContent-Disposition: form-data; name="file"; filename="b.zip"\r\n\r\nPK\r\n'
            b"--B--\r\n",
            "multipart/form-data; boundary=B",
        ),
        (b"whatever", "multipart/form-data"),  # no boundary at all
    ],
)
def test_an_unreadable_dump_form_answers_in_the_error_contract(
    client: TestClient, analyst: User, body: bytes, content_type: str
) -> None:
    """Starlette answers these with its own 400 `detail`; ours is `{code, message_key}`."""
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        content=body,
        headers={**login(client, analyst.username), "Content-Type": content_type},
    )
    assert response.status_code == 422
    assert response.json() == {"code": "validation_failed", "message_key": "errors.validation"}


def _body_messages_pulled(
    app: Any, path: str, headers: dict[str, str], chunks: int = 50
) -> tuple[int, int]:
    """Drive the ASGI app directly and count how many body messages it READ.

    The disk-and-rows assertions above cannot see a regression that reads the
    body into memory before authenticating (a `File()` parameter coming back);
    this can (QA panel, phase 10).
    """
    pulled = 0
    status = 0

    async def receive() -> dict[str, Any]:
        nonlocal pulled
        pulled += 1
        return {"type": "http.request", "body": b"x" * 1024, "more_body": pulled < chunks}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 5000),
        "server": ("testserver", 80),
        "root_path": "",
    }
    asyncio.run(app(scope, receive, send))
    return status, pulled


def test_a_refused_caller_never_has_a_byte_of_its_body_read(
    app: Any, client: TestClient, analyst: User, developer: User
) -> None:
    project_id = new_project(client, login(client, analyst.username))
    ingest = f"/api/v1/projects/{project_id}/ingest"
    as_developer = login(client, developer.username)
    assert _body_messages_pulled(app, ingest, ZIP) == (401, 0)
    assert _body_messages_pulled(app, ingest, {**as_developer, **ZIP}) == (403, 0)
    form = {"Content-Type": "multipart/form-data; boundary=B"}
    dump = "/api/v1/inventory/vulndb/import"
    assert _body_messages_pulled(app, dump, form) == (401, 0)
    assert _body_messages_pulled(app, dump, {**as_developer, **form}) == (403, 0)


def test_a_second_file_in_the_dump_form_is_refused_even_with_a_reason(
    client: TestClient, analyst: User
) -> None:
    """With the justification present, only the file cap can refuse this body."""
    body = (
        b'--B\r\nContent-Disposition: form-data; name="justification"\r\n\r\n'
        b"una razon suficiente\r\n"
        b'--B\r\nContent-Disposition: form-data; name="file"; filename="a.zip"\r\n\r\nPK\r\n'
        b'--B\r\nContent-Disposition: form-data; name="file"; filename="b.zip"\r\n\r\nPK\r\n'
        b"--B--\r\n"
    )
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        content=body,
        headers={
            **login(client, analyst.username),
            "Content-Type": "multipart/form-data; boundary=B",
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"


def _broker_down(*_args: object, **_kwargs: object) -> None:
    raise ConnectionError("valkey unreachable")


def test_a_broker_outage_closes_the_zip_analysis_instead_of_stranding_it(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase-10 panel: the row used to stay QUEUED forever with its archive gone."""
    monkeypatch.setattr("app.ingest.service.enqueue_pipeline", _broker_down)
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest",
        content=make_zip({"a.js": "1"}),
        headers={**headers, **ZIP},
    )
    assert response.status_code == 503
    assert response.json() == {
        "code": "analysis_enqueue_failed",
        "message_key": "errors.ingest.enqueueFailed",
    }
    rows = db.query(Analysis).filter(Analysis.project_id == uuid.UUID(project_id)).all()
    assert [(row.status, row.failure_code) for row in rows] == [
        (AnalysisStatus.FAILED, "analysis_enqueue_failed")
    ]
    assert tree_under(project_id) == []


def test_a_broker_outage_closes_the_git_analysis_too(
    client: TestClient, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.ingest.service.enqueue_pipeline", _broker_down)
    monkeypatch.setattr("app.ingest.service.validate_repository_url", lambda url: url)
    headers = login(client, analyst.username)
    project_id = new_project(client, headers)
    response = client.post(
        f"/api/v1/projects/{project_id}/ingest/git",
        json={"url": "https://example.org/team/repo.git"},
        headers=headers,
    )
    assert response.status_code == 503
    assert response.json()["code"] == "analysis_enqueue_failed"
    rows = db.query(Analysis).filter(Analysis.project_id == uuid.UUID(project_id)).all()
    assert [(row.status, row.failure_code) for row in rows] == [
        (AnalysisStatus.FAILED, "analysis_enqueue_failed")
    ]


def test_an_existing_jail_with_no_spool_beside_it_is_refused_too(tmp_path: Path) -> None:
    jail = tmp_path / "an" / "src"
    jail.mkdir(parents=True)
    with pytest.raises(UploadMissing, match="already exists"):
        upload.extract_upload(jail, get_settings())
