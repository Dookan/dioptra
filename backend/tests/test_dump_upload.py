"""The vulnerability-dump import, parsed part by part straight to disk.

`tasks/phase10-survey.md` → Addendum A. The contract is unchanged (multipart,
`file` + `justification`, 202 `{token}`); these tests pin what changed under
it: the file never passes through the API's temporary directory, exactly two
parts are accepted, and every refusal leaves neither a spool file nor an
audit row.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.core.config import get_settings
from app.ingest.errors import UploadInterrupted
from app.inventory import dump_upload
from app.inventory.errors import DumpTooLarge
from tests.conftest import SEED_PASSWORD

ROUTE = "/api/v1/inventory/vulndb/import"
BOUNDARY = "dioptra-test-boundary"
FORM = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
REASON = "Equipo sin salida a internet: se importa el archivo a mano"
#: The opening of a `file` part, for bodies that stream its data separately.
FILE_HEAD = (
    f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="a.zip"\r\n\r\n'
).encode()


def login(client: TestClient, username: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": SEED_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def part(name: str, value: bytes, filename: str | None = None) -> bytes:
    disposition = f'form-data; name="{name}"'
    if filename is not None:
        disposition += f'; filename="{filename}"'
    return f"--{BOUNDARY}\r\nContent-Disposition: {disposition}\r\n\r\n".encode() + value + b"\r\n"


def body(*parts: bytes) -> bytes:
    return b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()


def spool_files() -> set[Path]:
    root = get_settings().vulndb_spool_dir
    return set(root.iterdir()) if root.exists() else set()


def import_requests(db: Session) -> int:
    return db.query(AuditLogEntry).filter(AuditLogEntry.action == "vulndb.import.request").count()


@pytest.fixture
def queued(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Capture the enqueue instead of running the import inline: the spool stays."""
    seen: list[tuple[str, str]] = []

    def capture(token: str, kind: str, _actor: str) -> None:
        seen.append((token, kind))

    monkeypatch.setattr("app.core.queue.enqueue_import", capture)
    return seen


# --- accepted ---------------------------------------------------------------


@pytest.mark.parametrize("reason_first", [True, False])
def test_the_dump_lands_on_disk_byte_for_byte_whatever_the_part_order(
    client: TestClient,
    analyst: User,
    db: Session,
    queued: list[tuple[str, str]],
    reason_first: bool,
) -> None:
    payload = b"PK\x03\x04" + bytes(range(256)) * 50
    reason = part("justification", REASON.encode())
    dump = part("file", payload, "npm-all.zip")
    response = client.post(
        ROUTE,
        content=body(reason, dump) if reason_first else body(dump, reason),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    token = response.json()["token"]
    assert queued == [(token, "osv-zip")]
    spool = get_settings().vulndb_spool_dir / f"{token}.zip"
    assert spool.read_bytes() == payload
    row = db.query(AuditLogEntry).filter(AuditLogEntry.action == "vulndb.import.request").one()
    assert (row.target, row.justification) == (f"osv-zip:{token}", REASON)
    spool.unlink()


def test_the_file_never_passes_through_starlettes_spooling(
    client: TestClient,
    analyst: User,
    queued: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`request.form()` rolled anything over 1 MiB into /tmp — RAM, in Compose.

    Its temporary files are unlinked at once, so listing /tmp proves nothing:
    instead, the class Starlette spools into is made to fail. A route that
    goes back to `request.form()` or `File()` fails this test.
    """

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the dump went through Starlette's SpooledTemporaryFile")

    monkeypatch.setattr("starlette.formparsers.SpooledTemporaryFile", forbidden)
    payload = b"PK" + b"x" * (3 * 1024 * 1024)
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), part("file", payload, "big.zip")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    spool = get_settings().vulndb_spool_dir / f"{queued[0][0]}.zip"
    assert spool.stat().st_size == len(payload)
    spool.unlink()


def test_the_file_name_decides_only_the_kind_never_the_path(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    response = client.post(
        ROUTE,
        content=body(
            part("justification", REASON.encode()),
            part("file", b'{"CVE_Items": []}', "../../../etc/nvdcve-2.0-2026.json.gz"),
        ),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    token, kind = queued[0]
    assert kind == "nvd-json-gz"
    spool = get_settings().vulndb_spool_dir / f"{token}.json.gz"
    assert spool.is_file()
    assert not Path("/etc/nvdcve-2.0-2026.json.gz").exists()
    spool.unlink()


# --- refused, and nothing left behind ---------------------------------------


REFUSALS = {
    "a third part": (
        body(
            part("justification", REASON.encode()),
            part("file", b"PK", "a.zip"),
            part("extra", b"x"),
        ),
        422,
        "validation_failed",
    ),
    "a repeated file": (
        body(
            part("justification", REASON.encode()),
            part("file", b"PK", "a.zip"),
            part("file", b"PK", "b.zip"),
        ),
        422,
        "validation_failed",
    ),
    "an unknown part name": (
        body(part("reason", REASON.encode()), part("file", b"PK", "a.zip")),
        422,
        "validation_failed",
    ),
    "no justification": (body(part("file", b"PK", "a.zip")), 422, "validation_failed"),
    "no file": (body(part("justification", REASON.encode())), 422, "validation_failed"),
    "an empty file": (
        body(part("justification", REASON.encode()), part("file", b"", "a.zip")),
        422,
        "dump_invalid",
    ),
    "a justification over the cap": (
        body(part("justification", b"x" * 8001), part("file", b"PK", "a.zip")),
        422,
        "validation_failed",
    ),
    "a justification under the floor": (
        body(part("justification", b"corta"), part("file", b"PK", "a.zip")),
        422,
        "justification_required",
    ),
    "an unknown file kind": (
        body(part("justification", REASON.encode()), part("file", b"PK", "a.tar")),
        422,
        "dump_kind_unknown",
    ),
    "a body that is not multipart at all": (b"--nothing here--", 422, "validation_failed"),
}


@pytest.mark.parametrize("case", list(REFUSALS))
def test_every_refusal_leaves_no_spool_and_no_audit_row(
    client: TestClient, analyst: User, db: Session, queued: list[tuple[str, str]], case: str
) -> None:
    content, status, code = REFUSALS[case]
    before = spool_files()
    response = client.post(
        ROUTE, content=content, headers={**login(client, analyst.username), **FORM}
    )
    assert (response.status_code, response.json()["code"]) == (status, code), case
    assert "message_key" in response.json()
    assert spool_files() == before
    assert import_requests(db) == 0
    assert queued == []


def test_a_multipart_body_without_a_boundary_is_refused_before_reading(
    client: TestClient, analyst: User
) -> None:
    response = client.post(
        ROUTE,
        content=body(part("file", b"PK", "a.zip")),
        headers={**login(client, analyst.username), "Content-Type": "multipart/form-data"},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"


def test_a_chunked_dump_over_the_cap_is_cut_and_leaves_nothing(
    client: TestClient,
    analyst: User,
    db: Session,
    queued: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "vulndb_max_dump_bytes", 64 * 1024)
    before = spool_files()

    def chunks() -> Iterator[bytes]:
        yield part("justification", REASON.encode())
        yield FILE_HEAD
        for _ in range(200):
            yield b"x" * 1024

    response = client.post(
        ROUTE, content=chunks(), headers={**login(client, analyst.username), **FORM}
    )
    assert response.status_code == 413
    assert response.json()["code"] == "dump_too_large"
    assert spool_files() == before
    assert import_requests(db) == 0


def test_a_declared_length_over_the_cap_is_refused_before_reading(
    client: TestClient, analyst: User
) -> None:
    cap = get_settings().vulndb_max_dump_bytes
    response = client.post(
        ROUTE,
        content=b"x",
        headers={
            **login(client, analyst.username),
            **FORM,
            "Content-Length": str(cap + 2 * 1024 * 1024),
        },
    )
    assert response.status_code == 413
    assert response.json()["code"] == "dump_too_large"


def test_the_default_cap_is_one_gib() -> None:
    from app.core.config import Settings

    assert Settings.model_fields["vulndb_max_dump_bytes"].default == 1024**3


async def _stream(parts: list[bytes], *, then: BaseException | None = None) -> AsyncIterator[bytes]:
    for chunk in parts:
        yield chunk
    if then is not None:
        raise then


def test_a_client_that_leaves_mid_file_leaves_nothing(tmp_path: Path) -> None:
    settings = get_settings().model_copy(update={"vulndb_spool_dir": tmp_path})
    with pytest.raises(UploadInterrupted):
        asyncio.run(
            dump_upload.receive_dump(
                _stream([FILE_HEAD, b"PK" * 1000], then=ClientDisconnect()),
                BOUNDARY.encode(),
                "t0",
                settings,
            )
        )
    assert list(tmp_path.iterdir()) == []


def test_the_cap_is_checked_on_what_arrives(tmp_path: Path) -> None:
    settings = get_settings().model_copy(
        update={"vulndb_spool_dir": tmp_path, "vulndb_max_dump_bytes": 1000}
    )
    with pytest.raises(DumpTooLarge):
        asyncio.run(
            dump_upload.receive_dump(
                _stream([FILE_HEAD, b"x" * 600, b"x" * 600]),
                BOUNDARY.encode(),
                "t1",
                settings,
            )
        )
    assert list(tmp_path.iterdir()) == []


def test_a_spool_is_private(tmp_path: Path) -> None:
    import stat

    target = tmp_path / "v" / "t.zip"
    with dump_upload._open_spool(target):
        pass
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        dump_upload._open_spool(target)


def test_a_broker_outage_removes_the_streamed_dump(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(*_args: Any) -> None:
        raise ConnectionError("valkey unreachable")

    monkeypatch.setattr("app.core.queue.enqueue_import", down)
    before = spool_files()
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), part("file", b"PK", "a.zip")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "vulndb_enqueue_failed"
    assert spool_files() == before


# --- mutation pass (addendum A close): edges the first suite left unpinned ---


def test_a_file_arriving_in_many_small_pieces_is_stored_whole(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    """Several parser callbacks between two disk writes must all be kept."""
    payload = bytes(range(256)) * 40

    def chunks() -> Iterator[bytes]:
        yield part("justification", REASON.encode())
        yield FILE_HEAD
        for start in range(0, len(payload), 97):
            yield payload[start : start + 97]
        yield f"\r\n--{BOUNDARY}--\r\n".encode()

    response = client.post(
        ROUTE, content=chunks(), headers={**login(client, analyst.username), **FORM}
    )
    assert response.status_code == 202, response.text
    spool = get_settings().vulndb_spool_dir / f"{queued[0][0]}.zip"
    assert spool.read_bytes() == payload
    spool.unlink()


def test_a_file_exactly_at_the_cap_is_accepted(
    client: TestClient,
    analyst: User,
    queued: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"PK" + b"z" * 998
    monkeypatch.setattr(get_settings(), "vulndb_max_dump_bytes", len(payload))
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), part("file", payload, "a.zip")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    (get_settings().vulndb_spool_dir / f"{queued[0][0]}.zip").unlink()


def test_the_transport_cap_on_the_reason_is_its_byte_bound_exactly(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    """8 000 four-byte characters sit exactly on the byte bound the transport
    cap implies, so they PASS the stream and meet the audit's own 4 000-character
    ceiling (`clean_justification`), which answers `justification_required`.
    One byte more is the stream's refusal, `validation_failed`."""
    exact = "\N{GRINNING FACE}" * 8000
    response = client.post(
        ROUTE,
        content=body(part("justification", exact.encode()), part("file", b"PK", "a.zip")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert (response.status_code, response.json()["code"]) == (422, "justification_required")
    over = client.post(
        ROUTE,
        content=body(part("justification", exact.encode() + b"x"), part("file", b"PK", "a.zip")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert (over.status_code, over.json()["code"]) == (422, "validation_failed")
    assert queued == []


def test_a_file_part_without_a_file_name_is_an_unknown_kind(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    before = spool_files()
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), part("file", b"PK")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert (response.status_code, response.json()["code"]) == (422, "dump_kind_unknown")
    assert spool_files() == before
    assert queued == []


def test_the_spool_directory_is_created_however_deep(tmp_path: Path) -> None:
    target = tmp_path / "data" / "vulndb" / "t.zip"
    with dump_upload._open_spool(target):
        pass
    assert target.is_file()


def test_a_file_name_that_is_not_utf8_is_read_by_its_extension(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    """Hostile bytes in the name are replaced, never raised on: the kind is the extension."""
    file_part = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="'.encode()
        + b"\xff\xfe\xfd.zip"
        + b'"\r\n\r\nPK\r\n'
    )
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), file_part),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    assert queued[0][1] == "osv-zip"
    (get_settings().vulndb_spool_dir / f"{queued[0][0]}.zip").unlink()


# --- addendum panel: truncation, header count, cancellation, audit failure ---


def test_a_body_without_its_closing_boundary_is_refused_not_queued_truncated(
    client: TestClient, analyst: User, db: Session, queued: list[tuple[str, str]]
) -> None:
    before = spool_files()
    truncated = part("justification", REASON.encode()) + FILE_HEAD + b"PK\x03\x04partial"
    response = client.post(
        ROUTE, content=truncated, headers={**login(client, analyst.username), **FORM}
    )
    assert (response.status_code, response.json()["code"]) == (422, "validation_failed")
    assert spool_files() == before
    assert import_requests(db) == 0
    assert queued == []


def test_a_part_with_too_many_headers_is_refused(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    noisy = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="justification"\r\n'.encode()
        + b"".join(f"X-Filler-{n}: x\r\n".encode() for n in range(9))
        + b"\r\n"
        + REASON.encode()
        + b"\r\n"
    )
    response = client.post(
        ROUTE,
        content=body(noisy, part("file", b"PK", "a.zip")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert (response.status_code, response.json()["code"]) == (422, "validation_failed")
    assert queued == []


def test_a_cancelled_upload_leaves_nothing_behind(tmp_path: Path) -> None:
    """A server shutdown cancels the request task; the cleanup must still run."""
    import anyio

    settings = get_settings().model_copy(update={"vulndb_spool_dir": tmp_path})

    async def endless() -> AsyncIterator[bytes]:
        yield FILE_HEAD
        while True:
            yield b"x" * (256 * 1024)
            await anyio.sleep(0.01)

    async def run() -> None:
        with anyio.move_on_after(0.3):
            await dump_upload.receive_dump(endless(), BOUNDARY.encode(), "t2", settings)

    anyio.run(run)
    assert list(tmp_path.iterdir()) == []


def test_the_zip_spool_is_removed_on_cancellation_too(tmp_path: Path) -> None:
    import anyio

    from app.ingest import upload

    target = tmp_path / "an" / upload.UPLOAD_NAME

    async def endless() -> AsyncIterator[bytes]:
        while True:
            yield b"x" * (256 * 1024)
            await anyio.sleep(0.01)

    async def run() -> None:
        with anyio.move_on_after(0.3):
            await upload.spool_body(endless(), target, 10**12)

    anyio.run(run)
    assert not target.exists()


def test_a_database_that_refuses_the_audit_row_leaves_no_spool(
    client: TestClient,
    analyst: User,
    queued: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = login(client, analyst.username)

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("app.inventory.sync.audit.record", refuse)
    before = spool_files()
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), part("file", b"PK", "a.zip")),
        headers={**headers, **FORM},
    )
    assert response.status_code == 500
    assert set(response.json()) == {"code", "message_key"}
    assert spool_files() == before
    assert queued == []


# --- addendum coverage adversary: six survivors, one test each ---


def test_the_audit_row_is_committed_before_the_job_exists(
    client: TestClient, analyst: User, engine: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No row, no job: the enqueue must see the request row already durable."""
    in_transaction: list[bool] = []

    def capture(token: str, _kind: str, _actor: str) -> None:
        in_transaction.append(engine.raw_connection().driver_connection.in_transaction)
        (get_settings().vulndb_spool_dir / f"{token}.zip").unlink()

    monkeypatch.setattr("app.core.queue.enqueue_import", capture)
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), part("file", b"PK", "a.zip")),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    assert in_transaction == [False]


def test_an_endless_justification_is_cut_at_its_byte_bound(tmp_path: Path) -> None:
    """The character cap at the end would hide a missing byte cap in every
    output; only memory would grow. The stream must stop at the bound."""
    import anyio

    from app.core.errors import ValidationFailed

    settings = get_settings().model_copy(update={"vulndb_spool_dir": tmp_path})
    consumed = 0

    async def endless() -> AsyncIterator[bytes]:
        nonlocal consumed
        head = f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="justification"\r\n\r\n'
        yield head.encode()
        while True:
            consumed += 4096
            yield b"x" * 4096

    async def run() -> None:
        with anyio.fail_after(5):
            await dump_upload.receive_dump(endless(), BOUNDARY.encode(), "t3", settings)

    with pytest.raises(ValidationFailed):
        anyio.run(run)
    assert consumed <= 8000 * 4 + 4096


def test_the_header_count_is_per_part_not_per_body(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    def with_fillers(name: str, value: bytes, filename: str | None = None) -> bytes:
        disposition = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        fillers = "".join(f"X-Filler-{n}: x\r\n" for n in range(5))
        return (
            f"--{BOUNDARY}\r\nContent-Disposition: {disposition}\r\n{fillers}\r\n".encode()
            + value
            + b"\r\n"
        )

    response = client.post(
        ROUTE,
        content=body(
            with_fillers("justification", REASON.encode()), with_fillers("file", b"PK", "a.zip")
        ),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    (get_settings().vulndb_spool_dir / f"{queued[0][0]}.zip").unlink()


def test_the_disposition_is_found_whatever_the_header_order(
    client: TestClient, analyst: User, queued: list[tuple[str, str]]
) -> None:
    file_part = (
        f"--{BOUNDARY}\r\nContent-Type: application/zip\r\n"
        'Content-Disposition: form-data; name="file"; filename="a.zip"\r\n\r\n'
    ).encode() + b"PK\r\n"
    response = client.post(
        ROUTE,
        content=body(part("justification", REASON.encode()), file_part),
        headers={**login(client, analyst.username), **FORM},
    )
    assert response.status_code == 202, response.text
    (get_settings().vulndb_spool_dir / f"{queued[0][0]}.zip").unlink()


@pytest.mark.parametrize(
    "content_type",
    [
        "application/x-www-form-urlencoded; boundary=abc",  # a boundary, wrong media
        "multipart/form-data; boundary=" + "a" * 201,  # over our cap
        "multipart/form-data; boundary=" + "a" * 300,  # over the library's: a raw 500 without ours
    ],
)
def test_a_boundary_is_taken_only_from_a_sane_multipart_header(content_type: str) -> None:
    from app.core.errors import ValidationFailed

    with pytest.raises(ValidationFailed):
        dump_upload.boundary_of(content_type)


def test_a_boundary_at_the_cap_is_accepted() -> None:
    assert dump_upload.boundary_of("multipart/form-data; boundary=" + "a" * 200) == b"a" * 200
