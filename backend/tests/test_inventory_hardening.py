"""What the day-18 precommit panel found on the sync/import surface, pinned.

Each test names the failure it prevents: a scheduled chain that dies after
one run, a parser exception that kills a job instead of becoming a row, an
unbounded buffer, a broker-chosen actor in the audit trail, a spool file
left behind by a broker outage, and an NVD row wiping an OSV join.
"""

from __future__ import annotations

import json
import zipfile
import zlib
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import AuditLogEntry, AuditOutcome
from app.auth.models import User
from app.core.config import get_settings
from app.core.queue import SYNC_JOB_ID
from app.inventory import importers, sync
from app.inventory.errors import DumpInvalid
from app.inventory.models import SyncStatus, VulnDbSync, Vulnerability, VulnerabilitySource
from tests.inventory_support import (
    LODASH_CVE,
    LODASH_GHSA,
    nvd_item,
    osv_record,
    write_nvd_feed,
    write_osv_zip,
)
from tests.support import login

MAX = 64 * 1024 * 1024


def test_the_successor_sync_never_reuses_the_running_jobs_id() -> None:
    """RQ deletes the finished job's hash: a successor under the same id dies with it."""
    settings = get_settings().model_copy(update={"vulndb_sync_interval_hours": 24})
    now = 1_700_000_000
    successor = sync.next_sync_job_id(settings, now)
    assert successor != SYNC_JOB_ID
    assert successor.startswith(f"{SYNC_JOB_ID}-")
    # Same slot from any replica → same id (deduplicated); the next slot differs.
    assert sync.next_sync_job_id(settings, now + 60) == successor
    assert sync.next_sync_job_id(settings, now + 24 * 3600) != successor
    zero = settings.model_copy(update={"vulndb_sync_interval_hours": 0})
    assert sync.next_sync_job_id(zero, now).startswith(f"{SYNC_JOB_ID}-")


def test_reschedule_passes_the_next_slot_id_and_survives_a_dead_broker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, Any]] = []

    def fake_enqueue(requested_by: str | None, **kwargs: Any) -> None:
        seen.append({"requested_by": requested_by, **kwargs})
        raise ConnectionError("valkey down")

    monkeypatch.setattr("app.core.queue.enqueue_sync", fake_enqueue)
    settings = get_settings().model_copy(
        update={"queue_inline": False, "vulndb_sync_interval_hours": 6}
    )
    sync.reschedule(settings)  # must not raise
    assert seen and seen[0]["job_id"] != SYNC_JOB_ID
    assert seen[0]["delay_seconds"] == 6 * 3600


def test_a_zip_entry_the_library_cannot_read_is_one_skipped_record(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unsupported method, encrypted entry, corrupt deflate: `zipfile` raises three
    different non-ValueError types; each is one skipped record, not a dead job."""
    dump = tmp_path / "odd.zip"
    with zipfile.ZipFile(dump, "w") as archive:
        archive.writestr("unsupported.json", b"{}")
        archive.writestr("encrypted.json", b"{}")
        archive.writestr("corrupt.json", b"{}")
        archive.writestr("deep.json", "[" * 100_000 + "]" * 100_000)
        archive.writestr("ok.json", json.dumps(osv_record(LODASH_GHSA)))
    real_open = zipfile.ZipFile.open
    raised = {
        "unsupported.json": NotImplementedError("That compression method is not supported"),
        "encrypted.json": RuntimeError("File is encrypted"),
        "corrupt.json": zlib.error("Error -3 while decompressing data"),
    }

    def failing_open(self: zipfile.ZipFile, name: Any, *args: Any, **kwargs: Any) -> Any:
        filename = name.filename if isinstance(name, zipfile.ZipInfo) else str(name)
        if filename in raised:
            raise raised[filename]
        return real_open(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", failing_open)
    stats = importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX)
    assert stats.stored == 1
    assert stats.skipped == 4
    assert db.get(Vulnerability, LODASH_GHSA) is not None


def test_a_bottomless_nvd_record_is_refused_not_crashed(db: Session, tmp_path: Path) -> None:
    feed = tmp_path / "deep.json"
    feed.write_bytes(b'{"vulnerabilities": [' + b"[" * 100_000 + b"]" * 100_000 + b"]}")
    with pytest.raises(DumpInvalid):
        importers.import_dump(db, feed, kind=importers.NVD_JSON, max_bytes=MAX)


def test_the_nvd_reader_stays_bounded_on_every_branch(db: Session, tmp_path: Path) -> None:
    junk = b"x" * (importers._MAX_PENDING + 1024)
    # (a) the key is there but the array never opens
    never_opens = tmp_path / "never.json"
    never_opens.write_bytes(b'{"vulnerabilities": ' + junk)
    with pytest.raises(DumpInvalid):
        importers.import_dump(db, never_opens, kind=importers.NVD_JSON, max_bytes=MAX * 4)
    # (b) trailing bytes after the closing bracket are never buffered
    trailing = tmp_path / "trailing.json"
    trailing.write_bytes(
        b'{"vulnerabilities": [' + json.dumps(nvd_item()).encode() + b"]}" + junk * 4
    )
    peak_before = len(junk) * 4
    records = list(importers.iter_nvd_feed(trailing, gzipped=False, max_bytes=MAX * 8))
    assert len(records) == 1
    assert peak_before > importers._MAX_PENDING, "the fixture is bigger than the buffer bound"


def test_a_broker_chosen_actor_never_reaches_the_audit_trail() -> None:
    assert sync.actor_of("mmarin") == "mmarin"
    assert sync.actor_of(None) == sync.SYSTEM_ACTOR
    assert sync.actor_of("") == sync.SYSTEM_ACTOR
    assert sync.actor_of("Robert'); DROP TABLE audit_log;--") == sync.SYSTEM_ACTOR
    assert sync.actor_of("x" * 65) == sync.SYSTEM_ACTOR
    assert sync.actor_of("<script>") == sync.SYSTEM_ACTOR


def test_a_crashing_sync_is_a_failed_row_and_still_reschedules(
    db: Session, monkeypatch: pytest.MonkeyPatch, app: Any
) -> None:
    del app
    rescheduled: list[bool] = []

    def boom(*args: Any, **kwargs: Any) -> int:
        del args, kwargs
        raise MemoryError("simulated crash inside the job")

    monkeypatch.setattr(sync, "download", boom)
    monkeypatch.setattr(sync, "reschedule", lambda _settings: rescheduled.append(True))
    settings = get_settings().model_copy(
        update={"vulndb_osv_ecosystems": ("npm",), "vulndb_nvd_years": ()}
    )
    monkeypatch.setattr(sync, "get_settings", lambda: settings)
    sync.run_sync_job("mmarin", force=True)  # never raises
    run = db.scalars(select(VulnDbSync)).one()
    assert run.status is SyncStatus.FAILED
    assert run.requested_by_username == "mmarin"
    rows = [r for r in db.scalars(select(AuditLogEntry)) if r.action == "vulndb.sync"]
    assert rows and rows[0].outcome is AuditOutcome.ERROR
    assert rescheduled == [True]


def test_a_crashing_import_is_a_failed_row_and_the_spool_is_gone(
    db: Session, monkeypatch: pytest.MonkeyPatch, app: Any
) -> None:
    del app

    def boom(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(importers, "import_dump", boom)
    settings = get_settings()
    settings.vulndb_spool_dir.mkdir(parents=True, exist_ok=True)
    token = "11111111-1111-4111-8111-111111111111"
    spool = settings.vulndb_spool_dir / f"{token}.zip"
    spool.write_bytes(b"PK")
    sync.run_import_job(token, importers.OSV_ZIP, "mmarin")
    assert not spool.exists()
    run = db.scalars(select(VulnDbSync)).one()
    assert run.status is SyncStatus.FAILED and run.detail is not None
    assert "RuntimeError" in run.detail


def test_a_broker_outage_at_import_removes_the_spool_and_answers_typed(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, db: Session
) -> None:
    def down(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise ConnectionError("valkey down")

    monkeypatch.setattr("app.core.queue.enqueue_import", down)
    dump = write_osv_zip(tmp_path / "all.zip", [osv_record(LODASH_GHSA)])
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("all.zip", dump.read_bytes(), "application/zip")},
        data={"justification": "Importación con la cola caída a propósito"},
        headers=login(client, "mmarin"),
    )
    assert response.status_code == 503
    assert response.json() == {
        "code": "vulndb_enqueue_failed",
        "message_key": "errors.inventory.enqueueFailed",
    }
    assert not list(get_settings().vulndb_spool_dir.iterdir()), "no 200 MiB orphan in the spool"
    assert db.get(Vulnerability, LODASH_GHSA) is None


def test_an_nvd_record_enriches_an_osv_row_but_never_wipes_its_packages(
    db: Session, tmp_path: Path
) -> None:
    osv = osv_record(
        LODASH_CVE, aliases=[LODASH_GHSA], vector=None, modified="2024-01-01T00:00:00Z"
    )
    importers.import_dump(
        db, write_osv_zip(tmp_path / "osv.zip", [osv]), kind=importers.OSV_ZIP, max_bytes=MAX
    )
    feed = write_nvd_feed(
        tmp_path / "nvd.json.gz", [nvd_item(LODASH_CVE, modified="2024-06-01T00:00:00.000")]
    )
    stats = importers.import_dump(db, feed, kind=importers.NVD_JSON_GZ, max_bytes=MAX)
    assert stats.stored == 1
    row = db.get(Vulnerability, LODASH_CVE)
    assert row is not None
    assert row.source is VulnerabilitySource.OSV, "the OSV row stays the correlation source"
    assert row.score == 7.4, "…and borrows NVD's score"
    assert [p.name for p in row.packages] == ["lodash"], "the join survives"
    assert row.summary == "Prototype pollution in lodash", "OSV's own text is kept"
