"""Sensitive artefacts committed to the audited tree (phase 11).

Hostile input first: the tree decides what it ships, how big it is and where.
The properties pinned here are the survey's (`tasks/phase11-survey.md` §8):
each rule fires on its positive and stays silent on the look-alike that is
legitimate source; a 50 MB dump costs one small read; nothing of a dump row or
an `.env` value ever reaches a finding or an export; a symlink is never
followed; an artefact inside a dependency directory stays in the E3 queue —
and ONLY an artefact does.
"""

from __future__ import annotations

import gzip
import io
import os
import uuid
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.analysis import artefacts
from app.analysis.artefacts import (
    DUMP,
    ENV,
    LOG,
    PRIVATE_KEY,
    UPLOADS,
    ArtefactHit,
    human_size,
    scan_artefacts,
    to_finding,
)
from app.analysis.catalog import ARTEFACT_CATALOG, CATALOG, describe
from app.analysis.models import Analysis, AnalysisStatus, Severity, ToolCategory, ToolStatus
from app.analysis.third_party import finding_is_third_party
from app.auth.models import User
from tests.test_pipeline import FixtureExecutor, login

PG_DUMP = (
    b"--\n-- PostgreSQL database dump\n--\n\nSET statement_timeout = 0;\n"
    b"COPY public.users (id, email) FROM stdin;\n1\tmaria@example.com\n\\.\n"
)
ROW_SECRET = "maria@example.com"
ENV_VALUE = "s3cr3t-db-password-value"


def _write(root: Path, rel: str, content: bytes | str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    return path


def _sparse(root: Path, rel: str, head: bytes, size: int) -> Path:
    """A file of ``size`` bytes that costs the disk only its head."""
    path = _write(root, rel, head)
    with path.open("r+b") as handle:
        handle.truncate(size)
    return path


def _rules(root: Path) -> set[tuple[str, str]]:
    return {(hit.rule_id, hit.path) for hit in scan_artefacts(root).hits}


# --- database dumps -------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("backup.sql", PG_DUMP),
        ("db/mysql.sql", b"-- MySQL dump 10.13  Distrib 8.0\n\nINSERT INTO t VALUES (1);\n"),
        ("db/maria.sql", b"-- MariaDB dump 10.19\n"),
        ("db/rows.sql", b"CREATE TABLE t (a int);\nINSERT INTO t VALUES (1);\n"),
        ("db/copy.dump", b"COPY public.t (a) FROM stdin;\n1\n\\.\n"),
        ("db/custom.pgdump", b"PGDMP\x01\x0e\x00binary"),
        ("db/old.bak", b"-- PostgreSQL database dump\n"),
        ("db/app.sqlite", b"SQLite format 3\x00" + b"\x00" * 100),
        ("db/app.db", b"SQLite format 3\x00" + b"\x00" * 100),
    ],
)
def test_a_database_dump_is_found(tmp_path: Path, name: str, content: bytes) -> None:
    _write(tmp_path, name, content)
    assert _rules(tmp_path) == {(DUMP, name)}


def test_a_gzipped_dump_is_read_through_its_compression(tmp_path: Path) -> None:
    _write(tmp_path, "prod.sql.gz", gzip.compress(PG_DUMP))
    (hit,) = scan_artefacts(tmp_path).hits
    assert (hit.rule_id, hit.detail) == (DUMP, "-- PostgreSQL database dump")


@pytest.mark.parametrize(
    ("name", "content"),
    [
        # Migrations and schema files are legitimate source: DDL, no data rows.
        ("migrations/0001_init.sql", b"CREATE TABLE users (id int);\nALTER TABLE users ADD x;\n"),
        ("schema.sql", b"-- schema\nCREATE TABLE t (a int);\n"),
        # A file that is not a SQLite database whatever its extension says.
        ("Thumbs.db", b"\xd0\xcf\x11\xe0 not sqlite"),
        ("notes.bak", b"just a backup of a text file\n"),
        ("broken.sql.gz", b"not gzip at all"),
    ],
)
def test_schema_and_look_alikes_are_not_dumps(tmp_path: Path, name: str, content: bytes) -> None:
    _write(tmp_path, name, content)
    assert _rules(tmp_path) == set()


def test_small_seed_data_is_source_and_a_large_one_is_a_dump(tmp_path: Path) -> None:
    rows = b"INSERT INTO t VALUES (1);\n"
    _write(tmp_path, "db/seed_small.sql", rows * 200)  # ~5 KB
    _write(tmp_path, "fixtures/users.sql", rows * 200)
    _sparse(tmp_path, "db/seed_big.sql", rows, 150 * 1024)
    _sparse(tmp_path, "seeders/big.sql", rows, 150 * 1024)
    assert _rules(tmp_path) == {(DUMP, "db/seed_big.sql"), (DUMP, "seeders/big.sql")}


def test_a_fifty_megabyte_dump_costs_one_small_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sparse(tmp_path, "huge.sql", PG_DUMP, 50 * 1024 * 1024)
    read: list[int] = []
    original = Path.open

    def counting_open(self: Path, *args: object, **kwargs: object) -> object:
        handle = original(self, *args, **kwargs)  # type: ignore[call-overload]
        inner = handle.read

        def read_counted(size: int = -1) -> bytes:
            assert size != -1, "an unbounded read of an audited file"
            data: bytes = inner(size)
            read.append(len(data))
            return data

        handle.read = read_counted
        return handle

    monkeypatch.setattr(Path, "open", counting_open)
    (hit,) = scan_artefacts(tmp_path).hits
    assert hit.size == 50 * 1024 * 1024
    assert sum(read) <= artefacts.HEAD_BYTES


def test_a_dump_finding_carries_the_signature_and_never_a_row(tmp_path: Path) -> None:
    _write(tmp_path, "backup.sql", PG_DUMP)
    (hit,) = scan_artefacts(tmp_path).hits
    finding = to_finding(hit)
    assert finding.snippet == "-- PostgreSQL database dump"
    for text in (finding.snippet, finding.message, finding.title):
        assert ROW_SECRET not in (text or "")
    # An INSERT signature is a canonical label, not the matched line.
    _write(tmp_path, "rows.sql", b"INSERT INTO users VALUES ('maria@example.com');\n")
    rows = next(h for h in scan_artefacts(tmp_path).hits if h.path == "rows.sql")
    assert rows.detail == "INSERT INTO …"
    assert ROW_SECRET not in (to_finding(rows).snippet or "")


# --- uploads --------------------------------------------------------------------


def test_an_upload_directory_is_one_finding_where_the_files_sit(tmp_path: Path) -> None:
    for index in range(12):
        _write(tmp_path, f"backend/uploads/despachos/{index}.jpg", b"x" * 100)
    _write(tmp_path, "backend/uploads/.gitkeep", b"")
    (hit,) = scan_artefacts(tmp_path).hits
    assert (hit.rule_id, hit.path, hit.files, hit.size) == (
        UPLOADS,
        "backend/uploads/despachos",
        12,
        1200,
    )
    finding = to_finding(hit)
    assert finding.snippet == "12 archivos · 1 KB"
    assert finding.severity is Severity.MEDIUM
    assert "datos personales" in (finding.message or "")


def test_an_upload_tree_fanned_out_per_user_still_counts_once(tmp_path: Path) -> None:
    for user in range(6):
        for index in range(2):
            _write(tmp_path, f"storage/app/public/u{user}/{index}.pdf", b"%PDF")
    (hit,) = scan_artefacts(tmp_path).hits
    assert (hit.rule_id, hit.path, hit.files) == (UPLOADS, "storage/app/public", 12)


@pytest.mark.parametrize(
    "directory",
    [
        "src/assets/img",  # the UI's own images are not uploads
        "public/img",
        "static",
    ],
)
def test_the_uis_own_images_are_not_uploads(tmp_path: Path, directory: str) -> None:
    for index in range(30):
        _write(tmp_path, f"{directory}/{index}.png", b"png")
    assert _rules(tmp_path) == set()


def test_fewer_than_ten_uploads_is_not_reported(tmp_path: Path) -> None:
    for index in range(9):
        _write(tmp_path, f"public/uploads/{index}.jpg", b"x")
    _write(tmp_path, "public/uploads/readme.txt", b"x")
    assert _rules(tmp_path) == set()


# --- .env -----------------------------------------------------------------------


def test_an_env_file_is_reported_with_key_names_and_never_a_value(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "backend/.env",
        f"# comment\nDB_PASSWORD={ENV_VALUE}\nexport API_KEY='abc'\nEMPTY=\nDB_PASSWORD=again\n",
    )
    (hit,) = scan_artefacts(tmp_path).hits
    assert (hit.rule_id, hit.detail) == (ENV, "DB_PASSWORD, API_KEY")
    finding = to_finding(hit)
    assert finding.severity is Severity.HIGH
    for text in (finding.snippet, finding.message, finding.title):
        assert ENV_VALUE not in (text or "")
        assert "abc" not in (text or "")


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (".env.example", "DB_PASSWORD=changeme\n"),
        (".env.sample", "DB_PASSWORD=changeme\n"),
        (".env.dist", "DB_PASSWORD=changeme\n"),
        (".env", "DB_PASSWORD=\nAPI_KEY=''\n# SECRET=x\n"),
        ("env.txt", "DB_PASSWORD=real\n"),
    ],
)
def test_templates_and_empty_env_files_are_not_reported(
    tmp_path: Path, name: str, content: str
) -> None:
    _write(tmp_path, name, content)
    assert _rules(tmp_path) == set()


def test_every_env_variant_with_values_is_reported(tmp_path: Path) -> None:
    _write(tmp_path, ".env.production", "A=1\n")
    _write(tmp_path, "api/.env.local", "B=2\n")
    assert _rules(tmp_path) == {(ENV, ".env.production"), (ENV, "api/.env.local")}


# --- private keys ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "content", "label"),
    [
        ("certs/server.key", b"-----BEGIN PRIVATE KEY-----\nMII", "-----BEGIN PRIVATE KEY-----"),
        (
            "certs/tls.pem",
            b"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
            b"-----BEGIN RSA PRIVATE KEY-----\nMII",
            "-----BEGIN RSA PRIVATE KEY-----",
        ),
        ("deploy/id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn", None),
        ("certs/store.p12", b"\x30\x82\x0a\x1b\x02\x01\x03\x30", "PKCS#12"),
    ],
)
def test_a_private_key_is_found(
    tmp_path: Path, name: str, content: bytes, label: str | None
) -> None:
    _write(tmp_path, name, content)
    (hit,) = scan_artefacts(tmp_path).hits
    assert (hit.rule_id, hit.path) == (PRIVATE_KEY, name)
    assert hit.detail == (label or "-----BEGIN OPENSSH PRIVATE KEY-----")
    # The key material never leaves the file.
    assert "MII" not in (to_finding(hit).snippet or "")


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("certs/pub.pem", b"-----BEGIN PUBLIC KEY-----\nMII\n-----END PUBLIC KEY-----\n"),
        ("certs/ca.pem", b"-----BEGIN CERTIFICATE-----\nMII\n"),
        ("certs/fake.p12", b"not der"),
        ("keys.txt", b"-----BEGIN PRIVATE KEY-----\n"),
    ],
)
def test_public_material_and_look_alikes_are_not_keys(
    tmp_path: Path, name: str, content: bytes
) -> None:
    _write(tmp_path, name, content)
    assert _rules(tmp_path) == set()


# --- logs -----------------------------------------------------------------------


def test_large_logs_are_one_finding_per_directory(tmp_path: Path) -> None:
    _sparse(tmp_path, "storage/logs/laravel.log", b"x", 2 * 1024 * 1024)
    _sparse(tmp_path, "storage/logs/old.log", b"x", 3 * 1024 * 1024)
    _write(tmp_path, "storage/logs/small.log", b"x" * 100)
    _write(tmp_path, "other/tiny.log", b"x")
    (hit,) = scan_artefacts(tmp_path).hits
    assert (hit.rule_id, hit.path, hit.files, hit.size) == (
        LOG,
        "storage/logs",
        2,
        5 * 1024 * 1024,
    )
    finding = to_finding(hit)
    assert (finding.severity, finding.snippet) == (Severity.LOW, "2 archivos · 5 MB")


# --- the walk itself ------------------------------------------------------------


def test_a_symlink_is_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _write(outside, "prod.sql", PG_DUMP)
    root = tmp_path / "tree"
    root.mkdir()
    (root / "prod.sql").symlink_to(outside / "prod.sql")
    (root / "linked-dir").symlink_to(outside)
    assert _rules(root) == set()


def test_git_internals_are_skipped_and_dependency_directories_are_not(tmp_path: Path) -> None:
    _write(tmp_path, ".git/objects/x.sql", PG_DUMP)
    _write(tmp_path, "node_modules/pkg/prod.sql", PG_DUMP)
    _write(tmp_path, "vendor/acme/.env", "KEY=value\n")
    assert _rules(tmp_path) == {
        (DUMP, "node_modules/pkg/prod.sql"),
        (ENV, "vendor/acme/.env"),
    }


def test_the_file_cap_is_a_recorded_gap_never_a_silent_pass(tmp_path: Path) -> None:
    for index in range(5):
        _write(tmp_path, f"f{index}.txt", b"x")
    _write(tmp_path, "zz/prod.sql", PG_DUMP)
    capped = scan_artefacts(tmp_path, max_files=3)
    assert (capped.truncated, capped.files_seen, capped.hits) == (True, 3, ())
    whole = scan_artefacts(tmp_path)
    assert (whole.truncated, whole.files_seen, len(whole.hits)) == (False, 6, 1)


def test_the_hit_cap_is_a_recorded_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artefacts, "MAX_HITS", 2)
    for index in range(3):
        _write(tmp_path, f"d{index}.sql", PG_DUMP)
    scan = scan_artefacts(tmp_path)
    assert scan.truncated is True
    assert [hit.path for hit in scan.hits] == ["d0.sql", "d1.sql"]


def test_the_scan_is_deterministic(tmp_path: Path) -> None:
    _write(tmp_path, "b.sql", PG_DUMP)
    _write(tmp_path, "a/.env", "K=v\n")
    _write(tmp_path, "c/id_rsa", b"-----BEGIN PRIVATE KEY-----\n")
    first = [to_finding(hit) for hit in scan_artefacts(tmp_path).hits]
    second = [to_finding(hit) for hit in scan_artefacts(tmp_path).hits]
    assert first == second
    assert [f.rule_id for f in first] == [DUMP, ENV, PRIVATE_KEY]


# --- the finding and its prose --------------------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "cwe", "owasp", "severity"),
    [
        (DUMP, 538, "A01:2021", Severity.HIGH),
        (UPLOADS, 538, "A01:2021", Severity.MEDIUM),
        (ENV, 538, "A01:2021", Severity.HIGH),
        (PRIVATE_KEY, 321, "A02:2021", Severity.HIGH),
        (LOG, 532, "A09:2021", Severity.LOW),
    ],
)
def test_each_rule_is_classified_as_the_survey_decided(
    rule_id: str, cwe: int, owasp: str, severity: Severity
) -> None:
    finding = to_finding(ArtefactHit(rule_id, "x/y", 10, "label", 3))
    assert (finding.category, finding.cwe, finding.owasp, finding.severity) == (
        ToolCategory.ARTEFACT,
        cwe,
        owasp,
        severity,
    )
    assert (finding.tools, finding.line, finding.title) == (
        ("artefacts",),
        None,
        ARTEFACT_CATALOG[rule_id].title,
    )


def test_the_dump_names_backup_exposure_in_its_references() -> None:
    references = ARTEFACT_CATALOG[DUMP].references
    assert "https://cwe.mitre.org/data/definitions/530.html" in references
    assert "https://cwe.mitre.org/data/definitions/538.html" in references


def test_artefact_prose_is_chosen_only_when_asked_for() -> None:
    # A caller that does not say "this is an artefact" gets the CWE's prose.
    assert describe(321) == describe(321, artefact_rule=None)
    assert describe(321, artefact_rule=PRIVATE_KEY) == ARTEFACT_CATALOG[PRIVATE_KEY]
    assert describe(79, artefact_rule="not-a-rule") == CATALOG[79]


@pytest.mark.parametrize(
    ("size", "text"),
    [
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1 KB"),
        (1024 * 1024 - 1, "1024 KB"),
        (1024 * 1024, "1 MB"),
        (206 * 1024 * 1024, "206 MB"),
        (1000 * 1024 * 1024, "1000 MB"),
    ],
)
def test_sizes_print_in_whole_units(size: int, text: str) -> None:
    assert human_size(size) == text


def test_the_exemption_applies_to_artefacts_and_to_nothing_new() -> None:
    path = "node_modules/pkg/prod.sql"
    assert finding_is_third_party(ToolCategory.ARTEFACT, path) is False
    assert finding_is_third_party(ToolCategory.SAST, path) is True
    assert finding_is_third_party(ToolCategory.SECRET, path) is True


# --- end to end -----------------------------------------------------------------


def _ingest_tree(client: TestClient, headers: dict[str, str], files: dict[str, bytes]) -> str:
    project = client.post(
        "/api/v1/projects",
        json={"name": f"p-{uuid.uuid4().hex[:8]}", "system": {"name": "s"}},
        headers=headers,
    ).json()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    response = client.post(
        f"/api/v1/projects/{project['id']}/ingest",
        content=buffer.getvalue(),
        headers={**headers, "Content-Type": "application/zip"},
    )
    assert response.status_code == 202, response.text
    analysis_id: str = response.json()["id"]
    return analysis_id


@pytest.fixture
def fixture_executor(monkeypatch: pytest.MonkeyPatch) -> FixtureExecutor:
    executor = FixtureExecutor()
    monkeypatch.setattr("app.analysis.pipeline.build_executor", lambda _settings: executor)
    return executor


def test_the_pipeline_reports_artefacts_as_findings_in_every_export(
    client: TestClient, analyst: User, db: Session, fixture_executor: FixtureExecutor
) -> None:
    del fixture_executor
    headers = login(client, analyst.username)
    analysis_id = _ingest_tree(
        client,
        headers,
        {
            "index.js": b"console.log(1);\n",
            "respaldo.sql": PG_DUMP,
            "backend/.env": f"DB_PASSWORD={ENV_VALUE}\n".encode(),
            "node_modules/pkg/prod.sql": PG_DUMP,
            # A hostile NAME: it is a path, shown escaped like any path.
            "<script>alert(1)</script>.sql": b"INSERT INTO t VALUES (1);\n" * 5000,
        },
    )
    analysis = db.get(Analysis, uuid.UUID(analysis_id))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE, analysis.failure_code

    run = next(r for r in analysis.tool_runs if r.tool == "artefacts")
    assert (run.category, run.status, run.detail) == (ToolCategory.ARTEFACT, ToolStatus.RAN, None)
    raw = next(r for r in analysis.raw_outputs if r.tool == "artefacts")
    assert raw.output is not None and b"respaldo.sql" in raw.output
    assert ROW_SECRET.encode() not in raw.output
    assert ENV_VALUE.encode() not in raw.output

    found = {f.path: f for f in analysis.findings if f.category is ToolCategory.ARTEFACT}
    assert set(found) == {
        "respaldo.sql",
        "backend/.env",
        "node_modules/pkg/prod.sql",
        "<script>alert(1)</script>.sql",
    }
    # Inside a dependency directory and still in the analyst's queue.
    assert found["node_modules/pkg/prod.sql"].third_party is False

    for fmt in ("html", "md"):
        body = client.get(
            f"/api/v1/analyses/{analysis_id}/report", params={"format": fmt}, headers=headers
        )
        assert body.status_code == 200, body.text
        text = body.text
        assert ARTEFACT_CATALOG[DUMP].title in text
        assert ARTEFACT_CATALOG[ENV].title in text
        assert "respaldo.sql" in text
        assert ROW_SECRET not in text
        assert ENV_VALUE not in text
        assert "<script>alert(1)</script>" not in text
    docx = client.get(
        f"/api/v1/analyses/{analysis_id}/report", params={"format": "docx"}, headers=headers
    )
    assert docx.status_code == 200
    with zipfile.ZipFile(io.BytesIO(docx.content)) as document:
        xml = document.read("word/document.xml").decode("utf-8")
    assert ARTEFACT_CATALOG[DUMP].title in xml
    assert ROW_SECRET not in xml and ENV_VALUE not in xml

    listed = client.get(f"/api/v1/analyses/{analysis_id}/findings", headers=headers).json()
    dump = next(f for f in listed if f["path"] == "respaldo.sql")
    assert dump["description"] == ARTEFACT_CATALOG[DUMP].description
    assert dump["mitigation"] == list(ARTEFACT_CATALOG[DUMP].mitigation)
    assert dump["category"] == "artefact"


def test_a_scan_that_cannot_run_is_a_coverage_gap(
    client: TestClient,
    analyst: User,
    db: Session,
    fixture_executor: FixtureExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fixture_executor

    def broken(_root: Path) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(artefacts, "scan_artefacts", broken)
    headers = login(client, analyst.username)
    analysis = db.get(Analysis, uuid.UUID(_ingest_tree(client, headers, {"a.js": b"1"})))
    assert analysis is not None
    assert analysis.status is AnalysisStatus.DONE
    run = next(r for r in analysis.tool_runs if r.tool == "artefacts")
    assert (run.status, run.detail) == (ToolStatus.FAILED, "scan failed: PermissionError")


def test_a_capped_scan_says_so_on_its_coverage_row(
    client: TestClient,
    analyst: User,
    db: Session,
    fixture_executor: FixtureExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fixture_executor
    original = artefacts.scan_artefacts
    monkeypatch.setattr(artefacts, "scan_artefacts", lambda root: original(root, max_files=1))
    headers = login(client, analyst.username)
    analysis = db.get(
        Analysis, uuid.UUID(_ingest_tree(client, headers, {"a.js": b"1", "b.js": b"2"}))
    )
    assert analysis is not None
    run = next(r for r in analysis.tool_runs if r.tool == "artefacts")
    assert run.status is ToolStatus.RAN
    assert run.detail is not None and "stopped after 1 files" in run.detail
    raw = next(r for r in analysis.raw_outputs if r.tool == "artefacts")
    assert raw.truncated is True


def test_a_dump_is_never_evicted_by_the_cap_behind_lower_findings(
    client: TestClient,
    analyst: User,
    db: Session,
    fixture_executor: FixtureExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Merged BEFORE the ordering: a HIGH dump competes on its severity."""
    del fixture_executor
    from app.analysis.normalizer import NormalizedFinding
    from app.core.config import get_settings

    def lows(_reports: object, _roots: object) -> list[NormalizedFinding]:
        return [
            NormalizedFinding(
                category=ToolCategory.SAST,
                tools=("semgrep",),
                rule_id="low",
                cwe=79,
                owasp="A03:2021",
                title=f"low {i}",
                severity=Severity.LOW,
                cvss_score=None,
                cvss_vector=None,
                path=f"src/f{i}.js",
                line=i,
                snippet=None,
                message=None,
                advisory=None,
                references=(),
                fingerprint=f"{i:064x}",
            )
            for i in range(20)
        ]

    monkeypatch.setattr("app.analysis.pipeline.normalize", lows)
    capped = get_settings().model_copy(update={"max_findings_per_analysis": 5})
    monkeypatch.setattr("app.analysis.pipeline.get_settings", lambda: capped)
    headers = login(client, analyst.username)
    analysis = db.get(
        Analysis, uuid.UUID(_ingest_tree(client, headers, {"zz/respaldo.sql": PG_DUMP}))
    )
    assert analysis is not None
    assert analysis.findings[0].rule_id == DUMP


# --- boundaries and walk order (phase-11 mutation pass) -------------------------


def test_the_gzip_head_is_bounded_however_well_it_compresses() -> None:
    from app.analysis.artefacts import _gunzip_head

    bomb = gzip.compress(b"a" * 10_000_000)[: artefacts.HEAD_BYTES]
    assert len(_gunzip_head(bomb)) == artefacts.HEAD_BYTES


@pytest.mark.parametrize(
    ("name", "label"),
    [
        ("a.sqlite", "SQLite format 3"),
        ("b.pgdump", "PGDMP"),
        ("c.sql", "-- MySQL dump"),
    ],
)
def test_each_dump_carries_its_canonical_label(tmp_path: Path, name: str, label: str) -> None:
    content = {
        "SQLite format 3": b"SQLite format 3\x00",
        "PGDMP": b"PGDMP\x01",
        "-- MySQL dump": b"-- MySQL dump 10.13\n",
    }[label]
    _write(tmp_path, name, content)
    (hit,) = scan_artefacts(tmp_path).hits
    assert hit.detail == label


def test_the_seed_floor_is_exclusive_and_applies_at_any_depth(tmp_path: Path) -> None:
    rows = b"INSERT INTO t VALUES (1);\n"
    _sparse(tmp_path, "database/seeders/at_floor.sql", rows, artefacts.SEED_FLOOR_BYTES)
    _sparse(tmp_path, "database/seeders/below.sql", rows, artefacts.SEED_FLOOR_BYTES - 1)
    assert _rules(tmp_path) == {(DUMP, "database/seeders/at_floor.sql")}


@pytest.mark.parametrize(
    ("content", "keys"),
    [
        ("EMPTY=\nKEY=v\n", "KEY"),  # an empty line before a filled one
        ("A=XX\n", "A"),
        ("NOTE=# only a comment\n", None),
        ("".join(f"K{i}=v\n" for i in range(45)), ", ".join(f"K{i}" for i in range(40))),
    ],
)
def test_env_values_and_the_key_cap(tmp_path: Path, content: str, keys: str | None) -> None:
    _write(tmp_path, ".env", content)
    hits = scan_artefacts(tmp_path).hits
    assert [hit.detail for hit in hits] == ([] if keys is None else [keys])


@pytest.mark.parametrize(
    ("name", "content", "found"),
    [
        ("certs/store.pfx", b"\x30\x82\x0a\x1b\x02\x01\x03", True),
        # DER-looking bytes in a .key are not PKCS#12: only .p12 / .pfx are.
        ("certs/x.key", b"\x02\x01\x03\x30", False),
        # The version must sit in the first eight bytes of the SEQUENCE.
        ("certs/late.p12", b"\x30\x82\x0a\x1b\x00\x00\x02\x01\x03", False),
    ],
)
def test_pkcs12_is_recognised_only_by_its_shape(
    tmp_path: Path, name: str, content: bytes, found: bool
) -> None:
    _write(tmp_path, name, content)
    assert _rules(tmp_path) == ({(PRIVATE_KEY, name)} if found else set())


@pytest.mark.parametrize(
    "directory",
    [
        "app/icons",  # `app` alone is not Laravel's storage/app
        "storage/framework",  # a sibling of storage/app is not uploads
        "app/storage",  # `storage` AFTER `app` is not storage/app
    ],
)
def test_only_upload_named_directories_count(tmp_path: Path, directory: str) -> None:
    for index in range(12):
        _write(tmp_path, f"{directory}/{index}.png", b"png")
    assert _rules(tmp_path) == set()


def test_separate_upload_roots_are_counted_separately(tmp_path: Path) -> None:
    for index in range(6):
        _write(tmp_path, f"a/uploads/{index}.jpg", b"x")
        _write(tmp_path, f"b/uploads/{index}.jpg", b"x")
    assert _rules(tmp_path) == set()
    for index in range(10):
        _write(tmp_path, f"c/media/{index}.jpg", b"x")
    # Exactly the threshold is reported, and a root below it does not stop
    # the ones after it from being looked at.
    assert _rules(tmp_path) == {(UPLOADS, "c/media")}


def test_subdirectories_of_one_upload_root_are_counted_together(tmp_path: Path) -> None:
    _write(tmp_path, "uploads/a/0.jpg", b"x")
    for index in range(11):
        _write(tmp_path, f"uploads/b/{index}.jpg", b"x")
    (hit,) = scan_artefacts(tmp_path).hits
    assert (hit.path, hit.files) == ("uploads", 12)


def test_a_log_at_the_floor_is_not_reported_and_one_at_the_root_is(tmp_path: Path) -> None:
    _sparse(tmp_path, "logs/at_floor.log", b"x", artefacts.LOG_MIN_BYTES)
    _sparse(tmp_path, "root.log", b"x", artefacts.LOG_MIN_BYTES + 1)
    assert _rules(tmp_path) == {(LOG, ".")}


def test_one_hit_in_a_directory_does_not_hide_the_next(tmp_path: Path) -> None:
    _write(tmp_path, "a.sql", PG_DUMP)
    _write(tmp_path, "b.key", b"-----BEGIN PRIVATE KEY-----\n")
    _write(tmp_path, "d/.env", "K=v\n")
    _write(tmp_path, "d/e.sql", PG_DUMP)
    assert _rules(tmp_path) == {
        (DUMP, "a.sql"),
        (PRIVATE_KEY, "b.key"),
        (ENV, "d/.env"),
        (DUMP, "d/e.sql"),
    }


def test_an_unreadable_or_special_file_does_not_stop_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    os.mkfifo(tmp_path / "a.fifo")
    _write(tmp_path, "b.txt", b"x")
    _write(tmp_path, "c.sql", PG_DUMP)
    original = Path.lstat

    def flaky(self: Path) -> os.stat_result:
        if self.name == "b.txt":
            raise PermissionError("gone")
        return original(self)

    monkeypatch.setattr(Path, "lstat", flaky)
    scan = scan_artefacts(tmp_path)
    assert [(hit.rule_id, hit.path) for hit in scan.hits] == [(DUMP, "c.sql")]
    # Neither the FIFO nor the vanished file counts as a file looked at.
    assert scan.files_seen == 1


def test_exactly_the_hit_cap_is_not_a_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artefacts, "MAX_HITS", 2)
    _write(tmp_path, "d0.sql", PG_DUMP)
    _write(tmp_path, "d1.sql", PG_DUMP)
    assert scan_artefacts(tmp_path).truncated is False


@pytest.mark.parametrize(
    ("rule_id", "files", "size", "detail", "message"),
    [
        (DUMP, 1, 234 * 1024 * 1024, "x", "Respaldo de base de datos de 234 MB en el repositorio."),
        (
            UPLOADS,
            405,
            206 * 1024 * 1024,
            "405",
            "405 archivos cargados por usuarios (206 MB). Revisar si contienen datos personales.",
        ),
        (ENV, 1, 40, "A, B", "Archivo de entorno con valores asignados. Claves: A, B."),
        (PRIVATE_KEY, 1, 10, "PKCS#12", "Clave privada en el repositorio (PKCS#12)."),
        (LOG, 3, 5 * 1024 * 1024, "3", "3 archivos de registro de más de 1 MB (5 MB)."),
    ],
)
def test_each_message_says_what_and_how_much(
    rule_id: str, files: int, size: int, detail: str, message: str
) -> None:
    assert to_finding(ArtefactHit(rule_id, "p", size, detail, files)).message == message


def test_a_file_that_cannot_be_read_does_not_stop_the_directory(tmp_path: Path) -> None:
    locked = _write(tmp_path, "a.sql", PG_DUMP)
    _write(tmp_path, "b.sql", PG_DUMP)
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("running as a user that reads through a 000 mode")
        assert _rules(tmp_path) == {(DUMP, "b.sql")}
    finally:
        locked.chmod(0o600)


# --- precommit panel, phase 11 --------------------------------------------------


def test_a_long_env_line_is_read_in_linear_time(tmp_path: Path) -> None:
    """A lazy tail before `\\s*$` was quadratic: 40 ms per 4 KiB line, times
    every `.env*` a hostile tree can ship (security panel)."""
    import time

    line = b"KEY=a" + b" " * (artefacts.HEAD_BYTES - 7) + b"b"
    for index in range(50):
        _write(tmp_path, f"d{index}/.env", line)
    started = time.perf_counter()
    scan = scan_artefacts(tmp_path)
    elapsed = time.perf_counter() - started
    assert len(scan.hits) == 50
    assert elapsed < 0.5, f"{elapsed:.2f}s for 50 files"


def test_env_values_are_trimmed_before_being_judged_empty(tmp_path: Path) -> None:
    _write(tmp_path, "a/.env", "KEY =   \nQ='  '\n")
    _write(tmp_path, "b/.env", "KEY = value  \n")
    assert _rules(tmp_path) == {(ENV, "b/.env")}


def test_the_hit_cap_keeps_the_worst_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Alphabetically a log sorts before a private key; by severity it must not."""
    monkeypatch.setattr(artefacts, "MAX_HITS", 2)
    for index in range(3):
        _sparse(tmp_path, f"logs{index}/big.log", b"x", 2 * 1024 * 1024)
    _write(tmp_path, "z/id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
    _write(tmp_path, "zz/.env", "K=v\n")
    scan = scan_artefacts(tmp_path)
    assert scan.truncated is True
    assert {hit.rule_id for hit in scan.hits} == {PRIVATE_KEY, ENV}


def test_only_the_root_git_directory_is_skipped(tmp_path: Path) -> None:
    _write(tmp_path, ".git/objects/x.sql", PG_DUMP)
    _write(tmp_path, "hidden/.git/prod.sql", PG_DUMP)
    assert _rules(tmp_path) == {(DUMP, "hidden/.git/prod.sql")}


def test_a_vendored_artefact_outranks_vendored_sast_in_the_cap(
    client: TestClient,
    analyst: User,
    db: Session,
    fixture_executor: FixtureExecutor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fixture_executor
    from app.analysis.normalizer import NormalizedFinding
    from app.core.config import get_settings

    def vendored_highs(_reports: object, _roots: object) -> list[NormalizedFinding]:
        return [
            NormalizedFinding(
                category=ToolCategory.SAST,
                tools=("semgrep",),
                rule_id="high",
                cwe=79,
                owasp="A03:2021",
                title=f"high {i}",
                severity=Severity.CRITICAL,
                cvss_score=None,
                cvss_vector=None,
                path=f"vendor/pkg/f{i}.php",
                line=i,
                snippet=None,
                message=None,
                advisory=None,
                references=(),
                fingerprint=f"{i:064x}",
            )
            for i in range(20)
        ]

    monkeypatch.setattr("app.analysis.pipeline.normalize", vendored_highs)
    capped = get_settings().model_copy(update={"max_findings_per_analysis": 5})
    monkeypatch.setattr("app.analysis.pipeline.get_settings", lambda: capped)
    headers = login(client, analyst.username)
    analysis = db.get(
        Analysis, uuid.UUID(_ingest_tree(client, headers, {"vendor/acme/prod.sql": PG_DUMP}))
    )
    assert analysis is not None
    first = analysis.findings[0]
    assert (first.rule_id, first.third_party) == (DUMP, False)


# --- coverage adversary, phase 11 -----------------------------------------------


def test_artefact_prose_reaches_the_report_context() -> None:
    from app.reports.context import _finding_context
    from tests.support import make_finding

    finding = make_finding(
        1,
        category=ToolCategory.ARTEFACT,
        tools=["artefacts"],
        rule_id=DUMP,
        cwe=538,
        owasp="A01:2021",
        line=None,
    )
    context = _finding_context(finding)
    assert context["description"] == ARTEFACT_CATALOG[DUMP].description
    assert context["impact"] == ARTEFACT_CATALOG[DUMP].impact


def test_an_artefact_rule_id_on_another_category_never_selects_its_prose() -> None:
    from app.projects.schemas import finding_out
    from app.reports.context import _finding_context
    from tests.support import make_finding

    finding = make_finding(1, rule_id=DUMP, cwe=79, third_party=False)
    assert _finding_context(finding)["description"] == describe(79).description
    assert finding_out(finding).description == describe(79).description


def test_the_asvs_annex_counts_artefact_findings(db: Session, tmp_path: Path) -> None:
    from app.reports import closure
    from tests.support import make_finding
    from tests.test_report_closure import _with_workflow

    analysis = _with_workflow(db, tmp_path / "jail")
    artefact = make_finding(
        5, cwe=538, owasp="A01:2021", category=ToolCategory.ARTEFACT, rule_id=DUMP
    )
    before = closure.closure_context(analysis, [])["annexes"]["asvs"]
    after = closure.closure_context(analysis, [artefact])["annexes"]["asvs"]
    assert sum(row["findings"] for row in after) == sum(row["findings"] for row in before) + 1


def test_hits_are_ordered_by_severity_then_rule_then_path(tmp_path: Path) -> None:
    _write(tmp_path, "a/id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
    _write(tmp_path, "b/.env", "K=v\n")
    _sparse(tmp_path, "0/big.log", b"x", 2 * 1024 * 1024)
    assert [hit.rule_id for hit in scan_artefacts(tmp_path).hits] == [ENV, PRIVATE_KEY, LOG]
