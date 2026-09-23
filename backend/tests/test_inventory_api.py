"""The inventory: correlation, VEX from the triage, the panel, exports, sync and import.

Every handler here reads the mirror; the two mutations only enqueue. In this
suite the queue is inline, so `download` is replaced by a fixture writer —
no test ever reaches the network, and a test that did would fail loudly.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, ToolCategory, Verdict
from app.audit.models import AuditLogEntry
from app.auth.models import User
from app.core.config import get_settings
from app.inventory import importers, service, sync
from app.inventory.correlation import VEX_EXPLOITABLE, VEX_IN_TRIAGE, VEX_NOT_AFFECTED, correlate
from app.inventory.models import CryptoAsset, SyncSource, SyncStatus, VulnDbSync, Vulnerability
from app.projects.models import Project
from tests.inventory_support import (
    LODASH_CVE,
    LODASH_GHSA,
    attach_sbom,
    component,
    nvd_item,
    osv_record,
    write_nvd_feed,
    write_osv_zip,
)
from tests.support import login, make_finding, seed_done_analysis

MAX = 64 * 1024 * 1024
HOSTILE = "<img src=x onerror=alert(1)>"


def _mirror(db: Session, tmp_path: Path, records: list[dict[str, Any]] | None = None) -> None:
    dump = write_osv_zip(
        tmp_path / "mirror.zip",
        records
        if records is not None
        else [
            osv_record(LODASH_GHSA),
            osv_record(
                "GHSA-axios-1",
                name="axios",
                introduced="0",
                fixed="0.21.1",
                aliases=["CVE-2020-28168"],
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            ),
            osv_record(
                "GHSA-noscore",
                name="minimist",
                fixed="1.2.6",
                aliases=["CVE-2021-44906"],
                vector=None,
            ),
        ],
    )
    importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX)


def _sbom_components() -> list[dict[str, Any]]:
    return [
        component("lodash", "4.17.15", "pkg:npm/lodash@4.17.15", ["MIT"]),
        component("axios", "0.21.0", "pkg:npm/axios@0.21.0", ["MIT"]),
        component("minimist", "1.2.5", "pkg:npm/minimist@1.2.5"),
        component("express", "4.19.2", "pkg:npm/express@4.19.2", ["MIT"]),
        component(HOSTILE, "=1+1", f"pkg:npm/{HOSTILE}@1.0.0"),
        component("weird", "latest", "pkg:npm/lodash@latest"),
    ]


def _sca(ordinal: int, advisory_id: str, package: str, verdict: Verdict | None) -> Any:
    return make_finding(
        ordinal,
        category=ToolCategory.SCA,
        tools=["osv-scanner"],
        rule_id=advisory_id,
        cwe=1395,
        advisory={"id": advisory_id, "package": package, "version": "x", "fixed": None},
        verdict=verdict,
        verdict_justification=None if verdict is None else "Justificación escrita del analista",
        verdict_by_username=None if verdict is None else "mmarin",
    )


@pytest.fixture
def seeded(db: Session, tmp_path: Path) -> Analysis:
    _mirror(db, tmp_path)
    analysis = seed_done_analysis(
        db,
        [
            _sca(0, LODASH_GHSA, "lodash", Verdict.CONFIRMED),
            _sca(1, "GHSA-axios-1", "axios", Verdict.FALSE_POSITIVE),
        ],
    )
    attach_sbom(db, analysis, _sbom_components())
    return analysis


# --- correlation ---------------------------------------------------------------


def test_correlation_matches_by_purl_and_version_range(seeded: Analysis, db: Session) -> None:
    inventory = service.inventory_of(db, seeded)
    by_component = {m.component.name: m for m in inventory.matches}
    assert set(by_component) == {"lodash", "axios", "minimist"}
    lodash = by_component["lodash"]
    assert lodash.cve == LODASH_CVE and lodash.fixed_in == "4.17.19"
    assert lodash.vex_state == VEX_EXPLOITABLE
    assert lodash.justification == "Justificación escrita del analista"
    axios = by_component["axios"]
    assert axios.vex_state == VEX_NOT_AFFECTED and not axios.open
    assert by_component["minimist"].vex_state == VEX_IN_TRIAGE
    assert [c.name for c in inventory.uncomparable] == ["weird"]
    assert len(inventory.open_matches) == 2
    assert inventory.vulnerable_component_count == 2


def test_an_unscored_osv_match_borrows_the_nvd_score(
    seeded: Analysis, db: Session, tmp_path: Path
) -> None:
    before = service.inventory_of(db, seeded)
    assert next(m for m in before.matches if m.component.name == "minimist").score is None
    feed = write_nvd_feed(
        tmp_path / "nvd.json.gz",
        [
            nvd_item(
                "CVE-2021-44906", score=5.6, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"
            )
        ],
    )
    importers.import_dump(db, feed, kind=importers.NVD_JSON_GZ, max_bytes=MAX)
    after = service.inventory_of(db, seeded)
    minimist = next(m for m in after.matches if m.component.name == "minimist")
    assert minimist.score == 5.6 and minimist.severity is not None
    assert minimist.summary == "Prototype pollution in lodash", "OSV's text is kept"


def test_a_verdict_is_never_borrowed_across_packages_and_matches_are_deduplicated(
    db: Session, tmp_path: Path
) -> None:
    """One advisory, two packages: the analyst discarded it for lodash-es only."""
    record = osv_record(LODASH_GHSA)
    record["affected"].append(
        {
            "package": {"ecosystem": "npm", "name": "lodash-es"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}],
        }
    )
    # The same package listed twice must still be ONE match per component.
    record["affected"].append(dict(record["affected"][0]))
    _mirror(db, tmp_path, [record])
    analysis = seed_done_analysis(db, [_sca(0, LODASH_GHSA, "lodash-es", Verdict.FALSE_POSITIVE)])
    attach_sbom(
        db,
        analysis,
        [
            component("lodash", "4.17.15", "pkg:npm/lodash@4.17.15"),
            component("lodash-es", "4.17.15", "pkg:npm/lodash-es@4.17.15"),
        ],
    )
    inventory = service.inventory_of(db, analysis)
    states: dict[str, list[str]] = {}
    for match in inventory.matches:
        states.setdefault(match.component.name, []).append(match.vex_state)
    assert states == {"lodash": [VEX_IN_TRIAGE], "lodash-es": [VEX_NOT_AFFECTED]}


def test_a_withdrawn_advisory_and_an_unknown_package_do_not_match(
    db: Session, tmp_path: Path
) -> None:
    _mirror(db, tmp_path, [osv_record(LODASH_GHSA, withdrawn="2024-01-01T00:00:00Z")])
    analysis = seed_done_analysis(db, [])
    attach_sbom(db, analysis, [component("lodash", "4.17.15", "pkg:npm/lodash@4.17.15")])
    result = correlate(db, service.inventory_of(db, analysis).components, [])
    assert result.matches == []


def test_outdated_is_a_newer_version_known_to_the_local_copy(seeded: Analysis, db: Session) -> None:
    inventory = service.inventory_of(db, seeded)
    names = {inventory.components[i].name: newer for i, newer in inventory.outdated.items()}
    assert names == {"lodash": "4.17.19", "axios": "0.21.1", "minimist": "1.2.6"}
    # Another project of the factory carrying express 4.20.0 makes ours outdated too.
    other = seed_done_analysis(db, [])
    attach_sbom(db, other, [component("express", "4.20.0", "pkg:npm/express@4.20.0")])
    overview = service.overview(db, get_settings())
    ours = next(row for row in overview["projects"] if row["analysis_id"] == str(seeded.id))
    assert ours["outdated"] == 4


def test_vulnerable_components_count_components_not_advisories(
    client: TestClient, seeded: Analysis, db: Session, tmp_path: Path, developer: User
) -> None:
    _mirror(
        db, tmp_path, [osv_record("GHSA-second-lodash", fixed="4.17.21", aliases=["CVE-2021-1"])]
    )
    body = client.get("/api/v1/inventory", headers=login(client, "cperez")).json()
    assert body["totals"]["open_cves"] == 3
    assert body["totals"]["vulnerable_components"] == 2


# --- the panel -----------------------------------------------------------------


def test_the_panel_is_readable_by_every_role_and_reads_the_mirror(
    client: TestClient, seeded: Analysis, analyst: User, developer: User, admin: User
) -> None:
    for username in ("mmarin", "cperez", "amedina"):
        response = client.get("/api/v1/inventory", headers=login(client, username))
        assert response.status_code == 200, response.text
    body = client.get("/api/v1/inventory", headers=login(client, "cperez")).json()
    assert body["totals"]["projects"] == 1
    assert body["totals"]["components"] == 6
    assert body["totals"]["open_cves"] == 2
    assert body["totals"]["vulnerable_components"] == 2
    assert body["totals"]["not_affected"] == 1
    assert body["totals"]["outdated"] == 3
    assert body["totals"]["uncomparable"] == 1
    assert body["totals"]["by_severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,  # axios is medium but "No aplica": it leaves every open count
        "low": 0,
        "info": 0,
    }
    assert {row["name"]: row["count"] for row in body["licenses"]} == {"MIT": 3}
    assert body["unlicensed"] == 3
    rows = {row["component"]: row for row in body["open"]}
    assert rows["lodash"]["cve"] == LODASH_CVE and rows["lodash"]["vex_state"] == "exploitable"
    assert rows["axios"]["vex_state"] == "not_affected"
    assert rows["axios"]["justification"] == "Justificación escrita del analista"
    project_row = body["projects"][0]
    assert project_row["open_cves"] == 2 and project_row["trend"] is None
    assert body["vulndb"]["sync_enabled"] is True
    assert body["vulndb"]["last_update"] is None and body["vulndb"]["runs"] == [], (
        "a direct import_dump call is not a recorded run; the job records runs"
    )


def test_the_trend_compares_the_two_latest_analyses_of_a_project(
    client: TestClient, seeded: Analysis, db: Session, analyst: User
) -> None:
    project = db.get(Project, seeded.project_id)
    assert project is not None
    newer = Analysis(
        project_id=project.id,
        source_kind=seeded.source_kind,
        source_ref="v2.zip",
        status=seeded.status,
    )
    db.add(newer)
    db.commit()
    attach_sbom(db, newer, [component("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")])
    body = client.get("/api/v1/inventory", headers=login(client, "mmarin")).json()
    row = body["projects"][0]
    assert row["analysis_id"] == str(newer.id)
    assert row["ordinal"] == 2
    assert row["open_cves"] == 0
    assert row["trend"] == -2, "two open CVEs fewer than the previous version"
    assert row["previous_analysis_id"] == str(seeded.id)


def test_the_panel_stops_at_the_component_cap_and_says_so(
    client: TestClient, seeded: Analysis, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    capped = get_settings().model_copy(update={"max_inventory_components": 100})
    monkeypatch.setattr("app.inventory.router.get_settings", lambda: capped)
    body = client.get("/api/v1/inventory", headers=login(client, "mmarin")).json()
    assert body["totals"]["capped"] is False
    tiny = get_settings().model_copy(update={"max_inventory_components": 100})
    tiny.__dict__["max_inventory_components"] = 4  # below the validator's floor, on purpose
    monkeypatch.setattr("app.inventory.router.get_settings", lambda: tiny)
    body = client.get("/api/v1/inventory", headers=login(client, "mmarin")).json()
    assert body["totals"]["capped"] is True
    assert body["totals"]["components"] == 4


# --- exports -------------------------------------------------------------------


def test_the_vex_document_is_cyclonedx_1_6_with_the_analysts_states(
    client: TestClient, seeded: Analysis, developer: User
) -> None:
    response = client.get(
        f"/api/v1/inventory/analyses/{seeded.id}/vex", headers=login(client, "cperez")
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert 'filename="analisis-caja-blanca-' in response.headers["content-disposition"]
    document = json.loads(response.content)
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
    assert document["serialNumber"].startswith("urn:uuid:")
    states = {v["affects"][0]["ref"]: v["analysis"] for v in document["vulnerabilities"]}
    assert states["pkg:npm/lodash@4.17.15"]["state"] == "exploitable"
    assert states["pkg:npm/axios@0.21.0"] == {
        "state": "not_affected",
        "detail": "Justificación escrita del analista",
    }
    assert states["pkg:npm/minimist@1.2.5"]["state"] == "in_triage"
    lodash = next(v for v in document["vulnerabilities"] if v["id"] == LODASH_GHSA)
    assert lodash["ratings"][0]["score"] == 7.4 and lodash["ratings"][0]["method"] == "CVSSv31"
    assert lodash["recommendation"] == "update to 4.17.19"
    assert {r["id"] for r in lodash["references"]} == {LODASH_CVE}


def test_the_cbom_document_lists_one_asset_per_algorithm_with_occurrences(
    client: TestClient, seeded: Analysis, db: Session, developer: User
) -> None:
    db.add_all(
        [
            CryptoAsset(
                analysis_id=seeded.id,
                primitive="hash",
                algorithm="SHA-1",
                path=f"auth/{HOSTILE}.js",
                line=18,
                weak=True,
                rule_id="crypto-inventory-js-weak-hash",
            ),
            CryptoAsset(
                analysis_id=seeded.id,
                primitive="hash",
                algorithm="SHA-1",
                path="auth/other.js",
                line=3,
                weak=True,
                rule_id="crypto-inventory-js-weak-hash",
            ),
            CryptoAsset(
                analysis_id=seeded.id,
                primitive="cipher",
                algorithm="AES-256-GCM",
                path="crypto/files.js",
                line=None,
                weak=False,
                rule_id="crypto-inventory-js-cipher",
            ),
            CryptoAsset(
                analysis_id=seeded.id,
                primitive="protocol",
                algorithm="TLSV1",
                path="server.js",
                line=9,
                weak=True,
                rule_id="crypto-inventory-js-weak-protocol",
            ),
        ]
    )
    db.commit()
    response = client.get(
        f"/api/v1/inventory/analyses/{seeded.id}/cbom", headers=login(client, "cperez")
    )
    assert response.status_code == 200
    document = json.loads(response.content)
    assert document["specVersion"] == "1.6"
    assets = {c["name"]: c for c in document["components"]}
    assert all(c["type"] == "cryptographic-asset" for c in document["components"])
    sha1 = assets["SHA-1"]
    assert sha1["cryptoProperties"] == {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "hash"},
    }
    assert sha1["evidence"]["occurrences"] == [
        {"location": f"auth/{HOSTILE}.js", "line": 18},
        {"location": "auth/other.js", "line": 3},
    ]
    assert sha1["properties"] == [{"name": "dioptra:weak", "value": "true"}]
    assert assets["AES-256-GCM"]["properties"][0]["value"] == "false"
    assert assets["AES-256-GCM"]["evidence"]["occurrences"] == [{"location": "crypto/files.js"}]
    assert assets["TLSV1"]["cryptoProperties"]["assetType"] == "protocol"
    # The panel sees the same rows, weak first.
    panel = client.get("/api/v1/inventory", headers=login(client, "cperez")).json()
    assert panel["crypto_weak"] == 3
    assert [row["algorithm"] for row in panel["crypto"]] == ["SHA-1", "TLSV1", "AES-256-GCM"]
    assert panel["crypto"][0]["occurrences"] == 2


def test_the_csv_neutralises_formulas_and_keeps_hostile_names_as_text(
    client: TestClient, seeded: Analysis, developer: User
) -> None:
    response = client.get(
        f"/api/v1/inventory/analyses/{seeded.id}/components.csv", headers=login(client, "cperez")
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][0] == "Proyecto" and rows[0][1] == "Componente"
    by_name = {row[1]: row for row in rows[1:]}
    assert by_name[HOSTILE][2] == "'=1+1", "a cell starting with = is prefixed"
    assert by_name["lodash"][6] == LODASH_CVE
    assert by_name["lodash"][7] == "high"
    assert by_name["lodash"][8] == "4.17.19"
    assert by_name["axios"][6] == "", "a not-affected CVE is not an open one"
    assert by_name["express"][6] == ""
    assert "\r\n" in response.text
    assert '"' + HOSTILE + '"' in response.text, "quoted, never interpreted"


def test_exports_need_an_sbom(client: TestClient, db: Session, developer: User) -> None:
    analysis = seed_done_analysis(db, [])
    headers = login(client, "cperez")
    for suffix in ("vex", "components.csv"):
        response = client.get(f"/api/v1/inventory/analyses/{analysis.id}/{suffix}", headers=headers)
        assert response.status_code == 404
        assert response.json()["message_key"] == "errors.inventory.sbomMissing"
    cbom = client.get(f"/api/v1/inventory/analyses/{analysis.id}/cbom", headers=headers)
    assert cbom.status_code == 200, "a CBOM exists without an SBOM: it comes from the source"
    assert json.loads(cbom.content)["components"] == []


# --- sync and import: the handlers only enqueue ----------------------------------


def _fake_download(records: list[dict[str, Any]]) -> Any:
    def fake(url: str, destination: Path, *, max_bytes: int, timeout_seconds: int) -> int:
        del max_bytes, timeout_seconds
        assert url.startswith("https://")
        if url.endswith(".zip"):
            write_osv_zip(destination, records)
        else:
            write_nvd_feed(destination, [nvd_item()])
        return destination.stat().st_size

    return fake


def test_the_analyst_requests_a_sync_and_the_job_fills_the_mirror(
    client: TestClient, db: Session, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    fake = _fake_download([osv_record(LODASH_GHSA)])

    def counting(url: str, destination: Path, **kwargs: Any) -> int:
        calls.append(url)
        return int(fake(url, destination, **kwargs))

    monkeypatch.setattr(sync, "download", counting)
    only_npm = get_settings().model_copy(
        update={"vulndb_osv_ecosystems": ("npm",), "vulndb_nvd_years": (2020,)}
    )
    monkeypatch.setattr(sync, "get_settings", lambda: only_npm)
    # A fresh mirror would make a SCHEDULED run a no-op; the panel's button
    # must still download ("Actualizar la base ahora" means now).
    from app.core.clock import utc_now  # noqa: PLC0415

    db.add(
        VulnDbSync(
            source=SyncSource.OSV, status=SyncStatus.OK, started_at=utc_now(), finished_at=utc_now()
        )
    )
    db.commit()
    response = client.post(
        "/api/v1/inventory/vulndb/sync",
        json={"justification": "Actualización semanal programada por el analista"},
        headers=login(client, "mmarin"),
    )
    assert response.status_code == 202, response.text
    assert calls == [
        "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2020.json.gz",
    ]
    assert db.get(Vulnerability, LODASH_GHSA) is not None
    assert db.get(Vulnerability, LODASH_CVE) is not None
    runs = [
        run
        for run in db.scalars(select(VulnDbSync).order_by(VulnDbSync.started_at))
        if run.requested_by_username is not None  # the seeded fresh run has none
    ]
    assert [(run.source.value, run.status) for run in runs] == [
        ("osv", SyncStatus.OK),
        ("nvd", SyncStatus.OK),
    ]
    assert runs[0].requested_by_username == "mmarin"
    actions = [
        (row.action, row.actor_username, row.justification)
        for row in db.scalars(select(AuditLogEntry).order_by(AuditLogEntry.occurred_at))
        if row.action.startswith("vulndb")
    ]
    assert (
        "vulndb.sync.request",
        "mmarin",
        "Actualización semanal programada por el analista",
    ) in actions
    assert ("vulndb.sync", "mmarin", None) in actions
    panel = client.get("/api/v1/inventory", headers=login(client, "mmarin")).json()
    assert panel["vulndb"]["last_update"] is not None
    assert [run["source"] for run in panel["vulndb"]["runs"]][:2] == ["nvd", "osv"]


def test_a_failed_download_is_a_recorded_run_never_a_crash(
    client: TestClient, db: Session, admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(url: str, destination: Path, **kwargs: Any) -> int:
        del destination, kwargs
        raise sync.DownloadFailed(url)

    monkeypatch.setattr(sync, "download", failing)
    one = get_settings().model_copy(
        update={"vulndb_osv_ecosystems": ("npm",), "vulndb_nvd_years": ()}
    )
    monkeypatch.setattr(sync, "get_settings", lambda: one)
    response = client.post(
        "/api/v1/inventory/vulndb/sync",
        json={"justification": "Prueba de sincronización desde el panel"},
        headers=login(client, "amedina"),
    )
    assert response.status_code == 202
    run = db.scalars(select(VulnDbSync)).one()
    assert run.status is SyncStatus.FAILED
    assert run.detail is not None and "vulndb_download_failed" in run.detail
    assert sync.last_update(db) is None


def test_a_sync_request_needs_a_written_reason_and_the_right_role(
    client: TestClient, developer: User, analyst: User, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never(*args: Any, **kwargs: Any) -> int:
        del args, kwargs
        raise AssertionError("a refused request must never reach the network")

    # A role regression here would otherwise run the inline job and phone home.
    monkeypatch.setattr(sync, "download", never)
    denied = client.post(
        "/api/v1/inventory/vulndb/sync",
        json={"justification": "Quiero actualizar la base"},
        headers=login(client, "cperez"),
    )
    assert denied.status_code == 403
    denial = db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "authz.denied")).one()
    assert (denial.actor_username, denial.target) == (
        "cperez",
        "POST /api/v1/inventory/vulndb/sync",
    )
    short = client.post(
        "/api/v1/inventory/vulndb/sync",
        json={"justification": "corto"},
        headers=login(client, "mmarin"),
    )
    assert short.status_code == 422
    assert short.json()["message_key"] == "errors.workflow.justificationRequired"
    assert db.scalars(select(VulnDbSync)).first() is None


def test_a_sync_request_is_refused_when_the_operator_disabled_it(
    client: TestClient, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    off = get_settings().model_copy(update={"vulndb_sync_enabled": False})
    monkeypatch.setattr(sync, "get_settings", lambda: off)
    response = client.post(
        "/api/v1/inventory/vulndb/sync",
        json={"justification": "Intento con la sincronización apagada"},
        headers=login(client, "mmarin"),
    )
    assert response.status_code == 409
    assert response.json()["message_key"] == "errors.inventory.syncDisabled"


def test_the_download_refuses_plain_http(tmp_path: Path) -> None:
    with pytest.raises(sync.DownloadFailed):
        sync.download(
            "http://example.invalid/all.zip", tmp_path / "x", max_bytes=10, timeout_seconds=1
        )
    assert not (tmp_path / "x").exists()


def test_a_dump_import_is_spooled_by_the_api_and_parsed_by_the_job(
    client: TestClient, db: Session, analyst: User, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def never(*args: Any, **kwargs: Any) -> int:
        del args, kwargs
        raise AssertionError("an import must never download anything")

    monkeypatch.setattr(sync, "download", never)
    dump = write_osv_zip(tmp_path / "npm-all.zip", [osv_record(LODASH_GHSA)])
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("npm-all.zip", dump.read_bytes(), "application/zip")},
        data={"justification": "Equipo sin salida a internet: se importa el archivo"},
        headers=login(client, "mmarin"),
    )
    assert response.status_code == 202, response.text
    token = response.json()["token"]
    assert db.get(Vulnerability, LODASH_GHSA) is not None
    run = db.scalars(select(VulnDbSync)).one()
    assert run.source.value == "import" and run.status is SyncStatus.OK
    assert run.records_stored == 1
    spool = get_settings().vulndb_spool_dir
    assert not list(spool.glob(f"{token}*")), "the spooled file is deleted after the job"
    actions = [
        row.action for row in db.scalars(select(AuditLogEntry)) if row.action.startswith("vulndb")
    ]
    assert actions == ["vulndb.import.request", "vulndb.import"]


def test_an_invalid_dump_import_is_a_recorded_failure(
    client: TestClient, db: Session, admin: User
) -> None:
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("feed.json", b'{"nothing": true}', "application/json")},
        data={"justification": "Archivo que no es un volcado válido"},
        headers=login(client, "amedina"),
    )
    assert response.status_code == 202
    run = db.scalars(select(VulnDbSync)).one()
    assert run.status is SyncStatus.FAILED and run.detail is not None
    assert "dump_invalid" in run.detail
    assert not list(get_settings().vulndb_spool_dir.iterdir()), "the spool never keeps a file"


def test_an_import_refuses_unknown_kinds_oversized_and_empty_uploads(
    client: TestClient, admin: User, monkeypatch: pytest.MonkeyPatch, db: Session
) -> None:
    headers = login(client, "amedina")
    unknown = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("dump.tar", b"xx", "application/octet-stream")},
        data={"justification": "Formato de archivo no reconocido"},
        headers=headers,
    )
    assert unknown.status_code == 422
    assert unknown.json()["message_key"] == "errors.inventory.dumpKindUnknown"
    empty = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("all.zip", b"", "application/zip")},
        data={"justification": "Archivo vacío enviado por error"},
        headers=headers,
    )
    assert empty.status_code == 422
    tiny = get_settings().model_copy(update={"vulndb_max_dump_bytes": 1024})
    monkeypatch.setattr(sync, "get_settings", lambda: tiny)
    monkeypatch.setattr("app.inventory.router.get_settings", lambda: tiny)
    big = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("all.zip", b"x" * 4096, "application/zip")},
        data={"justification": "Archivo que supera el tamaño máximo"},
        headers=headers,
    )
    assert big.status_code == 413
    assert db.scalars(select(VulnDbSync)).first() is None
    assert not list(get_settings().vulndb_spool_dir.iterdir())


def test_the_developer_cannot_import_a_dump(client: TestClient, developer: User) -> None:
    response = client.post(
        "/api/v1/inventory/vulndb/import",
        files={"file": ("all.zip", b"xx", "application/zip")},
        data={"justification": "El programador no puede tocar la base"},
        headers=login(client, "cperez"),
    )
    assert response.status_code == 403


def test_the_scheduled_job_skips_a_fresh_mirror_and_records_a_disabled_sync(
    db: Session, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, app: Any
) -> None:
    del app  # the fixture routes the job's session factory through the test database
    calls: list[str] = []

    def counting(url: str, destination: Path, **kwargs: Any) -> int:
        calls.append(url)
        return int(_fake_download([osv_record(LODASH_GHSA)])(url, destination, **kwargs))

    monkeypatch.setattr(sync, "download", counting)
    settings = get_settings().model_copy(
        update={"vulndb_osv_ecosystems": ("npm",), "vulndb_nvd_years": ()}
    )
    monkeypatch.setattr(sync, "get_settings", lambda: settings)
    sync.run_sync_job(None)
    sync.run_sync_job(None)
    assert len(calls) == 1, "a mirror younger than the interval is not downloaded again"
    sync.run_sync_job(None, force=True)
    assert len(calls) == 2
    off = settings.model_copy(update={"vulndb_sync_enabled": False})
    monkeypatch.setattr(sync, "get_settings", lambda: off)
    sync.run_sync_job("mmarin")
    runs = list(db.scalars(select(VulnDbSync).order_by(VulnDbSync.started_at)))
    assert runs[-1].status is SyncStatus.SKIPPED
