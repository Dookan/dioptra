"""Dump importers: a dump is untrusted input whatever its origin (survey §2)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Severity
from app.inventory import importers
from app.inventory.errors import DumpInvalid, DumpTooLarge
from app.inventory.models import (
    MAX_ALIASES,
    MAX_PACKAGES_PER_RECORD,
    MAX_SUMMARY_CHARS,
    Vulnerability,
    VulnerabilityPackage,
    VulnerabilitySource,
)
from tests.inventory_support import (
    LODASH_CVE,
    LODASH_GHSA,
    nvd_item,
    osv_record,
    write_nvd_feed,
    write_osv_zip,
)

MAX = 64 * 1024 * 1024


def _all(db: Session) -> dict[str, Vulnerability]:
    return {row.id: row for row in db.scalars(select(Vulnerability))}


def test_an_osv_zip_is_imported_with_its_packages_and_score(db: Session, tmp_path: Path) -> None:
    dump = write_osv_zip(
        tmp_path / "all.zip",
        [
            osv_record(LODASH_GHSA),
            osv_record(
                "PYSEC-2021-1",
                ecosystem="PyPI",
                name="Django",
                versions=["3.2", "3.2.1"],
                fixed=None,
                aliases=["CVE-2021-1"],
                vector=None,
            ),
        ],
    )
    stats = importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX)
    assert (stats.seen, stats.stored, stats.skipped) == (2, 2, 0)
    rows = _all(db)
    lodash = rows[LODASH_GHSA]
    assert lodash.source is VulnerabilitySource.OSV
    assert lodash.aliases == [LODASH_CVE]
    assert lodash.score == 7.4 and lodash.severity is Severity.HIGH
    assert lodash.summary == "Prototype pollution in lodash"
    assert lodash.modified_at is not None and lodash.modified_at.tzinfo is not None
    package = db.scalars(
        select(VulnerabilityPackage).where(VulnerabilityPackage.vulnerability_id == LODASH_GHSA)
    ).one()
    assert (package.ecosystem, package.name) == ("npm", "lodash")
    assert package.ranges == [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}
    ]
    django = rows["PYSEC-2021-1"]
    assert django.score is None
    assert (
        db.scalars(
            select(VulnerabilityPackage).where(
                VulnerabilityPackage.vulnerability_id == "PYSEC-2021-1"
            )
        )
        .one()
        .name
        == "django"
    ), "PyPI names are normalised like PEP 503"


def test_malformed_records_are_counted_and_skipped_never_raised(
    db: Session, tmp_path: Path
) -> None:
    dump = write_osv_zip(
        tmp_path / "all.zip",
        [osv_record(LODASH_GHSA), "not json at all", {"no": "id"}, 42],
        extra={"README": b"ignored, not .json", "dir/": b""},
    )
    stats = importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX)
    assert stats.stored == 1
    assert stats.skipped == 3
    assert set(_all(db)) == {LODASH_GHSA}


def test_reimport_is_idempotent_and_an_older_copy_never_overwrites(
    db: Session, tmp_path: Path
) -> None:
    newer = osv_record(LODASH_GHSA, modified="2024-06-01T00:00:00Z", summary="newer")
    older = osv_record(LODASH_GHSA, modified="2023-01-01T00:00:00Z", summary="older", fixed="9.9.9")
    importers.import_dump(
        db, write_osv_zip(tmp_path / "a.zip", [newer]), kind=importers.OSV_ZIP, max_bytes=MAX
    )
    stats = importers.import_dump(
        db, write_osv_zip(tmp_path / "b.zip", [older, newer]), kind=importers.OSV_ZIP, max_bytes=MAX
    )
    assert (stats.stored, stats.skipped) == (0, 2)
    row = _all(db)[LODASH_GHSA]
    assert row.summary == "newer"
    assert len(row.packages) == 1, "packages are replaced wholesale, never accumulated"
    assert row.packages[0].ranges[0]["events"][1] == {"fixed": "4.17.19"}


def test_a_newer_copy_replaces_the_packages(db: Session, tmp_path: Path) -> None:
    first = osv_record(LODASH_GHSA, modified="2024-01-01T00:00:00Z")
    second = osv_record(LODASH_GHSA, modified="2024-02-01T00:00:00Z", name="lodash-es")
    for index, record in enumerate([first, second]):
        importers.import_dump(
            db,
            write_osv_zip(tmp_path / f"{index}.zip", [record]),
            kind=importers.OSV_ZIP,
            max_bytes=MAX,
        )
    packages = list(
        db.scalars(
            select(VulnerabilityPackage).where(VulnerabilityPackage.vulnerability_id == LODASH_GHSA)
        )
    )
    assert [p.name for p in packages] == ["lodash-es"]


def test_every_field_is_capped_at_persistence(db: Session, tmp_path: Path) -> None:
    record = osv_record(LODASH_GHSA, summary="x" * 10_000)
    record["aliases"] = [f"CVE-2020-{i}" for i in range(MAX_ALIASES + 50)]
    record["affected"] = [
        {"package": {"ecosystem": "npm", "name": f"pkg-{i}"}, "versions": [str(i)]}
        for i in range(MAX_PACKAGES_PER_RECORD + 20)
    ]
    dump = write_osv_zip(tmp_path / "all.zip", [record])
    importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX)
    row = _all(db)[LODASH_GHSA]
    assert len(row.summary or "") == MAX_SUMMARY_CHARS
    assert len(row.aliases) == MAX_ALIASES
    assert len(row.packages) == MAX_PACKAGES_PER_RECORD


def test_a_withdrawn_record_is_stored_as_withdrawn(db: Session, tmp_path: Path) -> None:
    dump = write_osv_zip(
        tmp_path / "all.zip", [osv_record(LODASH_GHSA, withdrawn="2024-03-01T00:00:00Z")]
    )
    importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX)
    assert _all(db)[LODASH_GHSA].withdrawn is True


def test_an_oversized_or_entry_flooded_zip_is_refused(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = write_osv_zip(tmp_path / "big.zip", [osv_record(LODASH_GHSA)])
    with pytest.raises(DumpTooLarge):
        importers.import_dump(db, big, kind=importers.OSV_ZIP, max_bytes=10)
    monkeypatch.setattr(importers, "MAX_ZIP_ENTRIES", 1)
    flood = write_osv_zip(tmp_path / "flood.zip", [osv_record("A-1"), osv_record("A-2")])
    with pytest.raises(DumpTooLarge):
        importers.import_dump(db, flood, kind=importers.OSV_ZIP, max_bytes=MAX)
    assert _all(db) == {}, "nothing is stored from a refused dump"


def test_a_decompression_bomb_is_refused_by_the_declared_ratio(db: Session, tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.json", b"0" * (2 * 1024 * 1024))
    size = bomb.stat().st_size
    with pytest.raises(DumpTooLarge):
        importers.import_dump(db, bomb, kind=importers.OSV_ZIP, max_bytes=size + 1)


def test_an_oversized_single_record_is_skipped_not_loaded(db: Session, tmp_path: Path) -> None:
    dump = tmp_path / "all.zip"
    with zipfile.ZipFile(dump, "w") as archive:
        archive.writestr(
            "huge.json", b'{"id": "X", "pad": "' + b"a" * (importers.MAX_RECORD_BYTES + 5) + b'"}'
        )
        archive.writestr("ok.json", json.dumps(osv_record(LODASH_GHSA)))
    stats = importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX * 4)
    assert (stats.stored, stats.skipped) == (1, 1)


def test_not_a_zip_is_a_typed_error(db: Session, tmp_path: Path) -> None:
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"PK\x03\x04 not really")
    with pytest.raises(DumpInvalid):
        importers.import_dump(db, junk, kind=importers.OSV_ZIP, max_bytes=MAX)


def test_an_nvd_feed_is_streamed_record_by_record(db: Session, tmp_path: Path) -> None:
    feed = write_nvd_feed(
        tmp_path / "nvdcve-2.0-2020.json.gz",
        [
            nvd_item(LODASH_CVE),
            nvd_item(
                "CVE-2021-2", score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ),
            {"cve": {"id": "not-a-cve"}},
            "junk",
        ],
    )
    stats = importers.import_dump(db, feed, kind=importers.NVD_JSON_GZ, max_bytes=MAX)
    assert (stats.seen, stats.stored, stats.skipped) == (4, 2, 2)
    rows = _all(db)
    lodash = rows[LODASH_CVE]
    assert lodash.source is VulnerabilitySource.NVD
    assert lodash.score == 7.4 and lodash.severity is Severity.HIGH
    assert lodash.summary == "Prototype pollution in lodash before 4.17.19."
    assert rows["CVE-2021-2"].severity is Severity.CRITICAL
    assert lodash.packages == [], "NVD names products by CPE: never correlated by itself"


def test_a_plain_json_feed_is_accepted_too(db: Session, tmp_path: Path) -> None:
    feed = write_nvd_feed(tmp_path / "feed.json", [nvd_item()], gzipped=False)
    stats = importers.import_dump(db, feed, kind=importers.NVD_JSON, max_bytes=MAX)
    assert stats.stored == 1


def test_a_feed_without_the_array_or_with_a_giant_record_is_refused(
    db: Session, tmp_path: Path
) -> None:
    empty = tmp_path / "empty.json"
    empty.write_bytes(b'{"format": "NVD_CVE"}')
    with pytest.raises(DumpInvalid):
        importers.import_dump(db, empty, kind=importers.NVD_JSON, max_bytes=MAX)
    giant = tmp_path / "giant.json"
    giant.write_bytes(
        b'{"vulnerabilities": [{"cve": {"id": "CVE-1", "pad": "'
        + b"a" * (importers.MAX_RECORD_BYTES * 3)
        + b'"}}]}'
    )
    with pytest.raises(DumpInvalid):
        importers.import_dump(db, giant, kind=importers.NVD_JSON, max_bytes=MAX * 4)


def test_a_feed_that_inflates_past_the_ratio_is_refused(db: Session, tmp_path: Path) -> None:
    feed = write_nvd_feed(
        tmp_path / "bomb.json.gz", [{"cve": {"id": "CVE-1", "pad": "a" * 200_000}}]
    )
    with pytest.raises(DumpTooLarge):
        importers.import_dump(
            db, feed, kind=importers.NVD_JSON_GZ, max_bytes=feed.stat().st_size + 1
        )


def test_an_unknown_kind_is_refused(db: Session, tmp_path: Path) -> None:
    with pytest.raises(DumpInvalid):
        importers.import_dump(db, tmp_path / "x", kind="tarball", max_bytes=MAX)


def test_nvd_never_overwrites_a_score_osv_already_has(db: Session, tmp_path: Path) -> None:
    osv = osv_record(LODASH_CVE, aliases=[], modified="2024-01-01T00:00:00Z")  # vector → 7.4
    importers.import_dump(
        db, write_osv_zip(tmp_path / "osv.zip", [osv]), kind=importers.OSV_ZIP, max_bytes=MAX
    )
    feed = write_nvd_feed(
        tmp_path / "nvd.json.gz",
        [nvd_item(LODASH_CVE, score=9.8, modified="2024-06-01T00:00:00.000")],
    )
    importers.import_dump(db, feed, kind=importers.NVD_JSON_GZ, max_bytes=MAX)
    row = _all(db)[LODASH_CVE]
    assert row.score == 7.4, "enrichment fills gaps; it never replaces OSV's own score"


def test_osv_fallbacks_severity_word_ecosystem_suffix_and_nvd_rejected(
    db: Session, tmp_path: Path
) -> None:
    worded = osv_record("GHSA-worded", vector=None)
    worded["database_specific"] = {"severity": "HIGH"}
    suffixed = osv_record("GHSA-suffixed", ecosystem="Maven:https://repo.example", name="g:a")
    dump = write_osv_zip(tmp_path / "osv.zip", [worded, suffixed])
    importers.import_dump(db, dump, kind=importers.OSV_ZIP, max_bytes=MAX)
    rows = _all(db)
    assert rows["GHSA-worded"].severity is Severity.HIGH
    assert rows["GHSA-suffixed"].packages[0].ecosystem == "Maven"
    rejected = nvd_item("CVE-2020-9999")
    rejected["cve"]["vulnStatus"] = "Rejected"
    importers.import_dump(
        db,
        write_nvd_feed(tmp_path / "nvd.json.gz", [rejected]),
        kind=importers.NVD_JSON_GZ,
        max_bytes=MAX,
    )
    assert _all(db)["CVE-2020-9999"].withdrawn is True


def test_an_empty_feed_is_refused_not_imported_as_ok(db: Session, tmp_path: Path) -> None:
    """The sync path can deliver a 0-byte file; it must not count as a fresh copy."""
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    with pytest.raises(DumpInvalid):
        importers.import_dump(db, empty, kind=importers.NVD_JSON, max_bytes=MAX)
