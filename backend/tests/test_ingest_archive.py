"""ZIP jail: every hostile-input case from tasks/phase1-audit-mvp.md."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from app.ingest.archive import ExtractionLimits, extract_zip
from app.ingest.errors import (
    InvalidArchive,
    TooManyEntries,
    ZipBomb,
    ZipSlipDetected,
    ZipTooLarge,
)

LIMITS = ExtractionLimits(max_entries=100, max_unpacked_bytes=1_000_000, max_ratio=100)


def build_zip(entries: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    buffer.seek(0)
    return buffer


def test_extracts_a_normal_tree(tmp_path: Path) -> None:
    source = build_zip({"app/index.js": b"console.log(1)\n", "package.json": b"{}"})
    report = extract_zip(source, tmp_path / "src", LIMITS)
    assert report.files == 2
    assert (tmp_path / "src" / "app" / "index.js").read_bytes() == b"console.log(1)\n"


@pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil.txt", "/etc/passwd", "a\\..\\b"])
def test_zip_slip_entry_is_rejected_and_nothing_is_left_behind(tmp_path: Path, name: str) -> None:
    source = build_zip({"ok.txt": b"fine", name: b"owned"})
    with pytest.raises(ZipSlipDetected):
        extract_zip(source, tmp_path / "src", LIMITS)
    assert not (tmp_path / "src").exists()
    assert not (tmp_path / "evil.txt").exists()


def test_parent_reference_is_refused_by_name_alone() -> None:
    """The name check stands on its own, independently of the jail check."""
    from app.ingest.archive import _safe_relative

    with pytest.raises(ZipSlipDetected):
        _safe_relative("a/../../b")


def test_jail_check_catches_an_escape_the_name_check_missed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defense in depth: even with the name check disabled, the resolved path must stay inside."""
    from pathlib import PurePosixPath

    monkeypatch.setattr("app.ingest.archive._safe_relative", PurePosixPath)
    source = build_zip({"../evil.txt": b"owned"})
    with pytest.raises(ZipSlipDetected):
        extract_zip(source, tmp_path / "src", LIMITS)
    assert not (tmp_path / "evil.txt").exists()


def test_symlink_entries_are_never_materialized(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16  # symlink mode bits
        archive.writestr(info, "/etc/passwd")
        archive.writestr("real.txt", "x")
    buffer.seek(0)
    report = extract_zip(buffer, tmp_path / "src", LIMITS)
    assert report.skipped_special == 1
    assert not (tmp_path / "src" / "link").exists()


def test_entry_count_bomb(tmp_path: Path) -> None:
    source = build_zip({f"f{i}.txt": b"x" for i in range(101)})
    with pytest.raises(TooManyEntries):
        extract_zip(source, tmp_path / "src", LIMITS)


def test_declared_size_above_cap(tmp_path: Path) -> None:
    source = build_zip({"big.bin": b"a" * 1_000_001}, compression=zipfile.ZIP_STORED)
    with pytest.raises(ZipTooLarge):
        extract_zip(source, tmp_path / "src", LIMITS)


def test_decompression_ratio_bomb(tmp_path: Path) -> None:
    source = build_zip({"zeros.bin": b"\0" * 900_000})
    with pytest.raises(ZipBomb):
        extract_zip(source, tmp_path / "src", LIMITS)


def test_declared_total_above_cap_is_refused_before_extraction(tmp_path: Path) -> None:
    """The declared-size guard fires on an honest header below the ratio cap.

    The streamed-byte counter in ``archive.py`` is defense in depth only: on
    Python 3.13 ``zipfile`` truncates a member at its declared size, so a forged
    header cannot push more bytes than it declares. It stays because that is a
    property of the interpreter, not of the format.
    """
    source = build_zip({"a.bin": b"ab" * 300_000})  # 600 kB declared honestly
    tight = ExtractionLimits(max_entries=100, max_unpacked_bytes=500_000, max_ratio=100_000)
    with pytest.raises(ZipTooLarge):
        extract_zip(source, tmp_path / "src", tight)
    assert not (tmp_path / "src").exists()


def test_not_a_zip(tmp_path: Path) -> None:
    with pytest.raises(InvalidArchive):
        extract_zip(io.BytesIO(b"definitely not a zip"), tmp_path / "src", LIMITS)
