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


# P1 close (2026-09-24): the mutation pass on this module left survivors the
# tests above could not see. Each test below pins one of them.


def _typed(name: str, mode: int, data: str = "x") -> tuple[zipfile.ZipInfo, str]:
    info = zipfile.ZipInfo(name)
    info.external_attr = mode << 16
    return info, data


def _build_typed(members: list[tuple[zipfile.ZipInfo, str]]) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for info, data in members:
            archive.writestr(info, data)
    buffer.seek(0)
    return buffer


def test_device_and_fifo_entries_are_skipped_and_typed_members_are_kept(tmp_path: Path) -> None:
    # A FIFO or a device is neither a link nor a regular file: it is special.
    # A member that DOES carry type bits (S_IFREG, S_IFDIR) is an ordinary one.
    # The special entries come FIRST so that skipping them must not stop the loop.
    source = _build_typed(
        [
            _typed("pipe", 0o010644),
            _typed("dev", 0o060644),
            _typed("dir/", 0o040755, ""),
            _typed("dir/file.txt", 0o100644, "regular"),
        ]
    )
    report = extract_zip(source, tmp_path / "src", LIMITS)
    assert report == type(report)(files=1, bytes_written=7, skipped_special=2)
    assert (tmp_path / "src" / "dir" / "file.txt").read_text() == "regular"
    assert not (tmp_path / "src" / "pipe").exists()
    assert not (tmp_path / "src" / "dev").exists()


def test_a_directory_entry_does_not_end_the_extraction(tmp_path: Path) -> None:
    # Nested directory entries with no parent entry, then a file inside one of
    # them, then an entry for a directory that already exists.
    source = build_zip({"a/b/": b"", "a/b/c.txt": b"abc", "a/": b"", "d/e/f.txt": b"def"})
    report = extract_zip(source, tmp_path / "src", LIMITS)
    assert report.files == 2
    assert report.bytes_written == 6
    assert (tmp_path / "src" / "a" / "b" / "c.txt").read_bytes() == b"abc"
    assert (tmp_path / "src" / "d" / "e" / "f.txt").read_bytes() == b"def"


def test_the_jail_and_what_it_holds_are_private(tmp_path: Path) -> None:
    source = build_zip({"dir/": b"", "dir/x.txt": b"x", "made/by/parent.txt": b"y"})
    jail = tmp_path / "deep" / "er" / "src"  # parents are created
    extract_zip(source, jail, LIMITS)
    assert jail.stat().st_mode & 0o777 == 0o700
    assert (jail / "dir").stat().st_mode & 0o777 == 0o700
    assert (jail / "made" / "by").stat().st_mode & 0o777 == 0o700
    assert (jail / "dir" / "x.txt").stat().st_mode & 0o777 == 0o600


def test_an_existing_jail_is_refused_and_left_alone(tmp_path: Path) -> None:
    # Extracting into a directory that already exists would mix two analyses.
    jail = tmp_path / "src"
    jail.mkdir()
    (jail / "keep.txt").write_text("previous")
    with pytest.raises(FileExistsError):
        extract_zip(build_zip({"a.txt": b"a"}), jail, LIMITS)
    assert (jail / "keep.txt").read_text() == "previous"


def test_nul_in_an_entry_name_is_refused() -> None:
    from app.ingest.archive import _safe_relative

    with pytest.raises(ZipSlipDetected):
        _safe_relative("a\x00.txt")


def test_entry_name_length_boundary() -> None:
    from app.ingest.archive import _safe_relative

    assert str(_safe_relative("a" * 1024)) == "a" * 1024
    with pytest.raises(ZipSlipDetected):
        _safe_relative("a" * 1025)


def test_every_cap_admits_exactly_its_own_value(tmp_path: Path) -> None:
    # 3 entries, 3 000 bytes stored uncompressed: ratio 1:1. `bytes_written`
    # equal to the cap also proves the streamed counter adds member after member
    # and admits its own value (the streamed guard itself is unreachable on
    # Python 3.13, see the docstring above).
    entries = {f"f{i}.bin": b"z" * 1000 for i in range(3)}
    exact = ExtractionLimits(max_entries=3, max_unpacked_bytes=3000, max_ratio=100)
    report = extract_zip(build_zip(entries, compression=zipfile.ZIP_STORED), tmp_path / "a", exact)
    assert report.bytes_written == 3000
    with pytest.raises(TooManyEntries):
        extract_zip(
            build_zip(entries, compression=zipfile.ZIP_STORED),
            tmp_path / "b",
            ExtractionLimits(max_entries=2, max_unpacked_bytes=3000, max_ratio=100),
        )
    with pytest.raises(ZipTooLarge):
        extract_zip(
            build_zip(entries, compression=zipfile.ZIP_STORED),
            tmp_path / "c",
            ExtractionLimits(max_entries=3, max_unpacked_bytes=2999, max_ratio=100),
        )


def test_the_ratio_is_an_integer_ratio_at_its_boundary(tmp_path: Path) -> None:
    source = build_zip({"zeros.bin": b"\0" * 100_000})
    with zipfile.ZipFile(source) as archive:
        (entry,) = archive.infolist()
        declared, compressed = entry.file_size, entry.compress_size
    source.seek(0)
    ratio = declared // compressed
    assert declared % compressed, "the fixture must not divide evenly"
    # Exactly the floor ratio is admitted; one less is refused. A float ratio
    # (declared / compressed) would exceed the floor and refuse the first call.
    at = ExtractionLimits(max_entries=10, max_unpacked_bytes=1_000_000, max_ratio=ratio)
    assert extract_zip(source, tmp_path / "a", at).bytes_written == declared
    source.seek(0)
    below = ExtractionLimits(max_entries=10, max_unpacked_bytes=1_000_000, max_ratio=ratio - 1)
    with pytest.raises(ZipBomb):
        extract_zip(source, tmp_path / "b", below)


def test_an_archive_of_empty_members_has_no_ratio_to_compute(tmp_path: Path) -> None:
    # Nothing compressed at all: the ratio guard must not divide by zero.
    source = build_zip({"empty/": b"", "blank.txt": b""}, compression=zipfile.ZIP_STORED)
    report = extract_zip(source, tmp_path / "src", LIMITS)
    assert report.files == 1
    assert report.bytes_written == 0
