"""Unit pins for the two functions the adversary found unfixtured: the CSV
cell neutraliser and the download's own response handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.inventory import sync
from app.inventory.documents import csv_cell
from app.inventory.errors import DumpTooLarge


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_every_formula_prefix_is_neutralised(prefix: str) -> None:
    assert csv_cell(prefix + "x") == "'" + prefix + "x"


def test_plain_cells_are_untouched() -> None:
    assert csv_cell("x") == "x"
    assert csv_cell(" =1+1") == " =1+1", "a leading space is not a formula"
    assert csv_cell(None) == ""
    assert csv_cell(3) == "3"


class _FakeResponse:
    def __init__(self, status: int, chunks: list[bytes]) -> None:
        self.status = status
        self._chunks = list(chunks)

    def read(self, _size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response

    def open(self, url: str, timeout: int) -> _FakeResponse:
        del url, timeout
        return self.response


def _use(monkeypatch: pytest.MonkeyPatch, response: _FakeResponse) -> None:
    monkeypatch.setattr(sync, "_opener", lambda: _FakeOpener(response))


def test_the_download_stops_at_the_byte_cap_and_leaves_no_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use(monkeypatch, _FakeResponse(200, [b"x" * 600, b"x" * 600]))
    target = tmp_path / "dump.zip"
    with pytest.raises(DumpTooLarge):
        sync.download("https://example.invalid/all.zip", target, max_bytes=1000, timeout_seconds=1)
    assert not target.exists()


def test_a_non_200_answer_is_a_failed_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use(monkeypatch, _FakeResponse(404, [b"not found"]))
    target = tmp_path / "dump.zip"
    with pytest.raises(sync.DownloadFailed):
        sync.download("https://example.invalid/all.zip", target, max_bytes=1000, timeout_seconds=1)
    assert not target.exists()


def test_a_good_download_is_written_whole(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use(monkeypatch, _FakeResponse(200, [b"ab", b"cd"]))
    target = tmp_path / "dump.zip"
    written: Any = sync.download(
        "https://example.invalid/all.zip", target, max_bytes=1000, timeout_seconds=1
    )
    assert written == 4 and target.read_bytes() == b"abcd"
