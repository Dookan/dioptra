"""Unit pins for the two functions the adversary found unfixtured: the CSV
cell neutraliser and the download's own response handling."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest

from app.analysis.models import Severity
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


# --- the CycloneDX documents' fields, pinned one by one (mutation pass, P5 close) ----


def _asset(**overrides: Any) -> Any:
    from app.inventory.models import CryptoAsset  # noqa: PLC0415

    base: dict[str, Any] = {
        "analysis_id": uuid.uuid4(),
        "primitive": "hash",
        "algorithm": "SHA-256",
        "path": "a.js",
        "line": 3,
        "weak": False,
        "rule_id": "crypto-inventory-js-hash",
    }
    base.update(overrides)
    return CryptoAsset(**base)


def _match(**overrides: Any) -> Any:
    from app.inventory.components import Component  # noqa: PLC0415
    from app.inventory.correlation import Match  # noqa: PLC0415

    component = Component(
        name="lodash",
        version="4.17.15",
        purl="pkg:npm/lodash@4.17.15",
        ecosystem="npm",
        osv_name="lodash",
        type="library",
        bom_ref="ref-lodash",
    )
    base: dict[str, Any] = {
        "component": component,
        "vulnerability_id": "GHSA-p6mc-m468-83gw",
        "aliases": ("CVE-2020-8203",),
        "score": 7.4,
        "severity": Severity.HIGH,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "summary": "Prototype pollution",
        "fixed_in": "4.17.19",
        "vex_state": "not_affected",
        "justification": "No se usa la ruta vulnerable",
        "verdict_by": "mmarin",
    }
    base.update(overrides)
    return Match(**base)


def test_the_documents_headers_are_deterministic_and_complete() -> None:
    from app.analysis.models import Analysis  # noqa: PLC0415
    from app.inventory.documents import cbom_document, vex_document  # noqa: PLC0415

    analysis = Analysis(id=uuid.UUID("11111111-1111-4111-8111-111111111111"))
    cbom, vex = cbom_document(analysis, []), vex_document(analysis, [])
    for document in (cbom, vex):
        assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
        assert document["version"] == 1
        assert document["serialNumber"].startswith("urn:uuid:")
        assert document["metadata"]["tools"]["components"] == [
            {"type": "application", "name": "Dioptra"}
        ]
        assert "T" in document["metadata"]["timestamp"]
    assert cbom["serialNumber"] != vex["serialNumber"], "one serial per document kind"
    assert cbom_document(analysis, [])["serialNumber"] == cbom["serialNumber"], (
        "stable per analysis"
    )
    assert cbom["metadata"]["component"] == {
        "type": "application",
        "name": "analysis:11111111-1111-4111-8111-111111111111",
    }
    assert cbom["components"] == [] and vex["vulnerabilities"] == []


def test_cbom_components_carry_every_field_the_spec_asks_for() -> None:
    from app.analysis.models import Analysis  # noqa: PLC0415
    from app.inventory.documents import MAX_OCCURRENCES_PER_ASSET, cbom_document  # noqa: PLC0415

    analysis = Analysis(id=uuid.uuid4())
    assets = [_asset(line=i) for i in range(MAX_OCCURRENCES_PER_ASSET + 5)] + [
        _asset(primitive="protocol", algorithm="TLSV1", weak=True, line=None, path="s.js"),
        _asset(primitive="certificate", algorithm="X509", path="c.pem", line=None),
    ]
    document = cbom_document(analysis, assets)
    by_name = {c["name"]: c for c in document["components"]}
    sha = by_name["SHA-256"]
    assert sha["type"] == "cryptographic-asset"
    assert sha["bom-ref"] == "crypto:hash:SHA-256"
    assert sha["cryptoProperties"] == {
        "assetType": "algorithm",
        "algorithmProperties": {"primitive": "hash"},
    }
    assert len(sha["evidence"]["occurrences"]) == MAX_OCCURRENCES_PER_ASSET
    assert sha["evidence"]["occurrences"][0] == {"location": "a.js", "line": 0}
    assert sha["properties"] == [{"name": "dioptra:weak", "value": "false"}]
    tls = by_name["TLSV1"]
    assert tls["cryptoProperties"] == {
        "assetType": "protocol",
        "protocolProperties": {"type": "tls"},
    }
    assert tls["evidence"]["occurrences"] == [{"location": "s.js"}]
    assert tls["properties"] == [{"name": "dioptra:weak", "value": "true"}]
    assert by_name["X509"]["cryptoProperties"] == {"assetType": "certificate"}
    assert [c["name"] for c in document["components"]] == ["X509", "SHA-256", "TLSV1"], (
        "sorted by (primitive, algorithm)"
    )


def test_vex_entries_carry_state_ratings_references_and_the_recommendation() -> None:
    from app.analysis.models import Analysis  # noqa: PLC0415
    from app.inventory.documents import vex_document  # noqa: PLC0415

    analysis = Analysis(id=uuid.uuid4())
    full = _match()
    bare = _match(
        vulnerability_id="CVE-2024-1",
        aliases=(),
        score=None,
        severity=None,
        vector=None,
        summary=None,
        fixed_in=None,
        vex_state="in_triage",
        justification=None,
        verdict_by=None,
    )
    document = vex_document(analysis, [full, bare])
    first, second = document["vulnerabilities"]
    assert first == {
        "id": "GHSA-p6mc-m468-83gw",
        "source": {"name": "OSV"},
        "affects": [{"ref": "ref-lodash"}],
        "analysis": {"state": "not_affected", "detail": "No se usa la ruta vulnerable"},
        "references": [{"id": "CVE-2020-8203", "source": {"name": "OSV"}}],
        "ratings": [
            {
                "score": 7.4,
                "method": "CVSSv31",
                "severity": "high",
                "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
            }
        ],
        "description": "Prototype pollution",
        "recommendation": "update to 4.17.19",
    }
    assert second == {
        "id": "CVE-2024-1",
        "source": {"name": "NVD"},
        "affects": [{"ref": "ref-lodash"}],
        "analysis": {"state": "in_triage"},
    }
    # Without a bom-ref the PURL is the ref, and without a PURL the name.
    from dataclasses import replace  # noqa: PLC0415

    no_ref = replace(full, component=replace(full.component, bom_ref=None))
    assert vex_document(analysis, [no_ref])["vulnerabilities"][0]["affects"] == [
        {"ref": "pkg:npm/lodash@4.17.15"}
    ]
    no_purl = replace(full, component=replace(full.component, bom_ref=None, purl=None))
    assert vex_document(analysis, [no_purl])["vulnerabilities"][0]["affects"] == [{"ref": "lodash"}]
