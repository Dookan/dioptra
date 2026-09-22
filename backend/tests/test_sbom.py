"""CycloneDX 1.6 structural validation of the SBOM that syft produces."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.analysis.sbom import MAX_COMPONENTS, SbomInvalid, component_count, validate_cyclonedx


def _document(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.19.2",
                "purl": "pkg:npm/express@4.19.2",
            },
            {"type": "library", "name": "lodash", "version": "4.17.21"},
        ],
    }
    base.update(overrides)
    return base


def test_valid_document_is_returned_unchanged() -> None:
    document = _document()
    assert validate_cyclonedx(json.dumps(document)) == document
    assert validate_cyclonedx(json.dumps(document).encode()) == document
    assert validate_cyclonedx(document) is document
    assert component_count(document) == 2


def test_empty_component_list_is_valid() -> None:
    assert component_count(validate_cyclonedx(_document(components=[]))) == 0


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"specVersion": "1.5"}, "specVersion is not 1.6"),
        ({"bomFormat": "SPDX"}, "bomFormat is not CycloneDX"),
        ({"components": {"name": "x"}}, "components is not a list"),
        ({"components": [{"type": "library"}]}, "component 0 has no name"),
        ({"components": [{"name": "x"}]}, "component 0 has no type"),
        ({"components": ["express"]}, "component 0 is not an object"),
    ],
)
def test_structural_violations_are_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(SbomInvalid) as excinfo:
        validate_cyclonedx(_document(**overrides))
    assert excinfo.value.detail == message
    assert excinfo.value.status_code == 422
    assert excinfo.value.code == "sbom_invalid"


def test_component_cap() -> None:
    too_many = [{"type": "library", "name": f"p{i}"} for i in range(MAX_COMPONENTS + 1)]
    with pytest.raises(SbomInvalid, match="components"):
        validate_cyclonedx(_document(components=too_many))


def test_not_json_and_not_an_object() -> None:
    with pytest.raises(SbomInvalid, match="not valid JSON"):
        validate_cyclonedx(b"\xff\xfe not json")
    with pytest.raises(SbomInvalid, match="root is not an object"):
        validate_cyclonedx("[]")


def test_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.analysis.sbom.MAX_DOCUMENT_BYTES", 16)
    with pytest.raises(SbomInvalid, match="exceeds"):
        validate_cyclonedx(json.dumps(_document()))


def test_hostile_component_names_are_preserved_raw() -> None:
    """Escaping happens at render, never here: the inventory needs the real string."""
    hostile = "<script>alert(1)</script>"
    document = validate_cyclonedx(
        _document(components=[{"type": "library", "name": hostile, "version": "=1+1"}])
    )
    assert document["components"][0]["name"] == hostile
    assert document["components"][0]["version"] == "=1+1"
