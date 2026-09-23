"""Reading components out of a stored SBOM: PURLs, ecosystems, licences, hostile names."""

from __future__ import annotations

import pytest

from app.inventory.components import components_of, osv_name_for, parse_purl


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/lodash@4.17.15", ("npm", None, "lodash", "4.17.15")),
        ("pkg:npm/%40angular/core@12.0.0", ("npm", "@angular", "core", "12.0.0")),
        ("pkg:pypi/Django@3.2", ("pypi", None, "Django", "3.2")),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
            ("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"),
        ),
        (
            "pkg:golang/github.com/gin-gonic/gin@v1.6.3",
            ("golang", "github.com/gin-gonic", "gin", "v1.6.3"),
        ),
        ("pkg:composer/laravel/framework@8.0.0#src", ("composer", "laravel", "framework", "8.0.0")),
        ("pkg:npm/express", ("npm", None, "express", None)),
    ],
)
def test_parse_purl(purl: str, expected: tuple[str, str | None, str, str | None]) -> None:
    assert parse_purl(purl) == expected


@pytest.mark.parametrize("junk", ["", "lodash@4", "pkg:", "pkg:npm", "http://x", "pkg:/name@1"])
def test_malformed_purls_are_none(junk: str) -> None:
    assert parse_purl(junk) is None


def test_osv_names_follow_each_ecosystem() -> None:
    assert osv_name_for("maven", "org.apache", "log4j") == "org.apache:log4j"
    assert osv_name_for("npm", "@angular", "core") == "@angular/core"
    assert osv_name_for("golang", "github.com/gin-gonic", "gin") == "github.com/gin-gonic/gin"
    assert osv_name_for("pypi", None, "Flask_Login") == "flask-login"
    assert osv_name_for("cargo", None, "serde") == "serde"


def test_components_of_shapes_licences_and_keeps_hostile_names_raw() -> None:
    hostile = "<img src=x onerror=alert(1)>"
    document = {
        "components": [
            {
                "type": "library",
                "name": hostile,
                "version": "=1+1",
                "purl": "pkg:npm/lodash@4.17.15",
                "bom-ref": "ref-1",
                "licenses": [
                    {"license": {"id": "MIT"}},
                    {"license": {"name": "Custom"}},
                    {"expression": "Apache-2.0 OR GPL-2.0"},
                    {"license": {"id": "MIT"}},
                    "junk",
                ],
            },
            {"type": "library", "name": "no-purl", "version": "1.0.0"},
            {"type": "library", "name": "weird", "purl": "pkg:unknown-type/x@1"},
            {"name": "no-type", "purl": "pkg:pypi/Requests@2.0"},
            "not a dict",
            {"type": "library"},  # nameless → dropped
        ]
    }
    components = components_of(document)
    assert [c.name for c in components] == [hostile, "no-purl", "weird", "no-type"]
    first = components[0]
    assert first.name == hostile, "nothing is escaped here — the renderers escape"
    assert first.version == "=1+1"
    assert first.key == ("npm", "lodash")
    assert first.licenses == ("MIT", "Custom", "Apache-2.0 OR GPL-2.0")
    assert first.bom_ref == "ref-1"
    assert components[1].key is None
    assert components[2].key is None, "an unknown PURL type is listed, never correlated"
    assert components[3].key == ("PyPI", "requests")
    assert components[3].version == "2.0", "the version falls back to the PURL's"
    assert components[3].type == "library"


def test_components_of_tolerates_a_document_without_components() -> None:
    assert components_of({}) == []
    assert components_of({"components": "nope"}) == []
