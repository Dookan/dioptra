"""SARIF normalization: hostile input in, stable findings out."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.analysis.catalog import ALIASES, CATALOG, UNKNOWN, describe
from app.analysis.cwe_owasp import OWASP_TITLES, owasp_for
from app.analysis.models import Severity, ToolCategory
from app.analysis.normalizer import (
    NormalizationError,
    ToolReport,
    normalize,
    normalize_path,
    parse_sarif,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _report(name: str, tool: str, category: ToolCategory) -> ToolReport:
    return ToolReport(tool, category, parse_sarif((FIXTURES / name).read_bytes()))


@pytest.fixture
def semgrep() -> ToolReport:
    return _report("semgrep.sarif.json", "semgrep", ToolCategory.SAST)


@pytest.fixture
def gitleaks() -> ToolReport:
    return _report("gitleaks.sarif.json", "gitleaks", ToolCategory.SECRET)


@pytest.fixture
def osv() -> ToolReport:
    return _report("osv.sarif.json", "osv-scanner", ToolCategory.SCA)


# --- parse_sarif ------------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "{", "[]", '{"runs": {}}', '{"version": "1.0", "runs": []}'])
def test_parse_sarif_rejects_non_sarif(text: str) -> None:
    with pytest.raises(NormalizationError):
        parse_sarif(text)


def test_parse_sarif_accepts_bytes_and_str() -> None:
    document = '{"version": "2.1.0", "runs": []}'
    assert parse_sarif(document) == parse_sarif(document.encode())


# --- semgrep ----------------------------------------------------------------------


def test_semgrep_cwe_from_tags_and_catalog_title(semgrep: ToolReport) -> None:
    findings = normalize([semgrep])
    xss = next(f for f in findings if f.rule_id == "dioptra.js.express.xss-res-send" and f.line)
    assert xss.cwe == 79
    assert xss.owasp == "A03:2021"
    assert xss.title == "Cross-Site Scripting (XSS)"
    assert xss.severity is Severity.HIGH
    assert xss.category is ToolCategory.SAST
    assert xss.path == "index.js"
    assert xss.line == 42
    assert xss.references == (
        "https://cwe.mitre.org/data/definitions/79.html",
        "https://owasp.org/Top10/A03_2021-Injection/",
    )


def test_snippet_is_stored_raw_never_escaped_here(semgrep: ToolReport) -> None:
    xss = next(f for f in normalize([semgrep]) if f.line == 42)
    assert xss.snippet is not None
    assert "<script>alert(1)</script>" in xss.snippet


def test_semgrep_cwe_from_properties_and_jail_prefix_stripped(semgrep: ToolReport) -> None:
    # Local runner mode: the pipeline passes the jail as a root; the fixture's
    # URI is the jail's absolute path (which ends in `src`).
    jail = "/var/lib/dioptra/workspaces/p/a/src"
    cdn = next(f for f in normalize([semgrep], ("/work", jail)) if f.rule_id == "dioptra.js.no-cdn")
    assert cdn.cwe == 829
    assert cdn.owasp == "A08:2021"
    assert cdn.title.startswith("Inclusión de recursos desde un origen no confiable")
    assert cdn.path == "public/index.html"
    # Without that root nothing is guessed: the path stays as the tool wrote it.
    unrooted = next(f for f in normalize([semgrep]) if f.rule_id == "dioptra.js.no-cdn")
    assert unrooted.path == "var/lib/dioptra/workspaces/p/a/src/public/index.html"


def test_unknown_cwe_is_a_valid_state(semgrep: ToolReport) -> None:
    unknown = next(f for f in normalize([semgrep]) if f.rule_id == "dioptra.py.suspicious-pattern")
    assert unknown.cwe is None
    assert unknown.owasp is None
    assert unknown.title == "Patrón sospechoso sin clasificar"  # the rule's own description
    assert unknown.severity is Severity.LOW
    assert unknown.path == "etc/passwd"  # traversal segments dropped, never absolute


def test_missing_location_and_garbage_types_never_raise(semgrep: ToolReport) -> None:
    findings = normalize([semgrep])
    no_location = next(f for f in findings if f.path == "" and f.cwe == 79)
    assert no_location.line is None
    garbage = next(f for f in findings if f.rule_id == "rule-not-declared-in-driver")
    assert garbage.path == ""
    assert garbage.line is None
    assert garbage.message is None
    assert garbage.severity is Severity.INFO
    assert garbage.cwe is None
    assert garbage.title == "rule-not-declared-in-driver"  # the only name the tool gave us


def test_semgrep_result_level_cvss_overrides_level() -> None:
    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "r", "properties": {"tags": ["CWE-89"]}}]}},
                "results": [
                    {
                        "ruleId": "r",
                        "level": "note",
                        "properties": {"cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}],
                    }
                ],
            }
        ],
    }
    (finding,) = normalize([ToolReport("semgrep", ToolCategory.SAST, sarif)])
    assert finding.cvss_score == 9.8
    assert finding.severity is Severity.CRITICAL
    assert finding.title == "Inyección SQL"


# --- gitleaks ---------------------------------------------------------------------


def test_gitleaks_secrets_are_cwe_798_high_with_the_anchor_title(gitleaks: ToolReport) -> None:
    findings = normalize([gitleaks])
    assert {f.title for f in findings} == {
        "Secreto expuesto (Generic Api Key)",
        "Secreto expuesto (GitLab Personal Access Token)",
    }
    for finding in findings:
        assert finding.cwe == 798
        assert finding.owasp == "A07:2021"
        assert finding.severity is Severity.HIGH
        assert finding.category is ToolCategory.SECRET
        assert finding.path == ".gitlab-ci.yml"
    assert sorted(f.line or 0 for f in findings) == [73, 74]
    assert len(findings) == 2


def test_two_secret_rules_on_the_same_line_are_one_finding(gitleaks: ToolReport) -> None:
    # Same path, line and CWE-798 from two rules is the same secret: dedupe keeps one.
    for result in gitleaks.sarif["runs"][0]["results"]:
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = 73
    (only,) = normalize([gitleaks])
    assert only.rule_id == "generic-api-key"
    assert only.tools == ("gitleaks",)


# --- osv-scanner ------------------------------------------------------------------


def test_osv_advisory_with_cvss_vector(osv: ToolReport) -> None:
    lodash = next(f for f in normalize([osv]) if f.rule_id == "CVE-2021-23337")
    assert lodash.category is ToolCategory.SCA
    assert lodash.cwe == 94  # carried by the rule's tags
    assert lodash.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    assert lodash.cvss_score == 7.2
    assert lodash.severity is Severity.HIGH
    assert lodash.advisory == {
        "id": "CVE-2021-23337",
        "package": "lodash",
        "version": "4.17.20",
        "fixed": "4.17.21",
        "ecosystem": "npm",
    }
    assert lodash.title == "Dependencia vulnerable: lodash@4.17.20 (CVE-2021-23337)"
    assert lodash.path == "package-lock.json"
    assert "https://osv.dev/vulnerability/CVE-2021-23337" in lodash.references


def test_osv_advisory_without_cwe_defaults_to_dependency_cwe(osv: ToolReport) -> None:
    ghsa = next(f for f in normalize([osv]) if f.rule_id == "GHSA-xxxx-yyyy-zzzz")
    assert ghsa.cwe == 1395
    assert ghsa.owasp == "A06:2021"
    assert ghsa.cvss_score is None
    assert ghsa.severity is Severity.MEDIUM  # from the SARIF level
    assert ghsa.advisory is not None
    assert ghsa.advisory["fixed"] is None
    assert ghsa.advisory["package"] == "example-pkg"


def test_two_advisories_on_the_same_lockfile_line_stay_distinct(osv: ToolReport) -> None:
    findings = normalize([osv])
    assert len(findings) == 2
    assert len({f.fingerprint for f in findings}) == 2


# --- dedupe and ordering ------------------------------------------------------------


def _single(tool: str, rule_id: str, cwe: str, uri: str, line: int, level: str) -> ToolReport:
    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": rule_id,
                                "properties": {
                                    "tags": [cwe],
                                    "references": [f"https://example.test/{tool}"],
                                },
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    return ToolReport(tool, ToolCategory.SAST, sarif)


def test_same_path_line_cwe_from_two_tools_merges_into_one_finding() -> None:
    first = _single("semgrep", "rule-a", "CWE-79", "./app.js", 10, "warning")
    second = _single("other-sast", "rule-b", "CWE-79: XSS", "app.js", 10, "error")
    (merged,) = normalize([first, second])
    assert merged.tools == ("semgrep", "other-sast")
    assert merged.references == ("https://example.test/semgrep", "https://example.test/other-sast")
    assert merged.severity is Severity.HIGH  # the worse of the two wins
    assert merged.rule_id == "rule-a"  # the first tool stays the primary source


def test_findings_are_ordered_by_severity_then_path_then_line() -> None:
    reports = [
        _single("t", "r1", "CWE-79", "b.js", 5, "note"),
        _single("t", "r2", "CWE-89", "a.js", 9, "error"),
        _single("t", "r3", "CWE-22", "a.js", 2, "error"),
        _single("t", "r4", "CWE-20", "z.js", 1, "warning"),
    ]
    ordered = [(f.path, f.line) for f in normalize(reports)]
    assert ordered == [("a.js", 2), ("a.js", 9), ("z.js", 1), ("b.js", 5)]


def test_fingerprint_is_deterministic_and_keyed_on_cwe(semgrep: ToolReport) -> None:
    first = normalize([semgrep])
    second = normalize([semgrep])
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    assert all(len(f.fingerprint) == 64 for f in first)


def test_result_count_is_capped() -> None:
    result = {"ruleId": "r", "level": "note", "locations": []}
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [dict(result, message={"text": str(i)}) for i in range(25_000)],
            }
        ],
    }
    # All 25 000 share (path, line, rule) → one finding; the cap keeps the walk bounded.
    assert len(normalize([ToolReport("semgrep", ToolCategory.SAST, sarif)])) == 1


def test_run_that_is_not_a_dict_is_ignored() -> None:
    sarif: dict[str, Any] = {"version": "2.1.0", "runs": ["garbage", 42, None]}
    assert normalize([ToolReport("semgrep", ToolCategory.SAST, sarif)]) == []


# --- paths ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("./index.js", "index.js"),
        # Only an exact root is stripped: the tree's own `src/` survives.
        ("/work/src/lib/a.js", "src/lib/a.js"),
        ("work/src/lib/a.js", "src/lib/a.js"),
        ("/abs/path/to/src/lib/a.js", "abs/path/to/src/lib/a.js"),
        ("file:///work/x.py", "x.py"),
        ("../../etc/passwd", "etc/passwd"),
        ("/workspace/a.js", "workspace/a.js"),
        ("C:\\repo\\src\\a.js", "C:/repo/src/a.js"),
        ("", ""),
        (None, ""),
        (42, ""),
        ("/", ""),
        ("x/" * 1000, ("x/" * 1000).rstrip("/")[:1024]),
    ],
)
def test_normalize_path(raw: object, expected: str) -> None:
    assert normalize_path(raw) == expected


def test_normalize_path_strips_the_jail_root_it_is_given() -> None:
    # Local runner mode: tools report the jail's absolute path, which ends in
    # `src` — the audited tree's own `src/` below it must survive.
    jail = "/var/lib/dioptra/workspaces/p/a/src"
    roots = ("/work", jail)
    assert normalize_path(f"{jail}/src/helpers/edad.js", roots) == "src/helpers/edad.js"
    assert normalize_path(f"file://{jail}/x.py", roots) == "x.py"
    assert normalize_path("/work/src/x.py", roots) == "src/x.py"
    # A sibling directory that merely shares the prefix string is not the root.
    assert normalize_path(f"{jail}2/x.py", roots) == "var/lib/dioptra/workspaces/p/a/src2/x.py"
    assert normalize_path("/x.py", ("/",)) == "x.py"
    # The root is stripped where it LEADS, never where it merely appears…
    assert normalize_path("packages/work/x.js") == "packages/work/x.js"
    assert normalize_path("/srv/work/x.js") == "srv/work/x.js"
    # …and only once: the tree may hold a directory named like the root.
    assert normalize_path("/work/work/x.js") == "work/x.js"
    assert normalize_path("/work/src/work/x.js", ("/work", jail)) == "src/work/x.js"


# --- catalog and mapping ---------------------------------------------------------


def test_catalog_anchor_wording_is_verbatim() -> None:
    entry = CATALOG[798]
    assert entry.title == "Credenciales embebidas en el código"
    assert entry.mitigation == (
        "Revocar y rotar de inmediato el secreto comprometido.",
        "Mover los secretos a variables de entorno o a un gestor de secretos.",
        "Verificar que el secreto no permanezca en el historial de versiones.",
    )
    assert CATALOG[400].title == "Consumo de recursos no controlado (Denegación de Servicio)"
    assert CATALOG[915].title.endswith("(Mass Assignment)")
    # Wording copied from the institution's earlier generator, the anchor.
    assert CATALOG[295].title == "Validación de certificado TLS deshabilitada"
    assert CATALOG[22].title == "Recorrido de directorios (Path Traversal)"
    assert CATALOG[1321].title == "Contaminación de prototipos (Prototype Pollution)"
    assert CATALOG[250].mitigation[0].startswith("Aplicar el principio de mínimo privilegio")
    assert CATALOG[434].references[0].startswith("https://owasp.org/www-community/")


def test_reference_generator_cwes_are_all_covered() -> None:
    for cwe in (
        295,
        79,
        89,
        78,
        22,
        502,
        327,
        330,
        798,
        942,
        400,
        20,
        434,
        778,
        918,
        915,
        1333,
        250,
        1321,
    ):
        assert cwe in CATALOG, cwe


def test_aliases_reuse_the_class_prose_and_add_their_own_reference() -> None:
    for alias, base in ALIASES.items():
        assert alias not in CATALOG
        entry = describe(alias)
        assert entry.title == CATALOG[base].title
        assert entry.description == CATALOG[base].description
        assert entry.mitigation == CATALOG[base].mitigation
        assert f"https://cwe.mitre.org/data/definitions/{alias}.html" in entry.references
        assert owasp_for(alias) in OWASP_TITLES, alias


def test_every_catalog_entry_is_complete_and_mapped_to_owasp() -> None:
    for cwe, entry in CATALOG.items():
        assert entry.title and entry.description and entry.impact
        assert len(entry.mitigation) >= 1
        assert any("cwe.mitre.org" in ref for ref in entry.references), cwe
        assert owasp_for(cwe) in OWASP_TITLES, cwe


def test_describe_fallbacks() -> None:
    assert describe(None) is UNKNOWN
    assert describe(None, fallback_title="Custom rule").title == "Custom rule"
    assert describe(99999).title == "Debilidad CWE-99999"
    assert describe(99999).references == ("https://cwe.mitre.org/data/definitions/99999.html",)
    assert describe(79, fallback_title="ignored").title == "Cross-Site Scripting (XSS)"


def test_owasp_mapping_covers_the_common_cwes_and_rejects_unknown() -> None:
    assert owasp_for(79) == "A03:2021"
    assert owasp_for(798) == "A07:2021"
    assert owasp_for(918) == "A10:2021"
    assert owasp_for(1395) == "A06:2021"
    assert owasp_for(732) == "A05:2021"
    assert owasp_for(400) == "A05:2021"  # as the anchor report prints it
    assert owasp_for(250) == "A05:2021"
    assert owasp_for(1333) == "A05:2021"
    assert owasp_for(1321) == "A08:2021"
    # Official 2021 lists win over the earlier generator's table.
    assert owasp_for(295) == "A07:2021"
    assert owasp_for(311) == "A04:2021"
    assert owasp_for(347) == "A02:2021"
    assert owasp_for(None) is None
    assert owasp_for(424242) is None
    assert len(OWASP_TITLES) == 10


def test_fixtures_are_valid_json() -> None:
    for name in ("semgrep", "gitleaks", "osv"):
        assert json.loads((FIXTURES / f"{name}.sarif.json").read_text())["version"] == "2.1.0"


def test_osv_scoped_npm_package_keeps_its_name() -> None:
    """``@babel/core@7.29.0`` must not collapse into the generic "dependencia"."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "osv-scanner", "rules": [{"id": "CVE-2026-49356"}]}},
                "results": [
                    {
                        "ruleId": "CVE-2026-49356",
                        "level": "error",
                        "message": {
                            "text": (
                                "Package '@babel/core@7.29.0' is vulnerable to 'CVE-2026-49356'."
                            )
                        },
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}}}
                        ],
                    }
                ],
            }
        ],
    }
    [finding] = normalize([ToolReport("osv-scanner", ToolCategory.SCA, sarif)])
    assert finding.advisory is not None
    assert finding.advisory["package"] == "@babel/core"
    assert finding.advisory["version"] == "7.29.0"
    assert "@babel/core@7.29.0" in finding.title
