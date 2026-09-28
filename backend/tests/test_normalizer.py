"""SARIF normalization: hostile input in, stable findings out."""

from __future__ import annotations

import copy
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


def test_severity_falls_back_to_the_rules_default_configuration() -> None:
    """SARIF 2.1.0 §3.27.10: a result with no level inherits its RULE's.

    Semgrep writes the level once per rule and omits it on every result, so
    reading only ``result.level`` sent every SAST finding to INFO whatever the
    rule declared. Found by running a real Laravel application through the
    pipeline (2026-09-23): 611 results, none carrying a level, and rules
    declared ``severity: ERROR`` reported as informational.
    """
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "rules.semgrep.php-dynamic-include",
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"cwe": "CWE-98", "owasp": "A03:2021"},
                            },
                            {
                                "id": "rules.semgrep.php-debug-output-function",
                                "defaultConfiguration": {"level": "warning"},
                                "properties": {"cwe": "CWE-489", "owasp": "A05:2021"},
                            },
                            {"id": "rules.semgrep.unset-level", "properties": {}},
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "rules.semgrep.php-dynamic-include",
                        "message": {"text": "include with a non-literal path"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "/work/app/Http/X.php"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "rules.semgrep.php-debug-output-function",
                        "message": {"text": "debug dump"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "/work/app/Http/Y.php"},
                                    "region": {"startLine": 9},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "rules.semgrep.unset-level",
                        "message": {"text": "no level anywhere"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "/work/app/Http/Z.php"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "rules.semgrep.php-dynamic-include",
                        "level": "note",
                        "message": {"text": "the result wins when it has one"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "/work/app/Http/W.php"},
                                    "region": {"startLine": 11},
                                }
                            }
                        ],
                    },
                ],
            }
        ]
    }
    findings = normalize(
        [ToolReport(tool="semgrep", category=ToolCategory.SAST, sarif=sarif)], roots=("/work",)
    )
    by_path = {f.path: f.severity for f in findings}
    assert by_path["app/Http/X.php"] is Severity.HIGH  # rule says error
    assert by_path["app/Http/Y.php"] is Severity.MEDIUM  # rule says warning
    assert by_path["app/Http/Z.php"] is Severity.INFO  # nothing says anything
    assert by_path["app/Http/W.php"] is Severity.LOW  # the result's own level wins


# --- P1 close: field by field (mutation pass, 2026-09-24) ---------------------------
#
# The phase-7a mutmut pass left 357 survivors here, recorded as a FIRST
# measurement of P1 code. Most were one class: which property SOURCE a field is
# read from, the per-field caps, and fields no test ever asserted. Each test
# below feeds ONE source alone, so dropping that source from the code fails it.


def _sarif(
    result: dict[str, Any], rule: dict[str, Any] | None = None, *, rule_id: str = "r1"
) -> dict[str, Any]:
    rules = [{"id": rule_id, **(rule or {})}]
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "x", "rules": rules}}, "results": [result]}],
    }


def _one(
    result: dict[str, Any],
    rule: dict[str, Any] | None = None,
    *,
    tool: str = "semgrep",
    category: ToolCategory = ToolCategory.SAST,
) -> Any:
    result = {"ruleId": "r1", **result}
    sarif = _sarif(result, rule, rule_id=result["ruleId"])
    (finding,) = normalize([ToolReport(tool, category, sarif)])
    return finding


def _at() -> dict[str, Any]:
    """A fresh location each time: a test may edit its copy."""
    return copy.deepcopy(_AT)


_AT = {
    "locations": [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "/work/src/a.js"},
                "region": {"startLine": 7, "snippet": {"text": "  eval(x)  "}},
            }
        }
    ]
}
_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.parametrize(
    ("result_props", "rule"),
    [
        ({"cwe": "CWE-79"}, {}),
        ({}, {"properties": {"cwe": 79}}),
        ({}, {"properties": {"metadata": {"cwe": ["CWE-79: XSS"]}}}),
        ({}, {"properties": {"tags": ["external/cwe/cwe-79"]}}),
    ],
)
def test_semgrep_reads_the_cwe_from_each_source_alone(
    result_props: dict[str, Any], rule: dict[str, Any]
) -> None:
    assert _one({"properties": result_props}, rule).cwe == 79


def test_semgrep_reads_the_cwe_from_the_rule_id_last() -> None:
    finding = _one({"ruleId": "CWE-89-sqli"})
    assert finding.cwe == 89


@pytest.mark.parametrize(
    ("result_props", "rule"),
    [
        ({"owasp": "A01:2021 - Broken Access Control"}, {}),
        ({}, {"properties": {"owasp": ["A01:2021"]}}),
        ({}, {"properties": {"metadata": {"owasp": "A01:2021"}}}),
        ({}, {"properties": {"tags": ["owasp:A01:2021"]}}),
    ],
)
def test_semgrep_reads_the_owasp_code_from_each_source_when_the_cwe_gives_none(
    result_props: dict[str, Any], rule: dict[str, Any]
) -> None:
    # No CWE at all, so the category must come from the declared OWASP code.
    finding = _one({"properties": result_props}, rule)
    assert finding.cwe is None
    assert finding.owasp == "A01:2021"


def test_semgrep_prefers_the_owasp_code_of_the_cwe_over_a_declared_one() -> None:
    finding = _one({"properties": {"cwe": "CWE-79", "owasp": "A01:2021"}})
    assert finding.owasp == owasp_for(79) != "A01:2021"


@pytest.mark.parametrize(
    ("result_props", "rule"),
    [
        ({"cvss": _VECTOR}, {}),
        ({"cvss_vector": _VECTOR}, {}),
        ({}, {"properties": {"cvss": _VECTOR}}),
        ({}, {"properties": {"metadata": {"cvss": _VECTOR}}}),
        ({}, {"properties": {"cvss_vector": _VECTOR}}),
    ],
)
def test_semgrep_reads_the_cvss_vector_from_each_source_alone(
    result_props: dict[str, Any], rule: dict[str, Any]
) -> None:
    finding = _one({"properties": result_props}, rule)
    assert finding.cvss_vector == _VECTOR
    assert finding.cvss_score == 9.8
    assert finding.severity is Severity.CRITICAL


@pytest.mark.parametrize(
    ("result_props", "rule_props"),
    [({"security-severity": "8.1"}, {}), ({}, {"security-severity": 8.1})],
)
def test_security_severity_is_read_from_the_result_then_the_rule(
    result_props: dict[str, Any], rule_props: dict[str, Any]
) -> None:
    finding = _one({"properties": result_props}, {"properties": rule_props})
    assert finding.severity is Severity.HIGH
    assert finding.cvss_score is None


def test_a_boolean_or_unparseable_security_severity_on_the_result_falls_through_to_the_rule() -> (
    None
):
    for bogus in (True, "high"):
        finding = _one(
            {"properties": {"security-severity": bogus}},
            {"properties": {"security-severity": "4.0"}},
        )
        assert finding.severity is Severity.MEDIUM, bogus


def test_every_field_of_a_semgrep_finding(semgrep: ToolReport) -> None:
    finding = _one(
        {
            **_at(),
            "message": {"text": "  user input reaches eval  "},
            "properties": {"cwe": "CWE-95"},
        },
        {"shortDescription": {"text": "Eval"}, "helpUri": "https://example.org/rule"},
    )
    assert finding.tools == ("semgrep",)
    assert finding.rule_id == "r1"
    assert (finding.path, finding.line) == ("src/a.js", 7)
    assert finding.snippet == "eval(x)"
    assert finding.message == "user input reaches eval"
    assert finding.references == ("https://example.org/rule",)
    assert finding.advisory is None
    # The fingerprint is (path, line, CWE when known): the same place and weakness
    # reported under another rule id is the SAME finding.
    other = _one({**_at(), "ruleId": "r2", "properties": {"cwe": "CWE-95"}})
    assert finding.fingerprint == other.fingerprint
    moved = _one({**_at(), "properties": {"cwe": "CWE-94"}})
    assert moved.fingerprint != finding.fingerprint


def test_the_semgrep_rule_id_falls_back_to_the_rule_then_to_a_placeholder() -> None:
    sarif = _sarif({"message": {"text": "m"}}, rule_id="from-rule")
    (finding,) = normalize([ToolReport("semgrep", ToolCategory.SAST, sarif)])
    # No ruleId on the result: the rules table has nothing to match, "?" it is.
    assert finding.rule_id == "?"


def test_every_field_is_capped(semgrep: ToolReport) -> None:
    from app.analysis.normalizer import MAX_MESSAGE, MAX_RULE_ID

    huge = "x" * 10_000
    finding = _one({"ruleId": "r" * 5000, "message": {"text": huge}})
    assert len(finding.rule_id) == MAX_RULE_ID
    assert len(finding.message) == MAX_MESSAGE
    secret = _one(
        {"ruleId": "s" * 5000, "message": {"text": huge}},
        tool="gitleaks",
        category=ToolCategory.SECRET,
    )
    assert len(secret.rule_id) == MAX_RULE_ID
    assert len(secret.message) == MAX_MESSAGE


def test_every_field_of_a_gitleaks_finding() -> None:
    finding = _one(
        {**_at(), "ruleId": "generic-api-key", "message": {"text": "a key"}},
        tool="gitleaks",
        category=ToolCategory.SECRET,
    )
    assert finding.snippet == "eval(x)"
    assert finding.message == "a key"
    assert finding.title == "Secreto expuesto (Generic Api Key)"
    other_rule = _one(
        {**_at(), "ruleId": "aws-key"},
        tool="gitleaks",
        category=ToolCategory.SECRET,
    )
    # A secret always carries CWE-798, so two secret rules on the same line are
    # the same finding (dedupe is on path, line and CWE when there is one).
    assert finding.fingerprint == other_rule.fingerprint
    elsewhere = _at()
    elsewhere["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "/work/b.js"
    moved = _one({**elsewhere}, tool="gitleaks", category=ToolCategory.SECRET)
    assert moved.fingerprint != finding.fingerprint


@pytest.mark.parametrize(
    ("tool", "category", "expected"),
    [
        ("gitleaks", ToolCategory.SAST, ToolCategory.SECRET),  # by name
        ("trufflehog", ToolCategory.SECRET, ToolCategory.SECRET),  # by category
        ("osv-scanner", ToolCategory.SAST, ToolCategory.SCA),
        ("trivy", ToolCategory.SCA, ToolCategory.SCA),
        ("semgrep", ToolCategory.SAST, ToolCategory.SAST),
    ],
)
def test_a_run_is_routed_by_tool_name_or_by_category(
    tool: str, category: ToolCategory, expected: ToolCategory
) -> None:
    finding = _one({**_at()}, tool=tool, category=category)
    assert finding.category is expected
    assert finding.tools == (tool,)


def test_a_non_dict_result_is_skipped_not_the_rest_of_the_run() -> None:
    sarif = _sarif({"ruleId": "r1", **_at()})
    sarif["runs"][0]["results"].insert(0, "garbage")
    assert len(normalize([ToolReport("semgrep", ToolCategory.SAST, sarif)])) == 1


# OSV-Scanner -----------------------------------------------------------------------


def _osv_one(result: dict[str, Any], rule: dict[str, Any] | None = None) -> Any:
    return _one({"ruleId": "GHSA-1", **result}, rule, tool="osv-scanner", category=ToolCategory.SCA)


def test_every_field_of_an_osv_finding_from_properties() -> None:
    finding = _osv_one(
        {
            **_at(),
            "message": {"text": "vulnerable"},
            "properties": {
                "package": "lodash",
                "version": "4.17.0",
                "fixed": "4.17.21",
                "ecosystem": "npm",
                "cwe": "CWE-1321",
                "cvss": _VECTOR,
            },
        },
        rule=None,
    )
    assert finding.advisory == {
        "id": "GHSA-1",
        "package": "lodash",
        "version": "4.17.0",
        "fixed": "4.17.21",
        "ecosystem": "npm",
    }
    assert finding.cwe == 1321
    assert finding.cvss_vector == _VECTOR
    assert finding.title == "Dependencia vulnerable: lodash@4.17.0 (GHSA-1)"
    assert finding.message == "vulnerable"
    assert (finding.path, finding.line, finding.snippet) == ("src/a.js", 7, "eval(x)")
    assert finding.tools == ("osv-scanner",)


def test_osv_reads_package_version_fixed_and_ecosystem_from_prose() -> None:
    # What OSV-Scanner actually emits: everything in the message and the help.
    finding = _osv_one(
        {"message": {"text": "Package 'lodash@4.17.0' is vulnerable"}},
        {
            "help": {"text": "| GHSA-1 | lodash | 4.17.21 |", "markdown": "Ecosystem: npm"},
            "fullDescription": {"text": "Prototype pollution. " + _VECTOR},
        },
    )
    assert finding.advisory == {
        "id": "GHSA-1",
        "package": "lodash",
        "version": "4.17.0",
        "fixed": "4.17.21",
        "ecosystem": "npm",
    }
    assert finding.cvss_vector == _VECTOR


@pytest.mark.parametrize(
    "rule",
    [
        {"help": {"markdown": "Package 'left-pad@1.0.0'"}},
        {"fullDescription": {"text": "Package 'left-pad@1.0.0'"}},
    ],
)
def test_osv_reads_the_package_from_every_help_field(rule: dict[str, Any]) -> None:
    advisory = _osv_one({}, rule).advisory
    assert (advisory["package"], advisory["version"]) == ("left-pad", "1.0.0")


def test_osv_keeps_a_declared_package_and_completes_only_the_version() -> None:
    advisory = _osv_one(
        {"properties": {"package": "declared"}, "message": {"text": "'other@2.0.0'"}}
    ).advisory
    assert (advisory["package"], advisory["version"]) == ("declared", "2.0.0")
    advisory = _osv_one(
        {"properties": {"version": "9.9.9"}, "message": {"text": "'other@2.0.0'"}}
    ).advisory
    assert (advisory["package"], advisory["version"]) == ("other", "9.9.9")


@pytest.mark.parametrize(
    ("result_props", "rule_props"),
    [
        ({"cwe": "CWE-502"}, {}),
        ({}, {"cwe": 502}),
        ({}, {"tags": ["CWE-502"]}),
    ],
)
def test_osv_reads_the_cwe_from_each_source_alone(
    result_props: dict[str, Any], rule_props: dict[str, Any]
) -> None:
    assert _osv_one({"properties": result_props}, {"properties": rule_props}).cwe == 502


def test_osv_without_a_cwe_is_the_dependency_cwe() -> None:
    from app.analysis.normalizer import DEPENDENCY_CWE

    finding = _osv_one({})
    assert finding.cwe == DEPENDENCY_CWE
    assert finding.title == "Dependencia vulnerable: dependencia (GHSA-1)"
    assert finding.message is None


@pytest.mark.parametrize(
    ("result_props", "rule_props"),
    [
        ({"cvss_vector": _VECTOR}, {}),
        ({}, {"cvss": _VECTOR}),
        ({}, {"cvss_vector": _VECTOR}),
        ({}, {"tags": [_VECTOR]}),
    ],
)
def test_osv_reads_the_cvss_vector_from_each_source_alone(
    result_props: dict[str, Any], rule_props: dict[str, Any]
) -> None:
    finding = _osv_one({"properties": result_props}, {"properties": rule_props})
    assert finding.cvss_vector == _VECTOR


def test_osv_severity_falls_back_to_the_rules_level() -> None:
    finding = _osv_one({}, {"defaultConfiguration": {"level": "error"}})
    assert finding.severity is Severity.HIGH


def test_osv_fields_are_capped() -> None:
    long = "p" * 1000
    advisory = _osv_one(
        {
            "properties": {
                "package": long,
                "version": "1" * 1000,
                "fixed": "2" * 1000,
                "ecosystem": "e" * 1000,
            }
        }
    ).advisory
    assert len(advisory["package"]) == 200
    assert len(advisory["version"]) == 100
    assert len(advisory["fixed"]) == 100
    assert len(advisory["ecosystem"]) == 40
    prose = _osv_one({"message": {"text": f"'pkg@{'9' * 1000}'"}}).advisory
    assert len(prose["version"]) == 100


def test_two_osv_findings_differ_by_package_at_the_same_place() -> None:
    a = _osv_one({**_at(), "properties": {"package": "a"}})
    b = _osv_one({**_at(), "properties": {"package": "b"}})
    none = _osv_one({**_at()})
    assert len({a.fingerprint, b.fingerprint, none.fingerprint}) == 3


# Dedupe -------------------------------------------------------------------------


def test_a_merge_keeps_the_first_value_and_fills_every_gap_from_the_second() -> None:
    # Same place and CWE from two tools: one fingerprint. The first report has
    # no snippet, message, vector or OWASP of its own; the second has them all.
    sparse = _sarif({"ruleId": "r1", **_at(), "properties": {"cwe": "CWE-79"}})
    sparse["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] = {"startLine": 7}
    rich = _sarif(
        {
            "ruleId": "r1",
            **_at(),
            "message": {"text": "from the second tool"},
            "properties": {"cwe": "CWE-79", "cvss": _VECTOR},
        },
        {"helpUri": "https://example.org/two"},
    )
    (merged,) = normalize(
        [
            ToolReport("tool-a", ToolCategory.SAST, sparse),
            ToolReport("tool-b", ToolCategory.SAST, rich),
        ]
    )
    assert merged.tools == ("tool-a", "tool-b")
    assert merged.snippet == "eval(x)"
    assert merged.message == "from the second tool"
    assert merged.cvss_vector == _VECTOR
    assert merged.cvss_score == 9.8
    assert merged.severity is Severity.CRITICAL  # the worse one wins
    assert merged.cwe == 79
    assert merged.owasp == owasp_for(79)
    assert merged.references == ("https://example.org/two",)


def test_a_merge_never_overwrites_what_the_first_tool_said() -> None:
    first = _sarif(
        {
            "ruleId": "r1",
            **_at(),
            "message": {"text": "first"},
            "properties": {"cwe": "CWE-79", "cvss": _VECTOR},
        }
    )
    second_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
    second = _sarif(
        {
            "ruleId": "r1",
            **_at(),
            "message": {"text": "second"},
            "properties": {"cwe": "CWE-79", "cvss": second_vector},
        }
    )
    second["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["snippet"] = {
        "text": "other snippet"
    }
    (merged,) = normalize(
        [
            ToolReport("tool-a", ToolCategory.SAST, first),
            ToolReport("tool-b", ToolCategory.SAST, second),
        ]
    )
    assert merged.message == "first"
    assert merged.snippet == "eval(x)"
    assert merged.cvss_vector == _VECTOR
    assert merged.cvss_score == 9.8
    assert merged.severity is Severity.CRITICAL  # the second is lower: the first stays


def test_a_merge_of_equal_severities_keeps_the_first() -> None:
    a = _sarif({"ruleId": "r1", **_at(), "level": "warning", "properties": {"cwe": "CWE-79"}})
    b = _sarif({"ruleId": "r1", **_at(), "level": "warning", "properties": {"cwe": "CWE-79"}})
    (merged,) = normalize(
        [ToolReport("a", ToolCategory.SAST, a), ToolReport("b", ToolCategory.SAST, b)]
    )
    assert merged.severity is Severity.MEDIUM
    assert merged.tools == ("a", "b")


def test_the_cwe_scan_skips_a_boolean_and_keeps_to_its_bounds() -> None:
    from app.analysis.normalizer import _first_cwe

    assert _first_cwe([True, "CWE-79"]) == 79
    assert _first_cwe(1) == 1
    assert _first_cwe(99_999) == 99_999
    assert _first_cwe(0, 100_000, "CWE-20") == 20


@pytest.mark.parametrize(
    ("raw", "severity"),
    [("0", Severity.INFO), ("10", Severity.CRITICAL), ("10.5", Severity.MEDIUM)],
)
def test_security_severity_is_honoured_only_inside_zero_to_ten(
    raw: str, severity: Severity
) -> None:
    # Out of range falls through to the result's own level (warning → medium).
    finding = _one({"level": "warning", "properties": {"security-severity": raw}})
    assert finding.severity is severity


def test_osv_reads_the_fixed_version_and_the_vector_from_prose_alone() -> None:
    finding = _osv_one(
        {"message": {"text": f"Fixed in 2.3.4, see {_VECTOR}"}},
        {"properties": {"security-severity": "1.0"}},
    )
    assert finding.advisory["fixed"] == "2.3.4"
    assert finding.cvss_vector == _VECTOR  # the vector wins over security-severity
    scored = _osv_one({}, {"properties": {"security-severity": "8.0"}})
    assert scored.severity is Severity.HIGH
    capped = _osv_one({"message": {"text": "fixed version " + "3" * 500}})
    assert len(capped.advisory["fixed"]) == 100


def test_an_osv_version_without_a_package_is_not_a_subject() -> None:
    finding = _osv_one({"properties": {"version": "1.0.0"}})
    assert finding.title == "Dependencia vulnerable: dependencia (GHSA-1)"


def test_the_fingerprint_separates_line_and_path() -> None:
    base = _one({**_at(), "properties": {"cwe": "CWE-95"}})
    other_line = _at()
    other_line["locations"][0]["physicalLocation"]["region"]["startLine"] = 8
    other_path = _at()
    other_path["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "/work/b.js"
    for location in (other_line, other_path):
        assert _one({**location, "properties": {"cwe": "CWE-95"}}).fingerprint != base.fingerprint
        osv = _osv_one({**location, "properties": {"package": "p"}})
        assert osv.fingerprint != _osv_one({**_at(), "properties": {"package": "p"}}).fingerprint


def test_findings_are_sorted_with_a_lineless_one_first() -> None:
    lineless = _at()
    lineless["locations"][0]["physicalLocation"]["region"] = {}
    at_zero = _at()
    at_zero["locations"][0]["physicalLocation"]["region"]["startLine"] = 0
    sarif = _sarif({"ruleId": "r1", **at_zero, "properties": {"cwe": "CWE-1"}})
    sarif["runs"][0]["results"].append({"ruleId": "r1", **lineless, "properties": {"cwe": "CWE-2"}})
    lines = [f.line for f in normalize([ToolReport("semgrep", ToolCategory.SAST, sarif)])]
    assert lines == [None, 0]


def test_a_malformed_run_is_skipped_not_the_rest_of_the_report() -> None:
    sarif = _sarif({"ruleId": "r1", **_at()})
    sarif["runs"].insert(0, "garbage")
    assert len(normalize([ToolReport("semgrep", ToolCategory.SAST, sarif)])) == 1


def test_the_snippet_and_the_osv_message_are_capped() -> None:
    from app.analysis.normalizer import MAX_MESSAGE, MAX_SNIPPET

    location = _at()
    location["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "s" * 9000}
    assert len(_one({**location}).snippet) == MAX_SNIPPET
    assert len(_osv_one({"message": {"text": "m" * 9000}}).message) == MAX_MESSAGE


def test_a_merge_fills_the_owasp_code_one_tool_declared() -> None:
    # No CWE on either side, so the fingerprint is the rule id and the OWASP code
    # can only come from a declaration — which only the second tool made.
    bare = _sarif({"ruleId": "r1", **_at()})
    declared = _sarif({"ruleId": "r1", **_at(), "properties": {"owasp": "A04:2021"}})
    (merged,) = normalize(
        [ToolReport("a", ToolCategory.SAST, bare), ToolReport("b", ToolCategory.SAST, declared)]
    )
    assert merged.owasp == "A04:2021"
    (kept,) = normalize(
        [
            ToolReport("a", ToolCategory.SAST, declared),
            ToolReport(
                "b",
                ToolCategory.SAST,
                _sarif({"ruleId": "r1", **_at(), "properties": {"owasp": "A05:2021"}}),
            ),
        ]
    )
    assert kept.owasp == "A04:2021"


def test_references_come_from_the_result_too_and_each_is_capped() -> None:
    long = "https://example.org/" + "a" * 1000
    finding = _one({"properties": {"references": ["https://example.org/r", long]}})
    assert finding.references == ("https://example.org/r", long[:500])


def test_a_location_without_a_physical_part_is_skipped_for_the_next_one() -> None:
    location = _at()
    location["locations"].insert(0, {"logicalLocations": [{"name": "f"}]})
    finding = _one({**location})
    assert (finding.path, finding.line) == ("src/a.js", 7)


def test_a_merge_caps_the_references() -> None:
    from app.analysis.normalizer import MAX_REFERENCES

    reports = [
        ToolReport(
            f"tool-{i}",
            ToolCategory.SAST,
            _sarif(
                {"ruleId": "r1", **_at(), "properties": {"cwe": "CWE-79"}},
                {"helpUri": f"https://example.org/{i}"},
            ),
        )
        for i in range(MAX_REFERENCES + 5)
    ]
    (merged,) = normalize(reports)
    assert len(merged.references) == MAX_REFERENCES
    assert merged.references[0] == "https://example.org/0"
