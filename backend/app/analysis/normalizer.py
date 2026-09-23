"""SARIF → internal findings (docs/analysis-pipeline.md → Normalizer invariants).

One parser for every tool: Semgrep, Gitleaks and OSV-Scanner all emit SARIF
2.1.0. Everything inside a SARIF document came out of the audited tree and is
hostile: strings are capped, paths are made relative, nothing is trusted to be
of the type the schema promises, and no missing field ever raises. "Unknown
CWE" is a valid state (``cwe = None``, OWASP bucket ``None``), not an error.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from app.analysis.catalog import describe
from app.analysis.cvss import base_score, severity_for_level, severity_for_score
from app.analysis.cwe_owasp import owasp_for
from app.analysis.models import SEVERITY_ORDER, Severity, ToolCategory
from app.core.errors import AppError

MAX_TITLE = 200
MAX_RULE_ID = 200
MAX_PATH = 1024
MAX_MESSAGE = 4000
MAX_SNIPPET = 2000
MAX_REFERENCES = 20
MAX_RESULTS_PER_RUN = 20_000
#: A finding whose location the tool did not report. The report renders the
#: label; the data stays empty rather than carrying display copy.
UNKNOWN_PATH = ""

GITLEAKS_CWE = 798
DEPENDENCY_CWE = 1395

_CWE_PATTERN = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)
_OWASP_PATTERN = re.compile(r"A(\d{2}):2021")
_CVSS_PATTERN = re.compile(r"CVSS:3\.[01]/[A-Z]{1,3}:[A-Z](?:/[A-Z]{1,3}:[A-Z])+")
# Scoped npm packages start with ``@`` (``@babel/core@7.29.0``): the name is
# everything up to the LAST ``@`` before the version.
_PACKAGE_AT_VERSION = re.compile(r"'(@?[^'@\s]+)@([^'\s@]+)'")
_FIXED_PATTERN = re.compile(r"[Ff]ixed(?: in| version)?[^0-9A-Za-z|]*([0-9][^\s|,;)]*)")
_ECOSYSTEM_PATTERN = re.compile(r"\b(npm|PyPI|Maven|Packagist|Go|crates\.io|RubyGems|NuGet)\b")
#: Inside the analysis container the tree is mounted at ``/work`` and tools
#: report it with or without the leading slash; in ``local`` runner mode they
#: report the jail's own absolute path, which the pipeline passes as a root.
#: Only an EXACT root is stripped: a generic ``/src/`` rule ate the audited
#: tree's own ``src/`` directory (proven on the MINCYT frontend, 2026-09-22),
#: leaving paths that matched neither the report nor the jail.
DEFAULT_ROOTS: tuple[str, ...] = ("/work", "work")


class NormalizationError(AppError):
    """A tool's output is not a SARIF document. Only raised inside the worker."""

    status_code = 422
    code = "normalization_failed"
    message_key = "errors.analysis.normalization"


@dataclass(frozen=True)
class ToolReport:
    tool: str
    category: ToolCategory
    sarif: dict[str, Any]


@dataclass(frozen=True)
class NormalizedFinding:
    category: ToolCategory
    tools: tuple[str, ...]
    rule_id: str
    cwe: int | None
    owasp: str | None
    title: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    path: str
    line: int | None
    snippet: str | None
    message: str | None
    advisory: dict[str, Any] | None
    references: tuple[str, ...]
    fingerprint: str


#: Rule ids of the CBOM inventory rules (rules/semgrep/crypto-inventory.yml).
#: Semgrep prefixes an id with the rule file's dotted path, so the LAST
#: dotted segment is what carries the prefix.
CRYPTO_RULE_PREFIX = "crypto-inventory-"
_CRYPTO_MESSAGE = re.compile(
    r"^crypto-asset primitive=(?P<primitive>[a-z]+) algorithm=(?P<algorithm>\S{1,80})"
    r" weak=(?P<weak>yes|no)$"
)
MAX_CRYPTO_ASSETS = 2000


@dataclass(frozen=True)
class NormalizedCryptoAsset:
    """One CBOM row: an algorithm the inventory rules saw at path:line."""

    primitive: str
    algorithm: str
    path: str
    line: int | None
    weak: bool
    rule_id: str


def is_crypto_inventory_rule(rule_id: str) -> bool:
    return rule_id.rsplit(".", 1)[-1].startswith(CRYPTO_RULE_PREFIX)


def _algorithm_name(raw: str) -> str:
    text = raw.strip().strip("\"'").upper().replace("_", "-")
    return re.sub(
        r"^(HMAC-)?SHA(?=(1|224|256|384|512)$)", lambda m: f"{m.group(1) or ''}SHA-", text
    )[:80]


def crypto_asset_from_message(
    rule_id: str, message: str | None, path: str, line: int | None
) -> NormalizedCryptoAsset | None:
    """Parse the fixed message shape the inventory rules commit to; ``None`` otherwise."""
    match = _CRYPTO_MESSAGE.match((message or "").strip())
    if match is None:
        return None
    return NormalizedCryptoAsset(
        primitive=match.group("primitive")[:40],
        algorithm=_algorithm_name(match.group("algorithm")),
        path=path,
        line=line,
        weak=match.group("weak") == "yes",
        rule_id=rule_id[:200],
    )


def normalize_crypto(
    reports: Sequence[ToolReport], roots: Sequence[str] = DEFAULT_ROOTS
) -> list[NormalizedCryptoAsset]:
    """Every crypto-inventory result of every SAST run, deduplicated by (path, line, algorithm)."""
    assets: dict[tuple[str, int | None, str], NormalizedCryptoAsset] = {}
    for report in reports:
        if report.category is not ToolCategory.SAST:
            continue
        for run in _list(report.sarif.get("runs")):
            if not isinstance(run, dict):
                continue
            for result in _list(run.get("results"))[:MAX_RESULTS_PER_RUN]:
                if not isinstance(result, dict):
                    continue
                rule_id = _text(result.get("ruleId"), MAX_RULE_ID) or ""
                if not is_crypto_inventory_rule(rule_id):
                    continue
                path, line, _snippet = _location(result, roots)
                asset = crypto_asset_from_message(
                    rule_id,
                    _text(_dict(result.get("message")).get("text"), MAX_MESSAGE),
                    path,
                    line,
                )
                if asset is not None:
                    assets.setdefault((asset.path, asset.line, asset.algorithm), asset)
                if len(assets) >= MAX_CRYPTO_ASSETS:
                    break
    return sorted(
        assets.values(), key=lambda a: (a.path, a.line if a.line is not None else -1, a.algorithm)
    )


def parse_sarif(text: str | bytes) -> dict[str, Any]:
    """Parse and structurally check a SARIF document."""
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise NormalizationError("tool output is not JSON") from error
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        raise NormalizationError("tool output is not a SARIF document")
    version = str(document.get("version", ""))
    if not version.startswith("2."):
        raise NormalizationError(f"unsupported SARIF version {version!r}")
    return document


# --- small hostile-input helpers ----------------------------------------------


def _text(value: object, limit: int) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped[:limit] if stripped else None
    return None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, float) and value >= 0 and value.is_integer():
        return int(value)
    return None


def _first_cwe(*sources: object) -> int | None:
    for source in sources:
        for item in _list(source) if isinstance(source, list) else [source]:
            if isinstance(item, bool):
                continue
            if isinstance(item, int) and 0 < item < 100_000:
                return item
            if isinstance(item, str):
                match = _CWE_PATTERN.search(item)
                if match:
                    return int(match.group(1))
    return None


def _first_owasp(*sources: object) -> str | None:
    for source in sources:
        for item in _list(source) if isinstance(source, list) else [source]:
            if isinstance(item, str):
                match = _OWASP_PATTERN.search(item)
                if match:
                    return f"A{match.group(1)}:2021"
    return None


def _first_vector(*sources: object) -> str | None:
    for source in sources:
        for item in _list(source) if isinstance(source, list) else [source]:
            if isinstance(item, str):
                match = _CVSS_PATTERN.search(item)
                if match:
                    return match.group(0)
    return None


def normalize_path(raw: object, roots: Sequence[str] = DEFAULT_ROOTS) -> str:
    """Relative POSIX path from the tree root, or empty when unknown.

    ``roots`` are the prefixes under which a tool may have seen the tree
    (the container mount, the jail on disk); the first exact match is
    stripped, nothing else is guessed. ``..`` segments are dropped.
    """
    text = _text(raw, MAX_PATH * 2)
    if text is None:
        return UNKNOWN_PATH
    text = text.replace("\\", "/")
    if text.lower().startswith("file://"):
        text = text[len("file://") :]
    for root in roots:
        prefix = root.replace("\\", "/").rstrip("/") + "/"
        # LEADING only, and only once: a root that merely appears inside the
        # path (``packages/work/x.js``) is part of the audited tree, and a
        # second pass would eat a real directory of the same name.
        if prefix != "/" and text.startswith(prefix):
            text = text[len(prefix) :]
            break
    parts = [part for part in text.split("/") if part not in ("", ".", "..")]
    cleaned = "/".join(parts)[:MAX_PATH]
    return cleaned or UNKNOWN_PATH


def _fingerprint(path: str, line: int | None, cwe: int | None, rule_id: str) -> str:
    key = f"{path}\x00{line if line is not None else ''}\x00{cwe if cwe else rule_id}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# --- SARIF walking --------------------------------------------------------------


def _rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = _dict(_dict(run.get("tool")).get("driver"))
    rules: dict[str, dict[str, Any]] = {}
    for rule in _list(driver.get("rules")):
        if isinstance(rule, dict):
            rule_id = _text(rule.get("id"), MAX_RULE_ID)
            if rule_id is not None:
                rules[rule_id] = rule
    return rules


def _location(result: dict[str, Any], roots: Sequence[str]) -> tuple[str, int | None, str | None]:
    for location in _list(result.get("locations")):
        physical = _dict(_dict(location).get("physicalLocation"))
        if not physical:
            continue
        artifact = _dict(physical.get("artifactLocation"))
        region = _dict(physical.get("region"))
        path = normalize_path(artifact.get("uri"), roots)
        line = _int(region.get("startLine"))
        snippet = _text(_dict(region.get("snippet")).get("text"), MAX_SNIPPET)
        return path, line, snippet
    return UNKNOWN_PATH, None, None


def _rule_text(rule: dict[str, Any], key: str) -> str | None:
    """A ``{"text": ...}`` rule property such as ``shortDescription``."""
    return _text(_dict(rule.get(key)).get("text"), MAX_TITLE)


def _rule_name(rule: dict[str, Any]) -> str | None:
    """SARIF ``rule.name`` is a plain string, unlike the description properties."""
    return _text(rule.get("name"), MAX_TITLE)


def _fixed_version(help_text: str, message: str, rule_id: str, package: str | None) -> str | None:
    """Fixed version from OSV-Scanner's remediation table, else from prose."""
    if package:
        row = re.compile(
            r"\|\s*"
            + re.escape(rule_id)
            + r"\s*\|\s*"
            + re.escape(package)
            + r"\s*\|\s*([^\s|]+)\s*\|"
        )
        match = row.search(help_text)
        if match:
            return match.group(1)[:100]
    match = _FIXED_PATTERN.search(help_text) or _FIXED_PATTERN.search(message)
    return match.group(1)[:100] if match else None


def _references(rule: dict[str, Any], result: dict[str, Any]) -> tuple[str, ...]:
    refs: list[str] = []
    for source in (
        _dict(rule.get("properties")).get("references"),
        _dict(result.get("properties")).get("references"),
        rule.get("helpUri"),
    ):
        for item in _list(source) if isinstance(source, list) else [source]:
            text = _text(item, 500)
            if text and text.startswith(("http://", "https://")) and text not in refs:
                refs.append(text)
    return tuple(refs[:MAX_REFERENCES])


def _security_severity(rule: dict[str, Any], result: dict[str, Any]) -> float | None:
    for props in (_dict(result.get("properties")), _dict(rule.get("properties"))):
        raw = props.get("security-severity")
        if isinstance(raw, int | float) and not isinstance(raw, bool):
            return float(raw)
        if isinstance(raw, str):
            try:
                return float(raw)
            except ValueError:
                continue
    return None


def _title_case_rule(rule_id: str) -> str:
    return " ".join(word.capitalize() for word in re.split(r"[-_\s]+", rule_id) if word)


def _semgrep_finding(
    tool: str,
    category: ToolCategory,
    rule: dict[str, Any],
    result: dict[str, Any],
    roots: Sequence[str],
) -> NormalizedFinding:
    rule_id = _text(result.get("ruleId"), MAX_RULE_ID) or _text(rule.get("id"), MAX_RULE_ID) or "?"
    rule_props = _dict(rule.get("properties"))
    result_props = _dict(result.get("properties"))
    metadata = _dict(rule_props.get("metadata"))
    tags = _list(rule_props.get("tags"))
    cwe = _first_cwe(
        result_props.get("cwe"), rule_props.get("cwe"), metadata.get("cwe"), tags, rule.get("id")
    )
    owasp = owasp_for(cwe) or _first_owasp(
        result_props.get("owasp"), rule_props.get("owasp"), metadata.get("owasp"), tags
    )
    vector = _first_vector(
        result_props.get("cvss"),
        result_props.get("cvss_vector"),
        rule_props.get("cvss"),
        metadata.get("cvss"),
        rule_props.get("cvss_vector"),
    )
    score, severity = _score_and_severity(vector, _security_severity(rule, result), result)
    path, line, snippet = _location(result, roots)
    fallback = _rule_text(rule, "shortDescription") or _rule_name(rule) or rule_id
    title = describe(cwe, fallback_title=fallback).title[:MAX_TITLE]
    return NormalizedFinding(
        category=category,
        tools=(tool,),
        rule_id=rule_id,
        cwe=cwe,
        owasp=owasp,
        title=title,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        path=path,
        line=line,
        snippet=snippet,
        message=_text(_dict(result.get("message")).get("text"), MAX_MESSAGE),
        advisory=None,
        references=_references(rule, result),
        fingerprint=_fingerprint(path, line, cwe, rule_id),
    )


def _score_and_severity(
    vector: str | None, security_severity: float | None, result: dict[str, Any]
) -> tuple[float | None, Severity]:
    if vector is not None:
        try:
            score = base_score(vector)
        except ValueError:
            pass  # a malformed vector is hostile input, not a crash: fall through
        else:
            return score, severity_for_score(score)
    if security_severity is not None and 0 <= security_severity <= 10:
        return None, severity_for_score(security_severity)
    return None, severity_for_level(_text(result.get("level"), 16))


def _gitleaks_finding(
    tool: str, rule: dict[str, Any], result: dict[str, Any], roots: Sequence[str]
) -> NormalizedFinding:
    rule_id = _text(result.get("ruleId"), MAX_RULE_ID) or "secret"
    path, line, snippet = _location(result, roots)
    name = _rule_name(rule) or _title_case_rule(rule_id)
    title = f"Secreto expuesto ({name})"[:MAX_TITLE]
    return NormalizedFinding(
        category=ToolCategory.SECRET,
        tools=(tool,),
        rule_id=rule_id,
        cwe=GITLEAKS_CWE,
        owasp=owasp_for(GITLEAKS_CWE),
        title=title,
        severity=Severity.HIGH,
        cvss_score=None,
        cvss_vector=None,
        path=path,
        line=line,
        snippet=snippet,
        message=_text(_dict(result.get("message")).get("text"), MAX_MESSAGE),
        advisory=None,
        references=_references(rule, result),
        fingerprint=_fingerprint(path, line, GITLEAKS_CWE, rule_id),
    )


def _osv_finding(
    tool: str, rule: dict[str, Any], result: dict[str, Any], roots: Sequence[str]
) -> NormalizedFinding:
    rule_id = _text(result.get("ruleId"), MAX_RULE_ID) or "advisory"
    rule_props = _dict(rule.get("properties"))
    result_props = _dict(result.get("properties"))
    message = _text(_dict(result.get("message")).get("text"), MAX_MESSAGE) or ""
    help_text = " ".join(
        text
        for text in (
            _text(_dict(rule.get("help")).get("text"), MAX_MESSAGE),
            _text(_dict(rule.get("help")).get("markdown"), MAX_MESSAGE),
            _text(_dict(rule.get("fullDescription")).get("text"), MAX_MESSAGE),
        )
        if text
    )
    cwe = _first_cwe(result_props.get("cwe"), rule_props.get("cwe"), rule_props.get("tags"))
    cwe = cwe if cwe is not None else DEPENDENCY_CWE
    vector = _first_vector(
        result_props.get("cvss"),
        result_props.get("cvss_vector"),
        rule_props.get("cvss"),
        rule_props.get("cvss_vector"),
        rule_props.get("tags"),
        message,
        help_text,
    )
    score, severity = _score_and_severity(vector, _security_severity(rule, result), result)

    package = _text(result_props.get("package"), MAX_TITLE)
    version = _text(result_props.get("version"), 100)
    if package is None or version is None:
        match = _PACKAGE_AT_VERSION.search(message) or _PACKAGE_AT_VERSION.search(help_text)
        if match:
            package = package or match.group(1)[:MAX_TITLE]
            version = version or match.group(2)[:100]
    fixed = _text(result_props.get("fixed"), 100) or _fixed_version(
        help_text, message, rule_id, package
    )
    ecosystem = _text(result_props.get("ecosystem"), 40)
    if ecosystem is None:
        eco_match = _ECOSYSTEM_PATTERN.search(help_text) or _ECOSYSTEM_PATTERN.search(message)
        ecosystem = eco_match.group(1) if eco_match else None

    path, line, snippet = _location(result, roots)
    subject = f"{package}@{version}" if package and version else package or "dependencia"
    title = f"Dependencia vulnerable: {subject} ({rule_id})"[:MAX_TITLE]
    return NormalizedFinding(
        category=ToolCategory.SCA,
        tools=(tool,),
        rule_id=rule_id,
        cwe=cwe,
        owasp=owasp_for(cwe),
        title=title,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        path=path,
        line=line,
        snippet=snippet,
        message=message or None,
        advisory={
            "id": rule_id,
            "package": package,
            "version": version,
            "fixed": fixed,
            "ecosystem": ecosystem,
        },
        references=_references(rule, result),
        fingerprint=_fingerprint(path, line, None, f"{rule_id}:{package or ''}"),
    )


def _findings_for_run(
    report: ToolReport, run: dict[str, Any], roots: Sequence[str]
) -> list[NormalizedFinding]:
    rules = _rules_by_id(run)
    tool = report.tool.strip().lower()[:40] or "unknown"
    findings: list[NormalizedFinding] = []
    for result in _list(run.get("results"))[:MAX_RESULTS_PER_RUN]:
        if not isinstance(result, dict):
            continue
        rule_id = _text(result.get("ruleId"), MAX_RULE_ID) or ""
        if is_crypto_inventory_rule(rule_id):
            # A CBOM row, never a finding: a strong algorithm is not a weakness
            # (normalize_crypto reads these; weak-crypto.yml makes the findings).
            continue
        rule = rules.get(rule_id, {})
        if tool == "gitleaks" or report.category is ToolCategory.SECRET:
            findings.append(_gitleaks_finding(tool, rule, result, roots))
        elif tool == "osv-scanner" or report.category is ToolCategory.SCA:
            findings.append(_osv_finding(tool, rule, result, roots))
        else:
            findings.append(_semgrep_finding(tool, report.category, rule, result, roots))
    return findings


def _merge(kept: NormalizedFinding, other: NormalizedFinding) -> NormalizedFinding:
    tools = kept.tools + tuple(tool for tool in other.tools if tool not in kept.tools)
    references = kept.references + tuple(
        ref for ref in other.references if ref not in kept.references
    )
    worse = other if SEVERITY_ORDER[other.severity] < SEVERITY_ORDER[kept.severity] else kept
    return replace(
        kept,
        tools=tools,
        references=references[:MAX_REFERENCES],
        severity=worse.severity,
        cvss_score=kept.cvss_score if kept.cvss_score is not None else other.cvss_score,
        cvss_vector=kept.cvss_vector if kept.cvss_vector is not None else other.cvss_vector,
        snippet=kept.snippet if kept.snippet is not None else other.snippet,
        message=kept.message if kept.message is not None else other.message,
        cwe=kept.cwe if kept.cwe is not None else other.cwe,
        owasp=kept.owasp if kept.owasp is not None else other.owasp,
    )


def normalize(
    reports: Sequence[ToolReport], roots: Sequence[str] = DEFAULT_ROOTS
) -> list[NormalizedFinding]:
    """Every result of every run, deduplicated across tools and sorted for the report.

    ``roots``: the prefixes under which the tools saw the tree (see ``normalize_path``).
    """
    merged: dict[str, NormalizedFinding] = {}
    for report in reports:
        for run in _list(report.sarif.get("runs")):
            if not isinstance(run, dict):
                continue
            for finding in _findings_for_run(report, run, roots):
                existing = merged.get(finding.fingerprint)
                merged[finding.fingerprint] = (
                    finding if existing is None else _merge(existing, finding)
                )
    return sorted(
        merged.values(),
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            item.path,
            item.line if item.line is not None else -1,
            item.rule_id,
        ),
    )


__all__ = [
    "NormalizationError",
    "NormalizedCryptoAsset",
    "NormalizedFinding",
    "ToolReport",
    "crypto_asset_from_message",
    "is_crypto_inventory_rule",
    "normalize",
    "normalize_crypto",
    "normalize_path",
    "parse_sarif",
]
