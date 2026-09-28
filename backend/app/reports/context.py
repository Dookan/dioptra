"""Report context: the one serializable dict every renderer consumes.

Everything here is DATA. Every label comes from ``templates/report/strings.json``
(report content, the carve-out CLAUDE.md names); this module holds no copy of
its own. Nothing in this module escapes anything: escaping is the renderer's
job, at render time, per output format.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any

from app.analysis.models import (
    SEVERITY_ORDER,
    Analysis,
    Finding,
    Severity,
    ToolCategory,
    ToolRun,
    ToolStatus,
)
from app.core.clock import utc_now
from app.projects.models import Project
from app.reports.closure import closure_context, stage_of
from app.reports.strings import report_strings

if TYPE_CHECKING:
    from app.reports.models import ReportVersion

_S = report_strings()
DATE_FORMAT: str = _S["date_format"]
NOT_AVAILABLE: str = _S["not_available"]
UNKNOWN_CWE_LABEL: str = _S["cwe_unknown"]
UNCLASSIFIED_OWASP_LABEL: str = _S["owasp_unclassified"]
UNKNOWN_PATH_LABEL: str = _S["path_unknown"]

SEVERITY_LABELS: dict[Severity, str] = {level: _S["severity"][level.value] for level in Severity}
#: Plural, lowercase forms used in the executive summary parenthesis.
SEVERITY_SUMMARY_WORDS: dict[Severity, str] = {
    level: _S["severity_summary"][level.value] for level in Severity
}
TOOL_STATUS_LABELS: dict[ToolStatus, str] = {
    status: _S["tool_status"][status.value] for status in ToolStatus
}
SPANISH_MONTHS: tuple[str, ...] = tuple(_S["months"])

#: Categories rendered in "Hallazgos de vulnerabilidades" (code, secrets and,
#: since phase 11, the sensitive artefacts committed to the tree).
SECURITY_CATEGORIES = frozenset({ToolCategory.SAST, ToolCategory.SECRET, ToolCategory.ARTEFACT})

#: Paragraph separator of the editable prose, both in defaults and overrides.
PARAGRAPH_BREAK = "\n\n"


def _catalog_describe(
    cwe: int | None, fallback_title: str | None, artefact_rule: str | None = None
) -> Any:
    """Resolve the institutional prose for a CWE.

    Imported lazily: the catalog is a sibling module of the pipeline and the
    report engine must stay importable (and testable) on its own.
    """
    from app.analysis.catalog import describe  # noqa: PLC0415

    return describe(cwe, fallback_title=fallback_title, artefact_rule=artefact_rule)


def _owasp_title(code: str | None) -> str | None:
    if code is None:
        return None
    from app.analysis.cwe_owasp import OWASP_TITLES  # noqa: PLC0415

    return OWASP_TITLES.get(code)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _or_na(value: str | None) -> str:
    text = (value or "").strip()
    return text or NOT_AVAILABLE


def _dependency_heading(finding: Finding, advisory: dict[str, Any]) -> tuple[str, str]:
    """Title/subtitle of an SCA finding, as the institutional template words them."""
    package = advisory.get("package") or finding.title or NOT_AVAILABLE
    version = advisory.get("version") or NOT_AVAILABLE
    advisory_id = advisory.get("id") or finding.rule_id
    return (
        _S["dependency_title"].format(
            severity=SEVERITY_LABELS[finding.severity], package=package, version=version
        ),
        _S["dependency_subtitle"].format(advisory_id=advisory_id),
    )


def _finding_context(finding: Finding) -> dict[str, Any]:
    entry = _catalog_describe(
        finding.cwe,
        finding.title,
        finding.rule_id if finding.category is ToolCategory.ARTEFACT else None,
    )
    path = finding.path or UNKNOWN_PATH_LABEL
    location = path if finding.line is None else f"{path}:{finding.line}"
    advisory = finding.advisory or {}
    title = finding.title or entry.title
    cwe_label = UNKNOWN_CWE_LABEL if finding.cwe is None else f"CWE-{finding.cwe}"
    subtitle = cwe_label
    if finding.category is ToolCategory.SCA:
        title, subtitle = _dependency_heading(finding, advisory)
    return {
        "title": title,
        "subtitle": subtitle,
        "severity": finding.severity.value,
        "severity_label": SEVERITY_LABELS[finding.severity],
        "cwe": finding.cwe,
        "cwe_label": cwe_label,
        "owasp": finding.owasp,
        "owasp_label": finding.owasp or UNCLASSIFIED_OWASP_LABEL,
        "owasp_title": _owasp_title(finding.owasp),
        "description": entry.description,
        "impact": entry.impact,
        "mitigation": list(entry.mitigation),
        "references": _dedupe([*entry.references, *finding.references]),
        "path": path,
        "line": finding.line,
        "location": location,
        "snippet": finding.snippet,
        "message": finding.message,
        "tools": list(finding.tools),
        "rule_id": finding.rule_id,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "advisory": {
            "id": advisory.get("id") or finding.rule_id,
            "package": advisory.get("package") or NOT_AVAILABLE,
            "version": advisory.get("version") or NOT_AVAILABLE,
            "fixed": advisory.get("fixed") or NOT_AVAILABLE,
            "ecosystem": advisory.get("ecosystem"),
        },
    }


def _tool_run_context(run: ToolRun) -> dict[str, Any]:
    return {
        "tool": run.tool,
        "category": run.category.value,
        "status": run.status.value,
        "status_label": TOOL_STATUS_LABELS[run.status],
        "detail": run.detail or "",
    }


def _sorted_findings(
    findings: list[Finding], excluded: frozenset[str] | None = None
) -> list[Finding]:
    # "Es real — incluir en el reporte": a false positive leaves the report;
    # a pending finding stays, so an untriaged analysis still exports in full.
    # A signed version carries the set it was signed with (``excluded``) and
    # ignores the live triage: what was signed is what renders.
    if excluded is None:
        kept = [f for f in findings if f.in_report]
    else:
        kept = [f for f in findings if str(f.id) not in excluded]
    return sorted(
        kept,
        key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line if f.line is not None else -1),
    )


def _owasp_distribution(findings: list[Finding]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for finding in findings:
        code = finding.owasp or ""
        counts[code] = counts.get(code, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0] or "~"))
    return [
        {
            "code": code or None,
            "label": code or UNCLASSIFIED_OWASP_LABEL,
            "title": _owasp_title(code or None),
            "count": count,
        }
        for code, count in ordered
    ]


def _paragraphs(text: str) -> list[str]:
    return [part.strip() for part in text.split(PARAGRAPH_BREAK) if part.strip()]


def default_sections(
    analysis: Analysis, project: Project, *, excluded: frozenset[str] | None = None
) -> dict[str, str]:
    """The institutional prose of every editable section, as plain text."""
    system = project.system
    system_name = _or_na(system.name if system is not None else project.name)
    findings = _sorted_findings(list(analysis.findings), excluded)
    counts = {level.value: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return {
        "introduction": PARAGRAPH_BREAK.join(
            paragraph.format(system_name=system_name) for paragraph in _S["introduction"]
        ),
        "summary": _summary_sentence(counts, len(findings)),
        "findings_intro": _S["findings_intro"],
        "dependencies_intro": _S["dependencies_intro"],
        "practices": PARAGRAPH_BREAK.join(_S["commented_code"]),
        "coverage_intro": _S["coverage_intro"],
    }


def _version_rows(versions: Sequence[ReportVersion], upto: int | None) -> list[dict[str, str]]:
    rows = [
        {
            "version": str(item.number),
            "areas": item.areas,
            "description": item.change_summary,
            # "Fecha de entrega" is the signature date: a draft was never delivered.
            "delivered_at": (
                NOT_AVAILABLE if item.signed_at is None else item.signed_at.strftime(DATE_FORMAT)
            ),
        }
        for item in versions
        if upto is None or item.number <= upto
    ]
    return rows or [{**_S["version_control_default"], "delivered_at": NOT_AVAILABLE}]


def _summary_sentence(counts: dict[str, int], total: int) -> str:
    # Mirrors the anchor: "(2 alta, 4 media)", every level with a count, in
    # severity order; "ninguno" when nothing was found so the parenthesis is
    # never empty.
    parts = [
        f"{counts[level.value]} {SEVERITY_SUMMARY_WORDS[level]}"
        for level in Severity
        if counts[level.value] > 0
    ]
    breakdown = ", ".join(parts) or _S["none_found"]
    sentence: str = _S["summary_sentence"].format(total=total, breakdown=breakdown)
    return sentence


def build_context(
    analysis: Analysis,
    project: Project,
    *,
    version: ReportVersion | None = None,
    versions: Sequence[ReportVersion] = (),
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Assemble the pure, serializable context shared by every output format.

    ``version`` supplies the analyst's section overrides and, once signed, the
    frozen set of excluded findings; ``versions`` the history the "Control de
    versiones" table lists (rows after ``version`` are left out so a snapshot
    never shows its own future).
    """
    now = generated_at or utc_now()
    excluded: frozenset[str] | None = None
    if version is not None and version.excluded_findings is not None:
        excluded = frozenset(version.excluded_findings)
    system = project.system
    system_name = _or_na(system.name if system is not None else project.name)
    detected_frameworks = ", ".join(analysis.frameworks or [])
    framework = (system.framework if system is not None else None) or detected_frameworks

    ordered = _sorted_findings(list(analysis.findings), excluded)
    security = [_finding_context(f) for f in ordered if f.category in SECURITY_CATEGORIES]
    dependencies = [_finding_context(f) for f in ordered if f.category is ToolCategory.SCA]

    counts = {level.value: 0 for level in Severity}
    for finding in ordered:
        counts[finding.severity.value] += 1
    total = len(ordered)

    tool_runs = [_tool_run_context(run) for run in analysis.tool_runs]
    osv_run = next((run for run in analysis.tool_runs if run.tool == "osv-scanner"), None)
    dependency_scan_ran = osv_run is not None and osv_run.status is ToolStatus.RAN

    metrics = analysis.metrics
    commented_files = list(metrics.commented_code_files) if metrics is not None else []

    defaults = default_sections(analysis, project, excluded=excluded)
    overrides: dict[str, str] = dict(version.sections) if version is not None else {}
    sections = {
        key: _paragraphs(overrides.get(key) or default) for key, default in defaults.items()
    }

    return {
        "generated_at": now.isoformat(),
        "period": f"{SPANISH_MONTHS[now.month - 1]} {now.year}",
        "author": _S["author"],
        "system": {
            "name": system_name,
            "framework": _or_na(framework),
            "installed_at": _or_na(
                system.installed_at.strftime(DATE_FORMAT)
                if system is not None and system.installed_at is not None
                else None
            ),
            "database": _or_na(system.database if system is not None else None),
            "developer": _or_na(system.developer if system is not None else None),
        },
        "project": {"name": project.name, "description": project.description or ""},
        "analysis": {
            "id": str(analysis.id),
            "source_kind": analysis.source_kind.value,
            "source_ref": analysis.source_ref,
            "status": analysis.status.value,
            "languages": dict(analysis.languages or {}),
            "frameworks": list(analysis.frameworks or []),
            "lockfiles": list(analysis.lockfiles or []),
        },
        "version_control": _version_rows(versions, version.number if version is not None else None),
        "report_version": version.number if version is not None else 1,
        "sections": sections,
        "summary": {
            "total": total,
            "counts": counts,
            "sentence": _summary_sentence(counts, total),
            "by_severity": [
                {
                    "severity": level.value,
                    "label": SEVERITY_LABELS[level],
                    "count": counts[level.value],
                    "percent": round(100 * counts[level.value] / total) if total else 0,
                }
                for level in Severity
            ],
            "by_owasp": [
                {**row, "percent": round(100 * row["count"] / total) if total else 0}
                for row in _owasp_distribution(ordered)
            ],
        },
        "security_findings": security,
        "dependency_findings": dependencies,
        "dependency_scan_ran": dependency_scan_ran,
        "commented_code_files": commented_files,
        "tool_runs": tool_runs,
        "sbom_component_count": analysis.sbom.component_count if analysis.sbom else None,
        # Sections 7–10 (P5): computed from the workflow's own rows.
        **closure_context(analysis, ordered),
        "stage_label": _S["stages"].get(stage_of(analysis), stage_of(analysis)),
        # The institution's prose for sections 7–10, so the templates hold no copy.
        "strings": _S,
    }
