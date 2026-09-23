"""Report sections 7–10 (P5 day 19): metrics, test debt, inventory, annexes.

Everything here is DATA for the renderers, computed from rows the workflow
already stores (metrics, plan, designs, test files, verification runs, the
SBOM and the mirror). Labels come from ``templates/report/strings.json``;
nothing is escaped here — the renderers escape at render time, per format,
and the annex SVG is produced by ``reports/svg.py`` with escaped labels.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy.orm import Session, object_session

from app.analysis.models import Analysis, Finding, Stage, ToolCategory
from app.reports.strings import report_strings
from app.workflow.ast.errors import AstError
from app.workflow.errors import WorkflowError
from app.workflow.models import CaseDesign, CoverageCriterion, TestFile, VerificationRun

MAX_TOP_FUNCTIONS = 10
MAX_ANNEX_DIAGRAMS = 12
MAX_ANNEX_TEST_CHARS = 40_000
MAX_INVENTORY_ROWS = 100
MAX_OUTDATED_ROWS = 50

_S = report_strings()


def _key(row: dict[str, Any]) -> tuple[str, str, int | None]:
    line = row.get("line")
    return (str(row.get("path")), str(row.get("function")), line if isinstance(line, int) else None)


# --- 7. `Métricas de código` (code metrics) -----------------------------------


def metrics_context(analysis: Analysis) -> dict[str, Any]:
    metrics = analysis.metrics
    functions: list[dict[str, Any]] = list(metrics.functions) if metrics is not None else []
    rows = [f for f in functions if isinstance(f, dict)]
    top = sorted(
        rows, key=lambda f: (-int(f.get("ccn") or 0), str(f.get("path")), str(f.get("function")))
    )
    languages: list[dict[str, Any]] = []
    lines = metrics.lines if metrics is not None and isinstance(metrics.lines, dict) else {}
    for language, counts in sorted(lines.items()):
        if not isinstance(counts, dict) or language in {"header", "SUM"}:
            continue
        languages.append(
            {
                "language": str(language),
                "files": int(counts.get("files") or counts.get("nFiles") or 0),
                "code": int(counts.get("code") or 0),
                "comment": int(counts.get("comment") or 0),
                "blank": int(counts.get("blank") or 0),
            }
        )
    complex_count = sum(1 for f in rows if int(f.get("ccn") or 0) > 10)
    return {
        "functions_measured": len(rows),
        "complex_functions": complex_count,
        "top": [
            {
                "path": str(f.get("path")),
                "function": str(f.get("function")),
                "line": f.get("line"),
                "ccn": int(f.get("ccn") or 0),
                "nloc": int(f.get("nloc") or 0),
            }
            for f in top[:MAX_TOP_FUNCTIONS]
        ],
        "languages": languages,
        "commented_files": len(metrics.commented_code_files) if metrics is not None else 0,
        # Duplication is not measured in v1.0.0 (no tool in the authority table).
        "duplication": None,
    }


# --- 8. `Deuda de pruebas` (test debt) ------------------------------------------


def _latest_runs(analysis: Analysis) -> dict[tuple[str, str, int | None], VerificationRun]:
    latest: dict[tuple[str, str, int | None], VerificationRun] = {}
    for run in analysis.verification_runs:
        latest[(run.path, run.function, run.line)] = run
    return latest


def stage_of(analysis: Analysis) -> str:
    """The stage value; an unflushed row (default not applied yet) is at E2."""
    stage = analysis.stage
    return stage.value if isinstance(stage, Stage) else Stage.CODE.value


def test_debt_context(analysis: Analysis) -> dict[str, Any]:
    plan = analysis.test_plan
    if plan is None or not isinstance(plan.functions, list):
        return {"plan": None, "functions": [], "totals": None, "stage": stage_of(analysis)}
    designs: dict[tuple[str, str, int | None], CaseDesign] = {
        (d.path, d.function, d.line): d for d in analysis.case_designs
    }
    files: dict[tuple[str, str, int | None], TestFile] = {
        (f.path, f.function, f.line): f for f in analysis.test_files
    }
    runs = _latest_runs(analysis)
    rows: list[dict[str, Any]] = []
    planned: list[Any] = plan.functions  # a JSON column: shape checked, never trusted
    for raw in planned:
        if not isinstance(raw, dict):
            continue
        key = _key(raw)
        design = designs.get(key)
        stored = files.get(key)
        run = runs.get(key)
        coverage = run.coverage if run is not None and isinstance(run.coverage, dict) else {}
        rows.append(
            {
                "path": key[0],
                "function": key[1],
                "line": key[2],
                "ccn": raw.get("ccn"),
                "cases": len(design.cases)
                if design is not None and isinstance(design.cases, list)
                else 0,
                "approved": design is not None and design.approved_at is not None,
                "written": stored is not None and bool(stored.content.strip()),
                "statement_percent": coverage.get("statement_percent"),
                "branch_percent": coverage.get("branch_percent"),
                # The percentages are the MODULE's while the verdict is the
                # planned function's, so the document has to say which lines
                # were judged — the same rule the mutation gap follows
                # (docs/workflow-gates.md → E7 re-audit rules, question 3).
                "criterion_lines": coverage.get("criterion_lines"),
                "status": run.status.value if run is not None else None,
                "status_label": _S["test_debt"]["status"][run.status.value]
                if run is not None
                else _S["test_debt"]["status"]["none"],
                "survivors": len(run.surviving_mutants) if run is not None else 0,
                "equivalent": len(run.equivalent_mutants) if run is not None else 0,
                # Zero survivors means two different things, and the report has
                # to tell them apart: "the tests killed every mutant" and "the
                # tool could not produce one" (a free PHP function under
                # Infection). tasks/phase7a-php.md, `mmarin` 2026-09-23.
                "mutation_measured": run.mutation_measured if run is not None else True,
                "uncovered": list(run.uncovered_items) if run is not None else [],
            }
        )
    measured = [r for r in rows if r["statement_percent"] is not None]
    criterion = plan.criterion if isinstance(plan.criterion, CoverageCriterion) else None
    totals = {
        "functions": len(rows),
        "approved": sum(1 for r in rows if r["approved"]),
        "written": sum(1 for r in rows if r["written"]),
        "passed": sum(1 for r in rows if r["status"] == "passed"),
        "survivors": sum(int(r["survivors"]) for r in rows),
        "equivalent": sum(int(r["equivalent"]) for r in rows),
        "mutation_not_measured": sum(1 for r in rows if not r["mutation_measured"]),
        "statement_percent": round(
            sum(float(r["statement_percent"]) for r in measured) / len(measured), 1
        )
        if measured
        else None,
        "branch_percent": round(
            sum(float(r["branch_percent"] or 0) for r in measured) / len(measured), 1
        )
        if measured
        else None,
    }
    return {
        "plan": {
            "criterion": criterion.value if criterion is not None else None,
            "criterion_label": _S["test_debt"]["criterion"].get(
                criterion.value if criterion is not None else "", ""
            ),
            "rationale": plan.rationale,
            "created_by": plan.created_by_username,
        },
        "functions": rows,
        "totals": totals,
        "stage": stage_of(analysis),
    }


# --- 9. `Inventario` (software inventory) ---------------------------------------


def inventory_context(analysis: Analysis) -> dict[str, Any] | None:
    """The inventory of THIS analysis, or ``None`` when it has no SBOM.

    Needs the mirror, so it needs the analysis' own session; a detached
    analysis (unit tests, a render outside a request) gets an SBOM-only
    summary and no correlation.
    """
    if analysis.sbom is None:
        return None
    from app.inventory import (
        service,  # noqa: PLC0415 — keep reports importable without the inventory
    )
    from app.inventory.components import components_of  # noqa: PLC0415

    db: Session | None = object_session(analysis)
    components = components_of(analysis.sbom.document)
    licenses: Counter[str] = Counter()
    unlicensed = 0
    for component in components:
        if component.licenses:
            licenses.update(component.licenses)
        else:
            unlicensed += 1
    result: dict[str, Any] = {
        "components": len(components),
        "licenses": [{"name": n, "count": c} for n, c in licenses.most_common(8)],
        "unlicensed": unlicensed,
        "open": [],
        "not_affected": [],
        "outdated": [],
        "crypto": [],
        "correlated": False,
        "vulndb_last_update": None,
    }
    if db is None:
        return result
    inventory = service.inventory_of(db, analysis)
    from app.inventory import sync  # noqa: PLC0415

    last = sync.last_update(db)
    vex_labels: dict[str, str] = _S["inventory"]["vex"]
    matches = sorted(
        inventory.matches,
        key=lambda m: (not m.open, -(m.score or 0), m.component.name),
    )
    rows = [
        {
            "component": m.component.name,
            "version": m.component.version or _S["not_available"],
            "cve": m.cve,
            "score": m.score,
            "severity_label": _S["severity"][m.severity.value]
            if m.severity is not None
            else _S["not_available"],
            "fixed_in": m.fixed_in or _S["not_available"],
            "vex_label": vex_labels[m.vex_state],
            "justification": m.justification or "",
            "open": m.open,
        }
        for m in matches[:MAX_INVENTORY_ROWS]
    ]
    result.update(
        {
            "correlated": True,
            "open": [r for r in rows if r["open"]],
            "not_affected": [r for r in rows if not r["open"]],
            "outdated": [
                {
                    "component": inventory.components[i].name,
                    "version": inventory.components[i].version or _S["not_available"],
                    "newer": newer,
                }
                for i, newer in sorted(inventory.outdated.items())[:MAX_OUTDATED_ROWS]
            ],
            "crypto": [
                {
                    "algorithm": asset.algorithm,
                    "primitive": _S["inventory"]["primitive"].get(asset.primitive, asset.primitive),
                    "location": f"{asset.path}:{asset.line}"
                    if asset.line is not None
                    else asset.path,
                    "weak": asset.weak,
                }
                for asset in inventory.crypto[:MAX_INVENTORY_ROWS]
            ],
            "vulndb_last_update": last.finished_at.strftime(_S["date_format"])
            if last is not None and last.finished_at is not None
            else None,
        }
    )
    return result


# --- 10. `Anexos` (annexes) -----------------------------------------------------


def asvs_context(findings: list[Finding]) -> list[dict[str, Any]]:
    """ASVS chapters touched by the findings, through the static OWASP → ASVS map."""
    chapters: list[dict[str, Any]] = _S["asvs"]["chapters"]
    mapping: dict[str, list[str]] = _S["asvs"]["owasp_to_chapters"]
    counts: Counter[str] = Counter()
    for finding in findings:
        for chapter in mapping.get(finding.owasp or "", []):
            counts[chapter] += 1
    return [
        {"chapter": c["id"], "title": c["title"], "findings": counts.get(c["id"], 0)}
        for c in chapters
    ]


def annex_context(analysis: Analysis, findings: list[Finding]) -> dict[str, Any]:
    from app.reports.svg import layout_svg  # noqa: PLC0415
    from app.workflow.design import FunctionRef, flow_graph  # noqa: PLC0415
    from app.workflow.diagrams import layout, to_mermaid  # noqa: PLC0415

    diagrams: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for design in analysis.case_designs[:MAX_ANNEX_DIAGRAMS]:
        title = f"{design.path} · {design.function}"
        entry: dict[str, Any] = {
            "path": design.path,
            "function": design.function,
            "line": design.line,
        }
        try:
            graph = flow_graph(
                analysis, FunctionRef(path=design.path, function=design.function, line=design.line)
            )
            entry["svg"] = layout_svg(layout(graph), title=title)
            entry["mermaid"] = to_mermaid(graph)
        except (AstError, WorkflowError, OSError, ValueError):
            entry["svg"] = None
            entry["mermaid"] = None
        diagrams.append(entry)
        cases.append(
            {
                "path": design.path,
                "function": design.function,
                "approved": design.approved_at is not None,
                "cases": [
                    {
                        "id": f"C{index}",
                        "title": str(case.get("title", "")),
                        "covers": [str(c) for c in case.get("covers", [])]
                        if isinstance(case.get("covers"), list)
                        else [],
                    }
                    for index, case in enumerate(design.cases, start=1)
                    if isinstance(case, dict)
                ],
            }
        )
    tests = [
        {
            "filename": stored.filename,
            "path": stored.path,
            "function": stored.function,
            "content": stored.content[:MAX_ANNEX_TEST_CHARS],
            "truncated": len(stored.content) > MAX_ANNEX_TEST_CHARS,
        }
        for stored in analysis.test_files
    ]
    sbom = analysis.sbom
    return {
        "asvs": asvs_context(findings),
        "diagrams": diagrams,
        "cases": cases,
        "tests": tests,
        "sbom": {
            "generator": sbom.generator,
            "spec_version": sbom.spec_version,
            "components": sbom.component_count,
        }
        if sbom is not None
        else None,
    }


def closure_context(analysis: Analysis, findings: list[Finding]) -> dict[str, Any]:
    """Sections 7–10 in one dict; ``findings`` are the report's (false positives out)."""
    security = [
        f
        for f in findings
        if f.category in {ToolCategory.SAST, ToolCategory.SECRET, ToolCategory.SCA}
    ]
    return {
        "metrics": metrics_context(analysis),
        "test_debt": test_debt_context(analysis),
        "inventory": inventory_context(analysis),
        "annexes": annex_context(analysis, security),
    }
