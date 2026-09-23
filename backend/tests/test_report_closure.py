"""Report sections 7–10 (P5 day 19): metrics, test debt, inventory, annexes.

Composed from the workflow's own rows; every value that came from the
audited tree or from a person is escaped by the renderer, per format.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Severity, ToolCategory, Verdict
from app.core.clock import utc_now
from app.ingest import service as ingest_service
from app.inventory import importers
from app.inventory.models import CryptoAsset
from app.reports import closure, engine
from app.reports.svg import layout_svg

# Imported by module: pytest would otherwise try to collect the ``Test*`` ORM classes.
from app.workflow import models as wf
from app.workflow.ast.graph import FlowGraph, FlowNode
from app.workflow.diagrams import layout
from app.workflow.models import CaseDesign, CoverageCriterion, VerificationRun, VerificationStatus
from tests.inventory_support import LODASH_GHSA, attach_sbom, component, osv_record, write_osv_zip
from tests.support import make_finding, seed_done_analysis

HOSTILE = "<script>alert('annex')</script>"
MAX = 64 * 1024 * 1024


def _with_workflow(db: Session, jail: Path) -> Analysis:
    """An analysis at E7 with a plan, an approved design, a test file and a run."""
    analysis = seed_done_analysis(
        db,
        [make_finding(0, owasp="A03:2021"), make_finding(1, owasp="A07:2021", cwe=287)],
        jail=jail,
    )
    metrics = analysis.metrics
    assert metrics is not None
    metrics.lines = {
        "JavaScript": {"nFiles": 3, "code": 120, "comment": 10, "blank": 8},
        "SUM": {"nFiles": 3, "code": 120, "comment": 10, "blank": 8},
    }
    metrics.commented_code_files = ["src/file-0.js"]
    planned = [
        {"path": "src/billing.js", "function": "calculateDiscount", "line": 20, "ccn": 5},
        {"path": "src/utils.js", "function": "formatDate", "line": 3, "ccn": 2},
    ]
    analysis.test_plan = wf.TestPlan(
        criterion=CoverageCriterion.DECISIONS,
        rationale=f"Las funciones de facturación primero {HOSTILE}",
        functions=planned,
        created_by_username="cperez",
    )
    analysis.case_designs = [
        CaseDesign(
            path="src/billing.js",
            function="calculateDiscount",
            line=20,
            cases=[{"title": f"Descuento con importe negativo {HOSTILE}", "covers": ["R1", "F1"]}],
            brief={"items": []},
            approved_at=utc_now(),
            approved_by_username="cperez",
            created_by_username="cperez",
        )
    ]
    analysis.test_files = [
        wf.TestFile(
            path="src/billing.js",
            function="calculateDiscount",
            line=20,
            filename="billing.calculateDiscount.abc123.dioptra.test.js",
            content=f"it('C1', () => {{ expect(1).toBe(1); }}); // {HOSTILE}",
            created_by_username="cperez",
        )
    ]
    analysis.verification_runs = [
        VerificationRun(
            path="src/billing.js",
            function="calculateDiscount",
            line=20,
            status=VerificationStatus.FAILED,
            reasons=["mutant_survived"],
            coverage={"statement_percent": 80.0, "branch_percent": 50.0},
            uncovered_items=["F1"],
            surviving_mutants=[{"id": "1", "line": "21", "mutant": "x"}],
            created_by_username="cperez",
        )
    ]
    db.commit()
    db.refresh(analysis)
    return analysis


def test_metrics_context_ranks_by_complexity_and_skips_cloc_totals(
    db: Session, tmp_path: Path
) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    metrics = closure.metrics_context(analysis)
    assert metrics["functions_measured"] == 3
    assert metrics["complex_functions"] == 1, "validateForm has ccn 12"
    assert [f["function"] for f in metrics["top"]] == [
        "validateForm",
        "calculateDiscount",
        "formatDate",
    ]
    assert metrics["languages"] == [
        {"language": "JavaScript", "files": 3, "code": 120, "comment": 10, "blank": 8}
    ]
    assert metrics["commented_files"] == 1
    assert metrics["duplication"] is None


def test_test_debt_context_reads_plan_designs_files_and_latest_runs(
    db: Session, tmp_path: Path
) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    debt = closure.test_debt_context(analysis)
    assert debt["plan"]["criterion_label"] == "decisiones"
    assert debt["plan"]["created_by"] == "cperez"
    rows = {row["function"]: row for row in debt["functions"]}
    billing = rows["calculateDiscount"]
    assert (billing["cases"], billing["approved"], billing["written"]) == (1, True, True)
    assert (billing["statement_percent"], billing["branch_percent"]) == (80.0, 50.0)
    assert billing["status_label"] == "Rechazada" and billing["survivors"] == 1
    assert billing["uncovered"] == ["F1"]
    other = rows["formatDate"]
    assert (other["cases"], other["approved"], other["written"], other["status"]) == (
        0,
        False,
        False,
        None,
    )
    assert other["status_label"] == "Sin ejecutar"
    totals = debt["totals"]
    assert totals == {
        "functions": 2,
        "approved": 1,
        "written": 1,
        "passed": 0,
        # Both runs measured mutation: the gap is a wave-2 (PHP) case.
        "mutation_not_measured": 0,
        "survivors": 1,
        "equivalent": 0,
        "statement_percent": 80.0,
        "branch_percent": 50.0,
    }


def test_no_plan_means_total_debt(db: Session) -> None:
    analysis = seed_done_analysis(db, [])
    debt = closure.test_debt_context(analysis)
    assert debt["plan"] is None and debt["totals"] is None
    html = engine.render_html(analysis, ingest_service.get_project(db, analysis.project_id))
    assert "la deuda es total" in html


def test_inventory_section_correlates_through_the_analysis_session(
    db: Session, tmp_path: Path
) -> None:
    importers.import_dump(
        db,
        write_osv_zip(tmp_path / "osv.zip", [osv_record(LODASH_GHSA)]),
        kind=importers.OSV_ZIP,
        max_bytes=MAX,
    )
    analysis = seed_done_analysis(
        db,
        [
            make_finding(
                0,
                category=ToolCategory.SCA,
                rule_id=LODASH_GHSA,
                advisory={"id": LODASH_GHSA, "package": "lodash", "version": "4.17.15"},
                verdict=Verdict.FALSE_POSITIVE,
                verdict_justification=f"No se usa la ruta vulnerable {HOSTILE}",
                verdict_by_username="mmarin",
            )
        ],
    )
    attach_sbom(
        db,
        analysis,
        [
            component("lodash", "4.17.15", "pkg:npm/lodash@4.17.15", ["MIT"]),
            component(HOSTILE, "1.0.0", f"pkg:npm/{HOSTILE}@1.0.0"),
        ],
    )
    db.add(
        CryptoAsset(
            analysis_id=analysis.id,
            primitive="hash",
            algorithm="SHA-1",
            path=f"auth/{HOSTILE}.js",
            line=18,
            weak=True,
            rule_id="crypto-inventory-js-weak-hash",
        )
    )
    db.commit()
    db.refresh(analysis)
    section = closure.inventory_context(analysis)
    assert section is not None and section["correlated"]
    assert section["components"] == 2 and section["unlicensed"] == 1
    assert section["open"] == []
    assert section["not_affected"][0]["vex_label"] == "No aplica"
    assert section["outdated"][0]["newer"] == "4.17.19"
    assert (
        section["crypto"][0]["weak"] and section["crypto"][0]["primitive"] == "función de resumen"
    )
    project = ingest_service.get_project(db, analysis.project_id)
    html = engine.render_html(analysis, project)
    assert "INVENTARIO DE SOFTWARE" in html and "No aplica" in html and "SHA-1" in html
    assert HOSTILE not in html and "&lt;script&gt;" in html
    markdown = engine.render_markdown(analysis, project)
    assert "<script>" not in markdown and "SHA-1" in markdown


def test_no_sbom_says_so_in_every_format(db: Session) -> None:
    analysis = seed_done_analysis(db, [])
    project = ingest_service.get_project(db, analysis.project_id)
    assert closure.inventory_context(analysis) is None
    assert "no produjo un inventario" in engine.render_html(analysis, project)
    assert "no produjo un inventario" in engine.render_markdown(analysis, project)


def test_annexes_carry_asvs_diagrams_cases_and_tests_escaped(db: Session, tmp_path: Path) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    project = ingest_service.get_project(db, analysis.project_id)
    annexes = closure.annex_context(analysis, list(analysis.findings))
    asvs = {row["chapter"]: row["findings"] for row in annexes["asvs"]}
    assert asvs["V5"] == 1 and asvs["V2"] == 1 and asvs["V3"] == 1 and asvs["V4"] == 0
    assert len(annexes["asvs"]) == 14
    diagram = annexes["diagrams"][0]
    assert diagram["svg"] is not None and diagram["svg"].startswith("<svg")
    assert diagram["mermaid"] is not None and diagram["mermaid"].startswith("flowchart TD")
    assert annexes["cases"][0]["cases"][0]["covers"] == ["R1", "F1"]
    assert annexes["tests"][0]["filename"].endswith(".dioptra.test.js")
    html = engine.render_html(analysis, project)
    for marker in ("MÉTRICAS DE CÓDIGO", "DEUDA DE PRUEBAS", "INVENTARIO DE SOFTWARE", "ANEXOS"):
        assert marker in html
    positions = [
        html.index(m)
        for m in (
            "COBERTURA DE HERRAMIENTAS",
            "MÉTRICAS DE CÓDIGO",
            "DEUDA DE PRUEBAS",
            "INVENTARIO DE SOFTWARE",
            "ANEXOS",
        )
    ]
    assert positions == sorted(positions), "sections 7–10 follow the anchor's six"
    assert "<svg" in html and "Anexo B" in html
    assert HOSTILE not in html, "the rationale, the case title and the test file are escaped"
    assert html.count("&lt;script&gt;") >= 3
    assert "Verificación" in html and "Rechazada" in html
    markdown = engine.render_markdown(analysis, project)
    assert "<script>" not in markdown and "flowchart TD" in markdown
    docx = engine.render_docx(analysis, project)
    with zipfile.ZipFile(io.BytesIO(docx)) as archive:
        document = archive.read("word/document.xml").decode()
    assert "DEUDA DE PRUEBAS" in document and "Anexo C" in document
    assert "<script>" not in document


def test_pdf_renders_with_an_inline_diagram(db: Session, tmp_path: Path) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    project = ingest_service.get_project(db, analysis.project_id)
    pdf = engine.render_pdf(analysis, project)
    assert pdf.startswith(b"%PDF")


def test_svg_labels_are_escaped_and_clipped() -> None:
    graph = FlowGraph(
        name="f",
        language="javascript",
        line=1,
        params=[],
        complexity=2,
        nodes=[
            FlowNode(id="n0", kind="start", label="", line=None),
            FlowNode(id="n1", kind="decision", label=f'x < 1 && "{HOSTILE}"' + "a" * 60, line=3),
            FlowNode(id="n2", kind="end", label="", line=None),
        ],
        edges=[],
    )
    svg = str(layout_svg(layout(graph), title=f"f {HOSTILE}"))
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg and "&amp;&amp;" in svg
    assert "…" in svg, "long labels are clipped"
    assert "href" not in svg and "<style" not in svg


def test_context_stays_serializable_with_the_closure_sections(db: Session, tmp_path: Path) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    project = ingest_service.get_project(db, analysis.project_id)
    from app.reports.context import build_context  # noqa: PLC0415

    context = build_context(analysis, project)
    json.dumps({k: v for k, v in context.items() if k != "annexes"})
    assert context["metrics"]["functions_measured"] == 3
    assert context["stage_label"] == "Código"
    assert context["test_debt"]["totals"]["functions"] == 2


def test_severity_label_helper_is_the_institutions() -> None:
    assert closure._S["severity"][Severity.HIGH.value] == "Alta"


# --- the coverage adversary's survivors (P5 close), pinned one by one -----------


def test_complex_functions_count_strictly_above_ten_and_cloc_meta_rows_are_skipped(
    db: Session, tmp_path: Path
) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    metrics = analysis.metrics
    assert metrics is not None
    metrics.functions = [
        *metrics.functions,
        {"path": "src/e.js", "function": "eleven", "line": 1, "ccn": 11, "nloc": 5},
        {"path": "src/t.js", "function": "ten", "line": 1, "ccn": 10, "nloc": 5},
    ]
    metrics.lines = {
        **metrics.lines,
        "header": {"cloc_url": "https://x", "elapsed_seconds": 0.1, "n_files": 3},
    }
    db.commit()
    db.refresh(analysis)
    section = closure.metrics_context(analysis)
    assert section["complex_functions"] == 2, (
        "validateForm (12) and eleven (11); ten is not complex"
    )
    assert [r["language"] for r in section["languages"]] == ["JavaScript"]


def test_excused_mutants_are_counted_per_function_and_in_the_totals(
    db: Session, tmp_path: Path
) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    analysis.verification_runs[0].equivalent_mutants = [{"id": "7", "line": "4", "mutant": "x"}]
    db.commit()
    db.refresh(analysis)
    debt = closure.test_debt_context(analysis)
    rows = {row["function"]: row for row in debt["functions"]}
    assert rows["calculateDiscount"]["equivalent"] == 1
    assert debt["totals"]["equivalent"] == 1


def test_a_function_mutation_could_not_measure_says_so_in_every_format(
    db: Session, tmp_path: Path
) -> None:
    """Zero survivors and no measurement are different facts; the report tells them apart.

    A free PHP function under Infection yields no mutant at all
    (tasks/phase7a-php.md), so printing "0" in the survivors column would
    read as "your tests killed them all".
    """
    analysis = _with_workflow(db, tmp_path / "jail")
    analysis.verification_runs[0].mutation_measured = False
    db.commit()
    db.refresh(analysis)

    debt = closure.test_debt_context(analysis)
    assert debt["functions"][0]["mutation_measured"] is False
    assert debt["totals"]["mutation_not_measured"] == 1

    project = ingest_service.get_project(db, analysis.project_id)
    html = engine.render_html(analysis, project)
    assert "no medida" in html
    assert "solo rompe código declarado dentro de una clase" in html

    markdown = engine.render_markdown(analysis, project)
    assert "no medida" in markdown
    assert "solo rompe c\u00f3digo declarado dentro de una clase" in markdown

    with zipfile.ZipFile(io.BytesIO(engine.render_docx(analysis, project))) as archive:
        document = archive.read("word/document.xml").decode()
    assert "no medida" in document
    # The sentence under the totals, not just the cell: "mutantes vivos: 0"
    # alone reads as a measured zero (precommit invariant panel, 2026-09-23).
    assert "solo rompe c\u00f3digo declarado dentro de una clase" in document


def test_a_detached_analysis_gets_the_sbom_summary_without_a_correlation(
    db: Session, tmp_path: Path
) -> None:
    analysis = seed_done_analysis(db, [])
    attach_sbom(db, analysis, [component("lodash", "4.17.15", "pkg:npm/lodash@4.17.15")])
    db.refresh(analysis)
    assert analysis.sbom is not None and analysis.sbom.document
    db.expunge(analysis)
    section = closure.inventory_context(analysis)
    assert section is not None
    assert section["correlated"] is False and section["components"] == 1


def test_the_test_annex_is_capped_and_says_so(db: Session, tmp_path: Path) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    analysis.test_files[0].content = "x" * (closure.MAX_ANNEX_TEST_CHARS + 1)
    db.commit()
    db.refresh(analysis)
    entry = closure.annex_context(analysis, [])["tests"][0]
    assert entry["truncated"] is True and len(entry["content"]) == closure.MAX_ANNEX_TEST_CHARS


def test_stage_of_an_unflushed_analysis_is_code_and_asvs_counts_security_findings_only(
    db: Session, tmp_path: Path
) -> None:
    from app.analysis.models import Analysis as AnalysisModel  # noqa: PLC0415
    from app.analysis.models import Stage  # noqa: PLC0415

    assert closure.stage_of(AnalysisModel()) == Stage.CODE.value
    analysis = _with_workflow(db, tmp_path / "jail")
    context = closure.closure_context(
        analysis, [make_finding(5, owasp="A03:2021", category=ToolCategory.METRICS)]
    )
    assert {r["chapter"]: r["findings"] for r in context["annexes"]["asvs"]}["V5"] == 0


def test_svg_clips_at_the_limit_and_translates_the_builders_tokens() -> None:
    from app.workflow.ast.graph import FlowEdge  # noqa: PLC0415

    graph = FlowGraph(
        name="f",
        language="javascript",
        line=1,
        params=[],
        complexity=2,
        nodes=[
            FlowNode(id="n0", kind="start", label="", line=None),
            FlowNode(id="n1", kind="decision", label="b" * 60, line=3),
            FlowNode(id="n2", kind="end", label="", line=None),
        ],
        edges=[
            FlowEdge(source="n0", target="n1", label=""),
            FlowEdge(source="n1", target="n2", label="true"),
        ],
    )
    svg = str(layout_svg(layout(graph), title="f"))
    assert ">" + "b" * 27 + "…<" in svg and "b" * 28 not in svg
    assert ">sí<" in svg and ">true<" not in svg
    assert svg.index(">Inicio<") < svg.index(">Fin<")


def test_control_characters_from_the_audited_tree_never_poison_the_docx(
    db: Session, tmp_path: Path
) -> None:
    """The wrappers exist for THIS path: values the section editor never touched."""
    analysis = _with_workflow(db, tmp_path / "jail")
    project = ingest_service.get_project(db, analysis.project_id)
    assert analysis.test_plan is not None and analysis.metrics is not None
    analysis.test_plan.rationale = "Plan\x0c con control"
    analysis.metrics.functions = [
        {**row, "path": str(row["path"]) + "\x01"} for row in analysis.metrics.functions
    ]
    analysis.findings[0].path = "src/a\x02.js"
    analysis.findings[0].snippet = "var x\x03 = 1"
    analysis.test_files[0].content = "it('C1'\x04, () => {});"
    db.commit()
    db.refresh(analysis)
    assert engine.render_docx(analysis, project).startswith(b"PK")


def test_the_docx_carries_the_rationale_the_mermaid_and_the_test_code(
    db: Session, tmp_path: Path
) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    project = ingest_service.get_project(db, analysis.project_id)
    with zipfile.ZipFile(io.BytesIO(engine.render_docx(analysis, project))) as archive:
        document = archive.read("word/document.xml").decode()
    assert "Las funciones de facturación primero" in document
    assert "flowchart TD" in document
    assert "expect(1).toBe(1)" in document


def test_the_html_debt_table_and_the_annexes_carry_their_values_not_only_headings(
    db: Session, tmp_path: Path
) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    project = ingest_service.get_project(db, analysis.project_id)
    html = engine.render_html(analysis, project)
    assert 'calculateDiscount</td><td class="count">1</td><td class="count">Sí</td>' in html
    assert 'formatDate</td><td class="count">0</td><td class="count">No</td>' in html
    assert '<pre class="snippet">flowchart TD' in html
    assert "Ítems sin cubrir: F1" in html


def test_the_markdown_escapes_the_rationale_and_fences_the_test_code(
    db: Session, tmp_path: Path
) -> None:
    analysis = _with_workflow(db, tmp_path / "jail")
    project = ingest_service.get_project(db, analysis.project_id)
    assert analysis.test_plan is not None
    analysis.test_plan.rationale = "Primero | la tabla *y* esto"
    analysis.test_files[0].content = "it('C1', () => { /* ``` */ });"
    db.commit()
    db.refresh(analysis)
    markdown = engine.render_markdown(analysis, project)
    assert "Primero \\| la tabla \\*y\\* esto" in markdown
    assert markdown.count("````\n") == 2, "a fence longer than the three backticks inside"


def test_the_report_says_which_lines_the_criterion_judged_in_every_format(
    db: Session, tmp_path: Path
) -> None:
    """A module percentage beside a function verdict has to say which is which.

    The E7 criterion is judged over the planned function's own lines while the
    printed percentages remain the whole file's, so without this sentence a
    signed report can show "PASSED · 8.8 % de sentencias" and mean two
    different scopes in one row (precommit security auditor, 2026-09-23).
    Checked in every format, because the same omission already happened once
    with the mutation-gap sentence.
    """
    analysis = _with_workflow(db, tmp_path / "jail")
    run = analysis.verification_runs[0]
    run.coverage = {**run.coverage, "criterion_lines": [3, 7]}
    db.commit()
    db.refresh(analysis)

    debt = closure.test_debt_context(analysis)
    assert debt["functions"][0]["criterion_lines"] == [3, 7]

    project = ingest_service.get_project(db, analysis.project_id)
    needle = "el criterio de cobertura se juzgó"
    html = engine.render_html(analysis, project)
    assert needle in html
    markdown = engine.render_markdown(analysis, project)
    assert needle in markdown
    docx = engine.render_docx(analysis, project)
    with zipfile.ZipFile(io.BytesIO(docx)) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
    assert "se juzgó" in document

    # And a run whose span could not be resolved says nothing, because the
    # whole module WAS judged there — the sentence would be false.
    run.coverage = {k: v for k, v in run.coverage.items() if k != "criterion_lines"}
    db.commit()
    db.refresh(analysis)
    assert needle not in engine.render_html(analysis, project)
