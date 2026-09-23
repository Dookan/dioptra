"""Report engine: structure follows the anchor, hostile values never render raw."""

from __future__ import annotations

import importlib.util
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analysis.models import (
    Analysis,
    AnalysisStatus,
    CodeMetrics,
    Finding,
    Severity,
    SourceKind,
    ToolCategory,
    ToolRun,
    ToolStatus,
)
from app.projects.models import Project, System
from app.reports import context as context_module
from app.reports import engine
from app.reports.context import build_context
from app.reports.errors import ForbiddenAssetFetch

HOSTILE_SNIPPET = "<script>alert(1)</script>"
HOSTILE_PATH = '"><img src=x onerror=alert(1)>'


@dataclass(frozen=True)
class _StubEntry:
    title: str
    description: str
    impact: str
    mitigation: tuple[str, ...]
    references: tuple[str, ...]


@pytest.fixture(autouse=True)
def _catalog_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the real catalog when the sibling module exists; otherwise a stub."""
    if importlib.util.find_spec("app.analysis.catalog") is not None:
        return

    def describe(cwe: int | None, fallback_title: str | None = None) -> _StubEntry:
        title = fallback_title or ("Debilidad sin clasificar" if cwe is None else f"CWE-{cwe}")
        return _StubEntry(
            title=title,
            description="Descripción de prueba.",
            impact="Impacto de prueba.",
            mitigation=("Mitigar.",),
            references=(f"https://cwe.mitre.org/data/definitions/{cwe or 0}.html",),
        )

    monkeypatch.setattr(context_module, "_catalog_describe", describe)


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "ordinal": 0,
        "category": ToolCategory.SAST,
        "tools": ["semgrep"],
        "rule_id": "dioptra.xss",
        "cwe": 79,
        "owasp": "A03:2021",
        "title": "Cross-Site Scripting (XSS)",
        "severity": Severity.MEDIUM,
        "cvss_score": None,
        "cvss_vector": None,
        "path": "index.js",
        "line": 36,
        "snippet": None,
        "message": None,
        "advisory": None,
        "references": [],
        "fingerprint": "f" * 64,
    }
    base.update(overrides)
    return Finding(**base)


def _tool_run(
    tool: str, category: ToolCategory, status: ToolStatus, detail: str | None = None
) -> ToolRun:
    return ToolRun(id=uuid.uuid4(), tool=tool, category=category, status=status, detail=detail)


def _project(with_system: bool = True) -> Project:
    project = Project(id=uuid.uuid4(), name="formulario_mincyt_apirest-desarrollo")
    if with_system:
        project.system = System(
            id=uuid.uuid4(),
            project_id=project.id,
            name="formulario_mincyt_apirest-desarrollo",
            framework="Express",
        )
    return project


def _analysis(
    findings: list[Finding] | None = None,
    tool_runs: list[ToolRun] | None = None,
    commented: list[str] | None = None,
) -> Analysis:
    analysis = Analysis(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        source_kind=SourceKind.ZIP,
        source_ref="upload.zip",
        status=AnalysisStatus.DONE,
        languages={"JavaScript": 12},
        frameworks=["Express"],
        lockfiles=["package-lock.json"],
    )
    analysis.findings = findings if findings is not None else []
    analysis.tool_runs = (
        tool_runs
        if tool_runs is not None
        else [
            _tool_run("semgrep", ToolCategory.SAST, ToolStatus.RAN),
            _tool_run("gitleaks", ToolCategory.SECRET, ToolStatus.RAN),
            _tool_run("osv-scanner", ToolCategory.SCA, ToolStatus.RAN),
        ]
    )
    analysis.metrics = CodeMetrics(
        id=uuid.uuid4(), functions=[], lines={}, commented_code_files=commented or []
    )
    return analysis


def _hostile_analysis() -> Analysis:
    return _analysis(
        findings=[
            _finding(snippet=HOSTILE_SNIPPET, path=HOSTILE_PATH, severity=Severity.HIGH),
            _finding(
                cwe=None,
                owasp=None,
                rule_id="custom.unknown",
                title="Regla sin CWE",
                severity=Severity.LOW,
                path="modulos/x.js",
                line=None,
            ),
            _finding(
                category=ToolCategory.SCA,
                tools=["osv-scanner"],
                rule_id="CVE-2024-0001",
                cwe=1395,
                owasp="A06:2021",
                title="Dependencia vulnerable",
                severity=Severity.HIGH,
                path="package-lock.json",
                line=None,
                advisory={
                    "id": "CVE-2024-0001",
                    "package": "lodash",
                    "version": "4.17.20",
                    "fixed": "4.17.21",
                },
            ),
        ],
        commented=["index.js", "<b>evil</b>.js"],
    )


# --- context -----------------------------------------------------------------


def test_installation_date_prints_in_the_reports_own_format() -> None:
    """The date is stored as a date and formatted at render, like every other date."""
    from datetime import date  # noqa: PLC0415

    project = _project()
    assert project.system is not None
    project.system.installed_at = date(2024, 3, 5)
    ctx = build_context(
        _hostile_analysis(), project, generated_at=datetime(2026, 6, 15, tzinfo=UTC)
    )
    assert ctx["system"]["installed_at"] == "05/03/2024"


def test_context_defaults_and_counts() -> None:
    analysis = _hostile_analysis()
    ctx = build_context(analysis, _project(), generated_at=datetime(2026, 6, 15, tzinfo=UTC))
    assert ctx["period"] == "Junio 2026"
    assert ctx["system"]["installed_at"] == "N/A"
    assert ctx["system"]["database"] == "N/A"
    assert ctx["system"]["framework"] == "Express"
    assert ctx["summary"]["total"] == 3
    assert ctx["summary"]["counts"]["high"] == 2
    assert "3 hallazgo(s) (2 alta, 1 baja)" in ctx["summary"]["sentence"]
    assert len(ctx["security_findings"]) == 2
    assert len(ctx["dependency_findings"]) == 1
    assert ctx["version_control"] == [
        {"version": "1", "areas": "Todas", "description": "-", "delivered_at": "N/A"}
    ]
    assert ctx["author"] == "Moises Marin"


def test_context_distribution_orders_and_percentages() -> None:
    # _hostile_analysis: A03 (high), unclassified (low), A06 (high) → 3 findings.
    ctx = build_context(_hostile_analysis(), _project())
    by_severity = {row["severity"]: row for row in ctx["summary"]["by_severity"]}
    assert by_severity["high"]["count"] == 2 and by_severity["high"]["percent"] == 67
    assert by_severity["low"]["count"] == 1 and by_severity["low"]["percent"] == 33
    assert by_severity["critical"]["count"] == 0 and by_severity["critical"]["percent"] == 0
    by_owasp = ctx["summary"]["by_owasp"]
    assert [row["count"] for row in by_owasp] == [1, 1, 1]
    # Ties break by code; the unclassified bucket always comes last.
    assert [row["code"] for row in by_owasp] == ["A03:2021", "A06:2021", None]
    assert by_owasp[-1]["label"] == "Sin clasificar"
    assert by_owasp[0]["title"] == "Injection"

    doubled = _analysis(
        findings=[_finding(), _finding(line=40), _finding(owasp="A06:2021", cwe=1395)]
    )
    ranked = build_context(doubled, _project())["summary"]["by_owasp"]
    assert [(row["code"], row["count"], row["percent"]) for row in ranked] == [
        ("A03:2021", 2, 67),
        ("A06:2021", 1, 33),
    ]

    empty = build_context(_analysis(findings=[]), _project())["summary"]
    assert empty["by_owasp"] == []
    assert all(row["percent"] == 0 and row["count"] == 0 for row in empty["by_severity"])


def test_context_framework_falls_back_to_detected_and_no_system() -> None:
    project = _project(with_system=False)
    ctx = build_context(_analysis(), project)
    assert ctx["system"]["name"] == project.name
    assert ctx["system"]["framework"] == "Express"
    assert ctx["summary"]["sentence"].startswith("El análisis identificó 0 hallazgo(s) (ninguno).")


def test_context_unknown_cwe_is_a_valid_state() -> None:
    ctx = build_context(_hostile_analysis(), _project())
    unknown = next(f for f in ctx["security_findings"] if f["cwe"] is None)
    assert unknown["cwe_label"] == "CWE desconocido"
    assert unknown["owasp_label"] == "Sin clasificar"
    assert unknown["location"] == "modulos/x.js"


def test_context_is_serializable() -> None:
    import json

    json.dumps(build_context(_hostile_analysis(), _project()))


# --- HTML --------------------------------------------------------------------


def test_html_escapes_hostile_snippet_and_path() -> None:
    html = engine.render_html(_hostile_analysis(), _project())
    assert HOSTILE_SNIPPET not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html
    assert "&#34;&gt;&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<b>evil</b>.js" not in html
    assert "CWE desconocido" in html
    assert "Sin clasificar" in html


def test_html_follows_anchor_section_order() -> None:
    html = engine.render_html(_hostile_analysis(), _project())
    order = [
        "Análisis de Caja Blanca Sistema",
        "INTRODUCCIÓN",
        "RESUMEN EJECUTIVO",
        "DETALLES DEL SISTEMA",
        "Control de versiones",
        "HALLAZGOS DE VULNERABILIDADES",
        "HALLAZGOS SOBRE PAQUETES Y DEPENDENCIAS",
        "ERRORES Y PRÁCTICAS NO ADECUADAS EN EL CÓDIGO",
        "COBERTURA DE HERRAMIENTAS",
    ]
    positions = [html.index(marker) for marker in order]
    assert positions == sorted(positions)
    assert "Nivel de severidad" in html
    assert "Código OWASP" in html
    assert "lodash" in html
    assert "ejecutada" in html
    assert "Presencia de código comentado en el sistema" in html


def test_html_dependency_wording_when_osv_missing() -> None:
    analysis = _analysis(
        tool_runs=[_tool_run("osv-scanner", ToolCategory.SCA, ToolStatus.MISSING, "no db")]
    )
    html = engine.render_html(analysis, _project())
    assert "no pudo ejecutarse" in html
    assert "no disponible" in html
    assert "No se identificaron dependencias" not in html


def test_html_dependency_clean_wording_when_osv_ran() -> None:
    html = engine.render_html(_analysis(), _project())
    assert "No se identificaron dependencias con vulnerabilidades conocidas" in html
    # The anchor omits both sections when there is nothing to list.
    assert "HALLAZGOS DE VULNERABILIDADES" not in html
    assert "ERRORES Y PRÁCTICAS" not in html


def test_html_inlines_its_stylesheet_and_references_nothing_external() -> None:
    html = engine.render_html(_analysis(), _project())
    assert "<style>" in html and "@page" in html
    assert "<link" not in html
    assert "http://" not in html and "https://" not in html.split("<body>")[0]


def test_sca_findings_use_the_anchor_title_convention() -> None:
    ctx = build_context(_hostile_analysis(), _project())
    dependency = ctx["dependency_findings"][0]
    assert dependency["title"] == "Dependencia con Vulnerabilidad Alta: lodash versión 4.17.20"
    assert dependency["subtitle"] == "Vulnerabilidad conocida: CVE-2024-0001"
    html = engine.render_html(_hostile_analysis(), _project())
    assert "A continuación lo encontrado:" in html
    assert dependency["title"] in html


# --- Markdown ----------------------------------------------------------------


def test_markdown_never_contains_raw_script() -> None:
    markdown = engine.render_markdown(_hostile_analysis(), _project())
    assert "<script" not in markdown
    assert "<img" not in markdown
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markdown
    assert markdown.startswith("# Análisis de Caja Blanca Sistema")


def test_markdown_fence_outgrows_backtick_runs() -> None:
    fenced = engine.md_fence("x ```` y")
    first_line = fenced.splitlines()[0]
    assert first_line == "`````"
    assert str(engine.md_escape("# | `a` <b>")) == "\\# \\| \\`a\\` &lt;b&gt;"
    # snake_case paths and package names stay readable; emphasis openers do not.
    assert str(engine.md_escape("formulario_mincyt_apirest-desarrollo")) == (
        "formulario_mincyt_apirest-desarrollo"
    )
    assert str(engine.md_escape("_em_ *b* [x](y)")) == "\\_em\\_ \\*b\\* \\[x\\](y)"


# --- PDF ---------------------------------------------------------------------


def test_url_fetcher_refuses_everything_but_template_assets(tmp_path: Path) -> None:
    with pytest.raises(ForbiddenAssetFetch):
        engine.restricted_url_fetcher("https://example.com/x.css")
    outside = tmp_path / "x.css"
    outside.write_text("body{}")
    with pytest.raises(ForbiddenAssetFetch):
        engine.restricted_url_fetcher(outside.as_uri())
    with pytest.raises(ForbiddenAssetFetch):
        engine.restricted_url_fetcher("file:///etc/passwd")


def test_url_fetcher_serves_the_stylesheet() -> None:
    pytest.importorskip("weasyprint")
    response = engine.restricted_url_fetcher((engine.TEMPLATES_DIR / "report.css").as_uri())
    assert response.read().startswith(b"/* Institutional")


def test_render_pdf_produces_a_pdf() -> None:
    weasyprint = pytest.importorskip("weasyprint")
    try:
        weasyprint.HTML(string="<p>x</p>").write_pdf()
    except OSError as exc:  # system libraries (pango/cairo) absent on this host
        pytest.skip(f"weasyprint cannot render here: {exc}")
    pdf = engine.render_pdf(_hostile_analysis(), _project())
    assert pdf.startswith(b"%PDF")


# --- DOCX --------------------------------------------------------------------


def test_render_docx_produces_a_docx() -> None:
    pytest.importorskip("docx")
    data = engine.render_docx(_hostile_analysis(), _project())
    assert data.startswith(b"PK")
