# Report format

> **Status: IN_PROGRESS — sections 1–6 plus "Hallazgos sobre paquetes", "Errores y prácticas" and "Cobertura de herramientas" built 2026-09-21 (`backend/app/reports/`, `backend/templates/report/`); versioning, signing and the editable sections built 2026-09-22 (`backend/app/reports/{versions,router}.py`, `frontend/src/screens/report-screen.tsx`); PDF fidelity is a first structural pass, see the scope-change log.** Anchor: the institution's
> manual white-box reports on the MINCYT form systems, in
> `/home/user/Desktop/UTD/CAJA-BLANCA/*.pdf` (structure is authoritative; the
> platform must reproduce it indistinguishably — the P1 success criterion,
> checked section by section on the plan's day 10). "MINCYT" names the audited
> systems; the template belongs to the institution.

## Structure (institutional template, kept)

1. Cover (institutional header, system name, date)
2. Introducción
3. Resumen ejecutivo — with severity/OWASP distribution tables and bars (P2, pure CSS in the PDF, tokens in the UI)
4. Detalles del sistema (name, framework, DB, developer, install date)
5. Control de versiones (auto-filled from the report versions: number, areas changed, change description, delivery date = signature date, `N/A` for a draft)
6. Hallazgos — per finding: title, severity, CWE, OWASP code, description,
   impact, detection (path:line + escaped snippet), mitigation, references
7. **New:** Métricas de código (complexity, critical functions, duplication)
8. **New:** Deuda de pruebas (coverage before/after, tests written, basis
   paths covered, mutation score)
9. **New (P5):** Inventario — SBOM summary of the analyzed version, open CVEs
   per component with VEX status, outdated components
10. **New:** Anexos — ASVS checklist, flow diagrams, pseudocode, test code,
    SBOM/CBOM attached (CycloneDX JSON) — flow diagrams as SVG produced
    server-side from the AST, never from the browser (`docs/threat-model.md`
    → row Flow diagrams)
11. Footer authorship: **Moises Marin**

Delivery per phase: sections 1–6 in P1 (day 9, PDF + Markdown + basic DOCX);
the visual executive summary in P2; sections 7–10 in P5 (day 19).

## Behavior

- The report composes itself from workflow data; the prose sections
  (Introducción, Resumen ejecutivo, the intros of Hallazgos / Paquetes /
  Cobertura, Errores y prácticas) are editable in the platform BEFORE export,
  with versioned snapshots. **Plain text, not rich text** (P2 decision,
  `tasks/phase2-survey.md` §5): paragraphs separated by a blank line, escaped
  at every render — HTML authored in a browser and fed to WeasyPrint is the
  stored-XSS path the threat model names. A sanitized subset (bold, lists) is
  a later decision, not a gap.
- Version 1 is the composed baseline; every save inserts the next number with
  the merged overrides. Signing (analyst only, written justification, audit
  row `report.sign`) records actor, time and a SHA-256 of the signed content (version number,
  section overrides and the ids of the findings excluded by triage at signing
  time) and makes the row immutable by database trigger; a signed version
  keeps rendering exactly the finding set it was signed with — a verdict
  revised afterwards (possible only while the analysis is still at E3;
  `stage_locked` once E4 is entered) is logged and lands in the next version; later edits open the next
  version and the "Control de versiones" table updates automatically. An
  export may name a version (`?version=N`); a snapshot never lists versions
  after its own.
- Triage feeds the report: a finding the analyst marked "No aplica" (false
  positive) leaves every format and the executive-summary counts; a pending
  finding stays, so an untriaged analysis still exports in full.
- Exports: PDF (Jinja2 → HTML → WeasyPrint, template identical to the manual
  one), DOCX (basic in P1, python-docx as the candidate library), Markdown.
  Report language follows the UI language (es default).
- Known PDF risks (plan, week 2): long tables, page breaks, repeated headers
  in WeasyPrint. That is why day 10 is entirely fidelity work; if it slips,
  buffer is consumed and P2 starts anyway on the data.
- Coverage gaps (a tool that could not run, tests that could not execute) are
  reported explicitly — the current manual template already does this; keep it.
