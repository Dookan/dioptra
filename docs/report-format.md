# Report format

> **Status: IN_PROGRESS — sections 1–6 plus "Hallazgos sobre paquetes", "Errores y prácticas" and "Cobertura de herramientas" built 2026-09-21 (`backend/app/reports/`, `backend/templates/report/`); versioning, signing and the editable sections built 2026-09-22 (`backend/app/reports/{versions,router}.py`, `frontend/src/screens/report-screen.tsx`); sections 7–10 (Métricas de código, Deuda de pruebas, Inventario de software, Anexos A–E) built 2026-09-22 (`backend/app/reports/{closure,svg}.py`, every format); PDF fidelity is a first structural pass, see the scope-change log.** Anchor: the institution's
> manual white-box reports on the MINCYT form systems, in
> `/home/user/Desktop/UTD/CAJA-BLANCA/*.pdf` (structure is authoritative; the
> platform must reproduce it indistinguishably — the P1 success criterion,
> checked section by section on the plan's day 10). "MINCYT" names the audited
> systems; the template belongs to the institution.

## Structure (institutional template, kept)

1. Cover (institutional header, system name, date)
2. Introducción
3. Resumen ejecutivo — with severity/OWASP distribution tables and bars (P2, pure CSS in the PDF, tokens in the UI)
4. Detalles del sistema (name, framework, DB, developer, install date — a
   real `date` column since migration 0011 (2026-09-23): the browser's date
   input hands over ISO, the API refuses text and a future date, and the
   report formats it with `%d/%m/%Y` like every other date; `N/A` when unset)
5. Control de versiones (auto-filled from the report versions: number, areas changed, change description, delivery date = signature date, `N/A` for a draft)
6. Hallazgos — per finding: title, severity, CWE, OWASP code, description,
   impact, detection (path:line + escaped snippet), mitigation, references
7. **Métricas de código** (P5, built): functions measured, the ten most
   complex (Lizard `ccn`, `nloc`), lines by language (cloc), files with
   commented-out code; duplication is stated as not measured in v1.0.0 (no
   tool in the authority table).
8. **Deuda de pruebas** (P5, built): the current workflow stage, the E4 plan
   (criterion, author, the team's own rationale), and per planned function
   the cases designed, whether a test file exists, statement and branch
   percentages from the LATEST verification run, the run's verdict by name,
   the brief items left uncovered and the mutants that survived; totals
   underneath. No plan → "la deuda es total".
9. **Inventario de software** (P5, built): component count and licences from
   the stored SBOM; when the render has the analysis' session, the
   correlation against the local mirror — open CVEs with VEX state, the
   analyst's "No aplica" justifications, outdated components, the CBOM
   rows — and the local copy's date. No SBOM → said in one sentence.
10. **Anexos** (P5, built) — A: the fourteen ASVS 4.0 chapters with the
    number of report findings whose OWASP category maps to each (static
    map in `strings.json`, "cero hallazgos no es verificado"); B: one flow
    diagram per designed function as inline SVG produced SERVER-SIDE from
    the AST layout (`reports/svg.py`, escaped labels, presentation
    attributes only, never the browser's picture — `docs/threat-model.md`
    → Flow diagrams) with the Mermaid interchange text under it (DOCX
    carries the Mermaid text only); C: the developer's cases per function
    with the brief items each declares; D: the stored test files verbatim,
    capped at 40 000 characters; E: the SBOM and CBOM summary with the note
    that the CycloneDX JSON documents are exported from the inventory panel
    — a PDF cannot carry an attachment WeasyPrint would embed faithfully.
11. Footer authorship: **Moises Marin**

Delivery per phase: sections 1–6 in P1 (day 9, PDF + Markdown + basic DOCX);
the visual executive summary in P2; sections 7–10 in P5 (day 19, built
2026-09-22). Sections 7–10 are COMPOSED, not editable: they carry no prose
of the analyst's, so they are absent from the editor's section list
(recorded deviation from mockup 09, `docs/ui-model.md` → Phase 5 screens).

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
  after its own. **Recorded limit (P5)**: sections 7–10 are composed LIVE
  from the workflow rows and the mirror — a signed version freezes its prose
  and its finding set, not the test-debt and inventory numbers, so the same
  signed version exported after a later verification run or a mirror sync
  can show different section 8/9 content. Snapshotting 7–10 into the
  version row is a 1.x decision for `mmarin`; until then the signature
  attests the prose and the finding set of sections 1–6. **Section 4 is the
  one composed part of them**: "Detalles del sistema" renders the `systems`
  row as it is at export time, so a change to that row — an edit, or migration
  `0011` nulling a free-text installation date — shows through in an
  already-signed version. The hash covers the version number, the section
  overrides and the excluded finding ids, never the system profile.
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
