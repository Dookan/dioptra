# Report format

> **Status: DESIGN SURFACE — not yet implemented.** Anchor: the institution's
> manual white-box reports on the MINCYT form systems, in
> `/home/user/Desktop/UTD/CAJA-BLANCA/*.pdf` (structure is authoritative; the
> platform must reproduce it indistinguishably — the P1 success criterion,
> checked section by section on the plan's day 10). "MINCYT" names the audited
> systems; the template belongs to the institution.

## Structure (institutional template, kept)

1. Cover (institutional header, system name, date)
2. Introducción
3. Resumen ejecutivo — now with severity/OWASP distribution visuals
4. Detalles del sistema (name, framework, DB, developer, install date)
5. Control de versiones (auto-filled from report edit history)
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

- The report composes itself from workflow data; every section is editable in
  the platform BEFORE export (rich text), with versioned snapshots.
- Signing locks a version; later edits create the next version and the
  "Control de versiones" table updates automatically.
- Exports: PDF (Jinja2 → HTML → WeasyPrint, template identical to the manual
  one), DOCX (basic in P1, python-docx as the candidate library), Markdown.
  Report language follows the UI language (es default).
- Known PDF risks (plan, week 2): long tables, page breaks, repeated headers
  in WeasyPrint. That is why day 10 is entirely fidelity work; if it slips,
  buffer is consumed and P2 starts anyway on the data.
- Coverage gaps (a tool that could not run, tests that could not execute) are
  reported explicitly — the current manual template already does this; keep it.
