# Report format

> **Status: DESIGN SURFACE — not yet implemented.** Anchor: the manual MINCYT
> reports in `/home/user/Desktop/UTD/CAJA-BLANCA/*.pdf` (structure is
> authoritative; the platform must reproduce it indistinguishably).

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
9. **New:** Anexos — ASVS checklist, flow diagrams, pseudocode, test code
10. Footer authorship: **Moises Marin**

## Behavior

- The report composes itself from workflow data; every section is editable in
  the platform BEFORE export (rich text), with versioned snapshots.
- Signing locks a version; later edits create the next version and the
  "Control de versiones" table updates automatically.
- Exports: PDF (Jinja2 → HTML → WeasyPrint, template identical to the manual
  one), DOCX, Markdown. Report language follows the UI language (es default).
- Coverage gaps (a tool that could not run, tests that could not execute) are
  reported explicitly — the current manual template already does this; keep it.
