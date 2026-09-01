# Mockups

`index.html` is the design contract — the 10 screens of the full flow approved
2026-08-17, plus the additions of 2026-08-28 for the work plan v1.0: screen 11
"Inventario" (SBOM/CBOM, open CVEs, local vulnerability-database date, exports),
the "Inventario" tab on every screen, the editable Mermaid text on "Diseño de
casos (E5)", and the "Inventario" / "Anexos (diagramas, tests, SBOM/CBOM)" sections on "Reporte
(E8)". Self-contained (open directly in a browser; no external resources, per
the no-CDN rule). It renders both themes via `prefers-color-scheme` and the
`data-theme` attribute.

How to use it during implementation:

- Each `<section class="shot">` is one screen; the `<style>` block at the top
  holds the token values that must land in `frontend/src/theme/tokens.css`
  (they are also transcribed in docs/ui-model.md — keep both in sync).
- The markup is mockup-grade, not production code: reuse the class structure
  and values as reference, re-implement as React components with i18n keys.
- `dioptra-mockup-fidelity` audits implementations against THIS file — if a design
  decision changes, change it here first, then implement.
