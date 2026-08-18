# Mockups

`index.html` is the approved design contract (2026-08-17) — the 10 screens of
the full flow, self-contained (open directly in a browser; no external
resources, per the no-CDN rule). It renders both themes via `prefers-color-scheme`
and the `data-theme` attribute.

How to use it during implementation:

- Each `<section class="shot">` is one screen; the `<style>` block at the top
  holds the token values that must land in `frontend/src/theme/tokens.css`
  (they are also transcribed in docs/ui-model.md — keep both in sync).
- The markup is mockup-grade, not production code: reuse the class structure
  and values as reference, re-implement as React components with i18n keys.
- `dioptra-mockup-fidelity` audits implementations against THIS file — if a design
  decision changes, change it here first, then implement.
