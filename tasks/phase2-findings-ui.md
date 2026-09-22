# Task: Phase 2 — Findings UI

> **Status: DONE — closed 2026-09-22; deliverables in commit `5f13ee1`, the
> phase-close evidence (mutation pass, the E3 walk on the real system) in the
> commit that carries this file. Deadline 2026-09-08, plan days 11–12, passed.
> Survey: `tasks/phase2-survey.md` ("go" by `mmarin`).** Closed together with P3 at
> the ◆ "P2+P3" milestone (2026-09-11, passed).

## Objective
Let the analyst work inside the platform: review every finding with a verdict
and a written justification, and edit the report under automatic version
control. E3's gate becomes usable start to finish in the UI.

## Deliverables
1. **Day 11 — findings viewer + triage** — `frontend/src/screens/findings-screen.tsx`, `backend/app/workflow/triage.py`
   - Mockup anchor: docs/mockups/index.html → "Hallazgos y revisión (E3)".
   - Filters by severity, OWASP category, tool, file; plain-language framing
     ("¿Qué encontramos?" / "¿Cómo corregirlo?").
   - `POST /api/v1/findings/{id}/verdict` — `confirm` or `false_positive`
     with a MANDATORY justification (server-side validated, `analyst` only);
     every verdict recorded in the append-only audit log with actor and
     justification. For SCA findings the verdict also seeds the VEX status
     consumed in P5.
   - Snippets escaped at render (hostile input).
   - i18n keys in BOTH `es.json` and `en.json`.
2. **Day 12 — versioned report editor** — `frontend/src/screens/report-screen.tsx`, `backend/app/reports/versions.py`
   - Mockup anchor: "Reporte (E8)".
   - Editor by section; every save creates a version snapshot; the "Control
     de versiones" table fills itself; export of the current version
     (PDF/DOCX/Markdown from P1's engine).
   - Signing locks a version (`analyst` only); later edits open the next one.
   - Plan-first gate applies (report-integrity surface: signing and
     versioning): `tasks/phase2-survey.md` with `## Verdict` BEFORE the
     versioning edits.
   - Visual executive summary: distribution by severity and by OWASP category
     (bundled charting only — no CDN; both themes; colors through tokens,
     severities legible in dark mode).
3. Tests — `backend/tests/test_triage.py`, `test_report_versions.py`; `frontend/src/screens/*.test.tsx`
   - A `developer` cannot post a verdict (deny by default); a verdict without
     justification is rejected; the E3 gate stays closed while one finding
     has no verdict; a signed version is immutable; a hostile snippet renders
     escaped.

## Constraints
- Hard Rules: gates server-side; audit log for every verdict and every
  sign; no visible string literals; tokens only; both themes.
- Mockup-fidelity audit is a verification gate (`dioptra-mockup-fidelity`).
- Forbidden: UI-only enforcement of the E3 gate; any AI suggestion in triage.

## Definition of Done
- [x] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [x] All specified tests passing (pytest / Vitest)
- [x] Mutation pass on the triage gate module (phase-close): `uv run mutmut run`
      over `app/workflow/triage.py` (with `gates`, `brief`, `test_plan`),
      2026-09-22 — 503/543 killed; every survivor inspected and classified in
      `tasks/phase3-workflow-e1-e5.md`; the meaningful ones became tests
      (audit row fields: actor id, role, ip, target)
- [x] No secrets in diff (Gitleaks clean); locale parity check green
- [x] `/precommit` returned `READY TO COMMIT` (including mockup fidelity)
- [x] `tasks/phase2-survey.md` written and signed off before the report-versioning edits
- [x] E3 walked start to finish on the real MINCYT frontend (2026-09-22, dev
      instance): fifteen findings, eleven confirmed and four discarded with
      justification, the gate opened, sections edited, version 2 signed by
      `mmarin` and exported as PDF / Markdown / DOCX / HTML with the version
      table filled and the false positives absent from every format
- [x] CLAUDE.md phase status + docs/development-phases.md: Phase 2 → DONE with date and commit

## Non-goals (explicit)
- Risk matrix, briefs, pseudocode (P3); test writing and sandbox (P4)
- Inventory panel and VEX authoring UI (P5) — P2 only stores the verdict
- Report sections 7–10 (metrics, test debt, inventory, annexes — P5)
- New dependencies without license + rationale
- Rich-text sections (plain paragraphs only, escaped at render — survey §5)
- Cryptographic (PKI) signatures — signing is an attested, immutable lock

## References
- `CLAUDE.md` → Roles, Hard Rules, Code Conventions
- `docs/ui-model.md`, `docs/mockups/index.html`, `docs/roles-and-permissions.md`, `docs/report-format.md`
- OWASP ASVS 4.0.3 V4.1 (access control), V5.3 (output encoding), V7.1 (audit)
