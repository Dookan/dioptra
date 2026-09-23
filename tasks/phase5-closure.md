# Task: Phase 5 — Cierre (inventory, wave 2, self-audit, release)

> **Status: IN_PROGRESS — started 2026-09-22, the moment P4 closed. Deadline
> ◆ "Release" 2026-09-18 (plan days 18–20), passed.** Tag v1.0.0 when the
> Definition of Done below is met. Day 20 is the buffer. Survey
> `tasks/phase5-survey.md` written and signed off 2026-09-22 (under `mmarin`'s
> "bueno hagamos lo necesario para cerrar"); day 18 BUILT 2026-09-22;
> **PHP/Java cut to a second cycle** (survey §9).

## Objective
Add the software inventory of the factory (SBOM/CBOM/VEX + local CVE
database + statistics), the second language wave, the full audit log and the
report's remaining sections; then harden, self-audit and release v1.0.0 with
the whole P0–P5 roadmap. Under overrun, PHP/Java is cut first; the inventory
is never cut.

## Deliverables
1. **Day 18 — software inventory** — BUILT 2026-09-22: `backend/app/inventory/{models,components,versions,importers,sync,correlation,documents,service,router}.py`, `backend/alembic/versions/0009_inventory.py`, `rules/semgrep/crypto-inventory.yml`, `backend/app/audit/router.py`, `frontend/src/screens/{inventory,audit}-screen.tsx`
   - Plan-first gate applies (new ingestion surface for dump files and a
     scheduled outbound job): `tasks/phase5-survey.md` with `## Verdict`.
   - SBOM per project and version (reusing P1's stored CycloneDX 1.6 — never
     regenerated), CBOM (algorithms, key sizes, protocols, certificates; tool
     decided in the survey among cdxgen CBOM, IBM cbomkit, own Semgrep crypto
     rules), VEX composed from the E3 verdicts on SCA findings.
   - Local vulnerability database: OSV + NVD (CVE.org) mirror in PostgreSQL;
     scheduled RQ sync (outbound only, to the public dump endpoints) OR
     file import for air-gapped deployments, schema-validated with size caps;
     last-update date always visible. **Never a live query.**
   - BOM ↔ CVE correlation by PURL + version range; outdated detection from
     the same mirror.
   - Statistics panel: outdated / vulnerable components, by severity, by
     project, by license, trend between versions. Export CycloneDX JSON
     (SBOM, CBOM, VEX) and CSV (formula-injection safe).
   - Roles: defined in `tasks/phase5-survey.md` and written into
     docs/roles-and-permissions.md before the endpoints exist; every
     inventory mutation (sync, import, VEX) → audit log with justification.
   - Mockup anchor: docs/mockups/index.html → "Inventario" (screen 11).
   - Acceptance (plan): for a real project, SBOM valid against schema 1.6,
     CBOM with at least the detected algorithms, panel showing which
     components have open CVEs and which are out of version.
   - **Decisions recorded** (survey §10): CBOM from our own Semgrep
     crypto-inventory rules (18 rules, positive/negative pairs run in the
     analysis image); OSV as the correlation source and NVD as enrichment
     (CPE does not map onto PURLs); "outdated" = a newer version known to the
     local copy; the sync is RQ's own scheduler with a self-rescheduling job
     under a fixed id; roles as in `docs/roles-and-permissions.md`. The
     audit-log READ (`GET /api/v1/audit`, the Bitácora screen) landed here
     rather than on day 19 because the inventory's audit rows needed a
     screen to be seen in.
2. **Day 19 — wave 2, audit log, report sections** — `backend/app/workflow/ast/{php,java}.py`, `scaffold/{phpunit,junit}.py`, `rules/semgrep/{php,java}-*.yml`, `backend/app/audit/`, `backend/templates/`
   - PHP/Laravel and Java/Spring: detector, AST + brief, PHPUnit / JUnit
     scaffolds, own Semgrep rules, Infection + Pitest in the sandbox.
   - Full audit log: every sensitive action of every phase recorded; audit
     log screen per docs/mockups "Usuarios y bitácora"; read scope per role.
   - Report sections Métricas de código, Deuda de pruebas (coverage before /
     after, tests written, basis paths covered, mutation score), Inventario
     (SBOM summary, open CVEs with VEX status, outdated components), Anexos
     (ASVS checklist, diagrams, pseudocode, test code, SBOM/CBOM attached).
   - **First task cut** if weeks 2–4 overran: the release then ships with
     JS/TS + Python, PHP/Java goes to a second cycle. **CUT APPLIED
     2026-09-22** (survey §9): the PHP/Java detector, AST, scaffolds, rules
     and mutation tools move to a second cycle; the rest of day 19 (audit
     log, report sections) stays.
3. **Day 20 — buffer, hardening, self-audit, release**
   - Buffer for S2–S4 overruns. Hardening review: security headers, rate
     limiting, refresh rotation (largely done in P0 — verify, do not redo).
   - Self-audit: the platform's own repository through its own pipeline
     (E1–E8 on itself); no high finding open without justification.
   - Complete ASVS L2 checklist in docs/standards-mapping.md; final
     docs/threat-model.md (residual risks reviewed; the `DROP TRIGGER`
     residual gets its migration-role / runtime-role split here).
   - Tag `v1.0.0`; README and docs in English; locales with no missing keys.
4. Tests — `backend/tests/test_inventory_*.py`, `test_vulndb_sync.py`, `test_vex.py`, `test_ast_{php,java}.py`, `test_audit_coverage.py`
   - Hostile lockfile names / versions escaped in panel, PDF and CSV; a
     tampered or oversized dump rejected; no request handler performs the
     sync itself (the panel button only enqueues the job); role denial per
     the P5 matrix (deny by default); deterministic PHP/Java briefs with
     hand-counted paths; every sensitive endpoint writes an audit row.

## Constraints
- Hard Rules: No CDNs level 3 (local vulnerability data only); free licenses
  (Syft/cdxgen/Dependency-Track Apache-2.0, cbomkit Apache-2.0, Infection
  BSD-3, Pitest Apache-2.0); Docker Scout REJECTED.
- Phase discipline: nothing from language wave 3 (Go, C#/.NET) or Tauri.
- Forbidden: regenerating the SBOM outside P1's runner; a live CVE lookup;
  allowlist exceptions in the license gate.

## Definition of Done
- [x] `tasks/phase5-survey.md` written and signed off before the inventory edits (2026-09-22)
- [ ] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [ ] All specified tests passing (pytest / Vitest)
- [ ] Mutation pass on correlation, VEX and audit modules (phase-close)
- [ ] No secrets in diff (Gitleaks clean); locale parity check green
- [x] Day 18: `/precommit` returned `READY TO COMMIT` (2026-09-22) after the
      panel's findings were applied and pinned. Security: the self-rescheduling
      sync died after ONE run (a successor under the running job's fixed id is
      deleted with it — reproduced against a real RQ worker; the successor
      now carries the next slot's id), parser exceptions (`zipfile` method /
      encryption / `zlib.error`, `RecursionError`) escaped the jobs instead of
      becoming a row, the NVD reader was bounded on only two of four branches,
      a broker-chosen `requested_by` reached the audit trail, a broker outage
      at import left the spool file behind with a bare 500, an NVD record
      could wipe an OSV row's packages, and the dump cap exceeded nginx's body
      cap. Invariants: `docs/analysis-pipeline.md` and `docs/workflow-gates.md`
      still described the pre-cut rules. Fidelity: `.panel ul` beat the CBOM
      list, the reason form touched the cards, named-interpolation plurals,
      a "CVSS" literal, "(worker)" jargon, `system` shown raw, a gendered
      subtitle. Coverage adversary: 77 mutants, 25 survivors, the twelve
      worth a test written (`csv_cell` per prefix, the queue allowlist, a
      verdict never borrowed across packages, the panel button forcing a
      fresh mirror, `download`'s cap and non-200 path, the OSV/NVD enrich
      rule, OSV fallbacks, an empty feed refused, `by_severity` whole,
      hostile justification in the screen, the role test never phoning home,
      `first_fix_after` boundary)
- [ ] Days 19–20: `/precommit` returned `READY TO COMMIT` (including mockup fidelity)
- [ ] Day-18 acceptance met on a real project (SBOM 1.6-valid, CBOM, panel)
- [ ] A real project walks E1–E8; sandbox escape tests negative
- [ ] Self-audit executed: no high finding open without justification
- [ ] ASVS L2 checklist complete in docs/standards-mapping.md; final threat model
- [ ] `v1.0.0` tagged on 2026-09-18; CLAUDE.md phase status +
      docs/development-phases.md: Phase 5 → DONE with date and commit

## Non-goals (explicit)
- Language wave 3 (Go, C#/.NET) and Tauri offline packaging — out of scope
  for v1.0.0 by design, not by overrun
- Dependency-Track deployment (accepted alternative, not the default)
- Any external vulnerability service at runtime

## Contingencies
- Two consecutive milestones missed → PHP/Java to a second cycle; the
  inventory stays.
- No internet → dump import by file; last-update date visible.
- Positive sandbox escape → no release (P4 rule still binds here).

## References
- `CLAUDE.md` → Hard Rules (No CDNs level 3), Analysis Tool Source Authority, Release rules
- `docs/software-inventory.md`, `docs/threat-model.md` → SBOM generation / Inventory rendering / Vulnerability DB sync / VEX
- `docs/report-format.md` → sections 7–10; `docs/roles-and-permissions.md` → inventory rows
- OWASP CycloneDX 1.6 (SBOM, CBOM, VEX); OWASP ASVS 4.0.3 V14.2; OSV schema; NVD CVE JSON 2.0
