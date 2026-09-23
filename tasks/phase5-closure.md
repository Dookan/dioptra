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
2. **Day 19 — wave 2, audit log, report sections** — BUILT 2026-09-22 (wave 2 CUT): `backend/app/reports/{closure,svg}.py`, `backend/templates/report/{report.html.j2,report.md.j2,strings.json,report.css}`, `backend/app/reports/engine.py` (DOCX), `backend/tests/test_report_closure.py`; the audit-log read landed on day 18
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
3. **Day 20 — buffer, hardening, self-audit, release** — BUILT 2026-09-22: `docker/initdb/01-runtime-role.sql` + `DIOPTRA_MIGRATION_DATABASE_URL` (owner/runtime role split, proven in CI and on the dev PostgreSQL), the ASVS L2 chapter checklist in `docs/standards-mapping.md`, the final `docs/threat-model.md`, `scripts/self_audit.py`, `scripts/dev.sh`, and — from the walk of the platform on itself — the E7 → E5 loop fix (`design._require_design_stage` accepts a reopened function at E7; a PASSED run clears the flag) and the **equivalent-mutant verdict** (`verify.mark_equivalent`, `POST …/mutants/equivalent`, migration `0010_equivalent_mutants`, the sandbox wrapper ships each survivor's diff, the verification screen's "Marcar como equivalente", the report's test-debt count)
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
- [x] Mutation pass on correlation, VEX and audit modules (phase-close): mutmut 3.8 over the P3/P4 targets plus `inventory/{correlation,versions,importers,documents,sync}.py` and `audit/router.py`, 2026-09-22 — 3 300 mutants, 2 739 killed (83 %), 23 without a covering test, 1 timeout, 537 survivors in the FIRST pass. 100 of them are P3/P4's, already classified in `tasks/phase{3,4}-*.md`. The 437 inventory/audit survivors were dumped with their diffs and read by function: **(a)** the largest groups are field-by-field shaping of a record or a document — `shape_nvd` 42, `vex_document` 30, `_packages` 26, `shape_osv` 22, `cbom_document` 22, `_header` 19 — where a mutant swaps a key's default, a `continue` for a `break` on a one-element fixture, or a string for its `XX…XX` twin; the behavioural ones became three field-by-field tests (`test_inventory_documents.py::test_the_documents_headers_are_deterministic_and_complete`, `…cbom_components_carry_every_field…`, `…vex_entries_carry_state_ratings_references…`, `test_inventory_import.py::test_shaping_reads_every_field…`) and the rest are the same equivalent classes P3 and P4 recorded (log-only `detail` strings, `[:n]`→`[:n+1]` caps, `or True` guards, codec-name case); **(b)** `_index_findings` 25 and `_verdict_for` 7 — the reference-derived ids and the case-insensitive package match had no fixture, now `test_inventory_api.py::test_verdicts_match_case_insensitively_and_through_references`; **(c)** `correlate` 11 — `continue`→`break` on single-component fixtures, now `…test_every_component_is_correlated_not_only_the_first`; **(d)** `versions.parse` 14 — one real edge (`parse("v")` raised instead of returning `None`), pinned with `"v"`, `"V"`, `"1:"`, `"+1"`; the rest are the `>`/`>=` boundaries of the same guard; **(e)** `sync.download` 23 and `_run_sync`/`run_import_job`/`_sync_one` ≈ 60 — the download's byte-cap and status paths are pinned by `test_inventory_documents.py` (fake opener), the remaining survivors are the log-only `detail` strings of `vulndb_syncs` rows and the URL templates, whose only observable is the row the tests already assert. The targeted tests were added after the pass; a second full pass was not run (≈ 1 h) and this is recorded rather than claimed
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
- [x] Days 19–20: `/precommit` returned `READY TO COMMIT` (2026-09-22) after
      the panel's findings were applied. Security: the sandbox wrapper ran
      `mutmut show` once per survivor unbounded (a 40-survivor first run would
      time out and strand E7 in its normal first state — now 15 survivors or
      30 s, the rest keep id + line); an excused mutant was matched by id
      alone, which an image rebuild can renumber (now id AND text); the
      owner's database URL lived in the long-running API process (now a
      one-shot `migrate` service, and the residual row names the remaining
      scope); the initdb `\set` used `echo`, which mangles backslashes
      (`printf`); `self_audit.py` accepted a developer as actor (role check).
      QA: `ruff format` red on `alembic/env.py`; every other claim GENUINE by
      execution (migration 0010 up/down/check, the role split against a real
      PostgreSQL in both deployment orders, the report on the self-audit and
      the MINCYT analyses, the endpoint). Invariants: sections 7–10 are
      composed live and sit OUTSIDE the signed content (recorded in
      `docs/report-format.md`); the annex SVG carried English `Start`/`true`
      tokens into a Spanish report (now `strings.json` → `diagram`). Fidelity:
      the excusal form inherited the mutant line's mono 12px (form moved out of
      the span), a refusal discarded the typed reason (`act` now answers
      true/false), the button ignored `busy`. Coverage adversary: 63 mutants,
      35 killed, 28 survivors — all mechanical, all written as tests
      (`test_report_closure.py`: the `ccn > 10` boundary and cloc's `header`
      row, the excused count, the detached SBOM-only path, the annex cap,
      `stage_of`'s fallback, the security-only ASVS count, SVG clipping and
      the `sí` token and `Inicio` before `Fin`, control characters from the
      rationale / paths / snippet / test file in the DOCX, the rationale,
      Mermaid and test code present in `document.xml`, the HTML `Sí`/`No`
      cells, the Mermaid `<pre>` and "Ítems sin cubrir", Markdown `\|` `\*`
      escaping and the four-backtick fence; `test_verify.py`: diagram text at
      E7 only once reopened, a FAILED run keeps the flag, another function's
      excusal never reaches this one, the mark refused at E8 and before E7,
      a never-verified function is 404; the screen: a refusal keeps the form
      and the reason, the excused list shows "línea 12 · …"). Two survivors
      have no unit test on purpose: the `alembic/env.py` URL precedence is
      proven by QA against a real database, not by pytest, and the wrapper's
      `show` budget lives in shell inside the image (`run-python.sh`), covered
      by the live sandbox suite only
- [x] Day-18 acceptance met on a real project: the platform's own tree (`dioptra-self-audit-20260922-e2238c6`, 342 SBOM components validated 1.6 at ingest, the CBOM rows from the crypto-inventory rules, the panel listing the five open CVEs of the sandbox and frontend lockfiles and the outdated components against the npm mirror)
- [x] A real project walks E1–E8 (2026-09-22, dev instance, the self-audit
      analysis of Dioptra's own tree): E1 the project `dioptra-self-audit-…`,
      E2 the archive through the pipeline (six tools RAN, 342 SBOM
      components), E3 the 94 verdicts with a written reason each, E4 a plan
      of one pure function (`scaffold/text.py::slug`, criterion decisions,
      rationale in the developer's words), E5 four cases covering R1 and R2
      and approved, E6 a hand-written test file over the scaffold (the
      platform wrote no assertion), E7 THREE sandbox runs: the first
      rejected (two hand-written assertions were wrong), the E7 → E5 loop
      reopened the function — which exposed and fixed the `stage_locked`
      defect on re-approval — the second run green at 100 % statements and
      branches with six survivors, all six judged equivalent with a written
      reason each (codec-name case, `ensure_ascii=None`, a dead `strip`),
      and the third run PASSED with zero survivors and the six excused ones
      recorded on the run; E8 version 1 signed by `mmarin` and exported as
      PDF, HTML and Markdown with sections 7–10 and the annexes (the flow
      diagram as inline SVG, the six equivalents in the test-debt totals).
      Every step is in the audit log. **Recorded limit**: the MINCYT frontend
      cannot reach E8 in v1.0.0 — every one of its modules imports project
      dependencies, which the sandbox never installs (the P4 non-goal); it
      reached E6 in P4 and stays there. Sandbox escape tests re-run against
      the image rebuilt on day 20 (the wrapper now ships each survivor's
      diff): `pytest -m sandbox` → 16 passed, every probe negative and
      attributable as recorded in `docs/threat-model.md`
- [x] Self-audit executed 2026-09-22 (`scripts/self_audit.py`, tree at `e2238c6`, every tool RAN): 94 findings — 3 high, 5 medium, 86 info. The three highs are `hardcoded-secret-assignment` on our own rule fixtures (`rules/semgrep/tests/hardcoded-secrets/positive.*`) and on the sandbox test's exfiltration canary: discarded with a written justification each. The 86 infos are the rule fixtures (`positive.*` files exist to make the rules fire), the suite's fixed test secrets, three `RegExp` in a frontend test and three `Markup(...)` calls in `reports/engine.py` that wrap already-escaped values — all discarded with a justification. The 5 mediums are real: CVE-2026-82417 / 82562 / 8723 on `qs` 6.15.1 in the sandbox image's lockfile and CVE-2026-84373 on `vitest` / `@vitest/mocker` 4.1.10 in the frontend's — confirmed as dependency debt for 1.x with the justification that neither is served to a user (dev and sandbox trees), and carried in the inventory with their VEX state. **No high finding is open.**
- [x] ASVS L2 checklist complete in docs/standards-mapping.md (chapter table V1–V14, 2026-09-22); final threat model (every row built, the `DROP TRIGGER` residual resolved by the role split with its remaining scope named)
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
