# Task: Phase 1 — Audit MVP

> **Status: DONE — closed 2026-09-24; the closing commit's hash is recorded
> here and in CLAUDE.md by a follow-up commit, as phase 8 did (`39eac51`). Started
> 2026-09-21, seventeen days past the ◆ "P1 (PDF)" deadline of 2026-09-04 (plan
> days 6–10, critical path); the deliverables were built on 2026-09-21 and have
> carried every later phase since. What kept it open was its own phase-close
> evidence — the mutation pass and the day-10 comparison — which is recorded
> below. Survey: `tasks/phase1-survey.md` (signed off "go" by `mmarin`,
> 2026-09-21).**

## Objective
Replicate the current manual audit process end to end: a real repository goes
in, the institutional PDF comes out. Success criterion (the most concrete of
the plan): the existing institutional backend report (MINCYT API system) is
reproduced automatically, indistinguishable in structure, compared section by
section. See docs/development-phases.md → Day table, days 6–10.

## Deliverables
1. **Day 6 — data model + ingest** — `backend/app/ingest/`, `backend/alembic/versions/0002_*.py`
   - Tables: `projects`, `systems` (E1 metadata: name, framework, DB,
     developer, install date), `analyses`, `findings`, `sboms`, `raw_tool_outputs`.
   - `POST /api/v1/projects/{id}/ingest` accepting a ZIP upload or a git URL
     (E2); language / framework / lockfile detection; typed errors
     `IngestError` → `ZipSlipDetected`, `ZipTooLarge`, `TooManyEntries`,
     `RepoUnreachable`, `ForbiddenHost`; jailed extraction per project.
   - RQ queueing on Valkey with a `worker` service added to
     `docker/docker-compose.yml` (deferred from P0); analysis status
     queryable by API (`GET /api/v1/analyses/{id}`).
   - Plan-first gate applies (ingest surface): `tasks/phase1-survey.md` with
     `## Verdict` BEFORE edits.
2. **Day 7 — runners + SBOM** — `backend/app/analysis/runners/`, `docker/analysis-*.Dockerfile`, `rules/semgrep/`
   - Ephemeral containers: Semgrep CE with the initial own rules (including
     the no-CDN rule → CWE-829 / A08:2021, each rule with `metadata.{cwe,owasp}`
     and a positive/negative test pair), Gitleaks (tree + history + CI
     configs), OSV-Scanner in offline mode against a local OSV database
     directory seeded from the OSV dump file (no mirror table before P5).
   - SBOM CycloneDX 1.6 JSON per ingested version via Syft or cdxgen from
     lockfiles + dependency tree — metadata only, no package scripts, no
     network; structurally validated before persistence (own check of
     bomFormat / specVersion 1.6 / component shape with caps — no JSON Schema
     dependency, see `tasks/phase1-survey.md` §3).
   - Every runner container with `--network none` and tools in offline mode
     (Semgrep `--metrics=off`, OSV-Scanner offline, mounted local data).
   - Per-tool timeout and CPU/RAM limits; raw output persisted; a tool that
     fails to run is recorded as a coverage gap, never silently skipped.
3. **Day 8 — normalizer + metrics** — `backend/app/analysis/normalizer.py`, `backend/app/analysis/cwe_owasp.py`
   - SARIF → `Finding {rule, cwe, owasp, cvss, severity, path, line, snippet,
     mitigation, references}`; CWE → OWASP Top 10:2021 map; CVSS 3.1 computed;
     dedupe across tools; **unknown CWE is a valid state** (`cwe = null`,
     bucket "unclassified"), never an exception.
   - Lizard (cyclomatic complexity per function) + cloc persisted for the
     E4 risk matrix.
4. **Day 9 — report engine** — `backend/app/reports/`, `backend/templates/`
   - Jinja2 → HTML → WeasyPrint with the full institutional template: cover,
     Introducción, Resumen ejecutivo, Detalles del sistema, Control de
     versiones, Hallazgos. Snippets escaped at render; WeasyPrint receives
     sanitized HTML only.
   - Markdown export and basic DOCX export (python-docx, MIT — license +
     rationale comment in `pyproject.toml`). First PDF with real data.
5. **Day 10 — PDF fidelity** — full day against the anchor backend report,
   section by section; differences fixed in the template, not in the data.
6. Tests — `backend/tests/test_ingest*.py`, `test_runners*.py`, `test_normalizer*.py`, `test_reports*.py`
   - Hostile-input cases: zip-slip entry, decompression bomb, entry-count
     bomb, git URL to a private range / non-allowlisted scheme, lockfile with
     a `postinstall` script (must never execute), SARIF without CWE, snippet
     containing `<script>` rendered into HTML/PDF.
   - Normalizer fixtures from the MINCYT-form systems.

## Constraints
- Hard Rules (CLAUDE.md): audited code is hostile; no CDN; free licenses only
  (Syft/cdxgen Apache-2.0, python-docx MIT, WeasyPrint BSD-3); English-only
  code; SBOM generated once and shared with the inventory (P5).
- No public Semgrep registry rules (restrictive license) — own rules only.
- The vulnerability data used by OSV-Scanner is a local mirror; no live query.
- Forbidden: executing anything from the audited tree outside a sandbox;
  installing its dependencies for analysis (lockfile parsing only).

## Definition of Done
- [x] All deliverables implemented; ruff + mypy + oxlint + tsc clean —
      `scripts/ci.sh` on 2026-09-24: every stage green (ruff, `mypy app tests`,
      oxlint, `tsc -b`, the production build, the licence gate on the host and
      inside both sandbox images, no-CDN)
- [x] All specified tests passing (pytest / Vitest), hostile-input cases
      included — 900 non-sandbox backend tests (929 collected with the `sandbox`-marked ones; 837 before this diff) and 122 frontend tests; zip-slip, the three bomb
      shapes, private / loopback / link-local git targets, `<script>` in a
      snippet and a SARIF without CWE are all in the suite
- [x] Mutation pass on the normalizer and the ingest guards (phase-close) —
      mutmut 3.8, 2026-09-24, `app/analysis/normalizer.py`,
      `app/ingest/archive.py`, `app/ingest/git_source.py` (the two ingest
      modules joined the target list here; the normalizer's FIRST measurement
      was phase 7a's). **Normalizer 701 → 1 111 killed of 1 185 (59 % → 94 %);
      `archive.py` 68 → 111 of 150; `git_source.py` 29 → 123 of 156**, and no
      mutant of the three is left without a covering test. What the pass found,
      and what was written because of it:
      **(a)** `git_source.shallow_clone` had NO test at all, so the clone's
      argv — `http.followRedirects=false`, `protocol.allow=never`,
      `credential.helper=`, `core.symlinks=false` — its empty environment and its
      cleanup on failure or timeout were a documented control nothing pinned;
      and nothing proved a PUBLIC address is accepted (removing the `not` from
      `_is_public` survived), nor that a username alone is refused as a
      credential, nor `.local` without DNS. **(b)** `archive.py`: no FIFO or
      device entry, no NUL in a name, no cap at exactly its own value, no
      check of the jail's `0700` / the files' `0600`, no refusal of an already
      existing jail, and the report's counts never asserted. **(c)** The
      normalizer's cross-tool dedupe (`_merge`) was never checked field by
      field — a merge that dropped the second tool's snippet, message, vector
      or OWASP code passed — and most field SOURCES (result properties, rule
      properties, rule metadata, tags, prose) were only exercised together, so
      dropping one survived; the per-field caps, the category routing when the
      tool name differs, the OSV prose fallbacks and the crypto scan's skips
      and cap had no test. All in `tests/test_{ingest_archive,ingest_git,normalizer,inventory_crypto}.py`.
      **What survives, all inspected** (74 + 39 + 33): the log-only `detail`
      text of typed errors (the client sees `{code, message_key}`); `[:n]`→
      `[:n+1]` cap off-by-ones and `_text(x, None)` on fields bounded again
      downstream (a title, a level mapped to an enum); `PurePosixPath` already
      refusing what `name.startswith("/")` and the empty-part check re-test;
      `is_global` already excluding every range `_is_public` also lists;
      `rmtree(ignore_errors=…)`, which only matters when the removal itself
      fails; `member.read(None)`, which changes memory, not output; `_merge`'s
      CWE fallback, unreachable because the fingerprint already contains the
      CWE; and `rsplit(".", 1)` against `rsplit(".")`, same last segment.
      The streamed-byte guard of `archive.py` stays unreachable on Python 3.13
      (`zipfile` truncates a member at its declared size), as its test already
      said. Two test files were kept out of the selection because they fail
      under mutmut's copied tree for layout reasons, not behaviour:
      `test_runners.py` and one end-to-end case of `test_inventory_crypto.py`
- [x] No secrets in diff (Gitleaks clean); locale parity check green —
      `gitleaks git` clean on the history; `gitleaks dir` reports only the
      sandbox test's canary INSIDE `backend/mutants/`, mutmut's gitignored copy
      that a CI checkout never has (already recorded 2026-09-24); parity is in
      the green Vitest run
- [ ] `/precommit` returned `READY TO COMMIT` on this closing diff
- [x] `tasks/phase1-survey.md` written and signed off before the ingest edits
      ("go", `mmarin`, 2026-09-21)
- [x] The anchor report is reproduced and the PDF is indistinguishable in
      STRUCTURE, section by section (day 10) — **with a recorded deviation on
      which anchor**. The MINCYT **backend** source is not on this machine (only
      its PDF and the old generator's `findings.json`), so the comparison was
      run on the **frontend** anchor, whose source is: the real
      `formulario_mincyt_front-desarrollo` tree through the Docker pipeline
      (six tools ran, 15 findings), rendered to PDF on 2026-09-24 and compared
      heading by heading with BOTH anchor PDFs, which share one template.
      Cover, Introducción, Resumen ejecutivo, Detalles del sistema, Control de
      versiones, Hallazgos de vulnerabilidades (per finding: Descripción
      General / Impacto / Detección / Mitigación / Referencias), Hallazgos sobre
      paquetes y dependencias and Cobertura de herramientas appear in the
      anchor's order; sections 7–10 follow by design (P5). **One anchor section
      needed a decision**: "Errores y prácticas no adecuadas en el código",
      absent from our first render. The anchor lists ten files there, and read one by one they hold
      mostly PROSE shaped like code ("Vista Pública o Especial (Sin Layout
      Administrativo)"), which its generator counted. **`mmarin`, 2026-09-24:
      the section must list the commented code the way the anchor does; the
      rest of the comparison does not matter.** So the scan took the anchor
      generator's breadth — a comment shaped like a call, an assignment, a
      keyword or a statement ending counts; tool directives (`TODO`, `eslint`,
      `noqa`…) never do; two such lines list a file — and it also reads
      `/* … */` and `<!-- … -->` blocks and `.vue` / `.css` / `.scss` /
      `.html` files, which it never did (`app/analysis/metrics.py`,
      `tests/test_metrics.py`). Re-run on the same tree and rendered: the
      section is present in the anchor's place and lists **9 of the anchor's
      10 files**. The tenth, `src/assets/css/styles.css`, came from the old
      generator reading CSS id selectors (`#nav-username {`) as `#` comments —
      live rules, not comments — and that defect is not reproduced. Pixel-level
      fidelity stays the open item it has been since the 2026-09-21 cut. The
      backend anchor is not reproduced from its source (not on this machine);
      `mmarin` accepted the frontend comparison
- [x] The SBOM passes the CycloneDX 1.6 structural validation
      (`app/analysis/sbom.py`) — validated at ingest on every run since P1;
      342 components on the 2026-09-24 self-audit
- [ ] CLAUDE.md phase status + docs/development-phases.md: Phase 1 → DONE with date and commit — date and status written; the commit hash lands in the follow-up commit

## Non-goals (explicit)
- Findings UI, triage, report editor (P2)
- Workflow stages E4–E7 (P3–P4)
- CBOM, VEX, BOM ↔ CVE correlation panel, scheduled vulnerability sync (P5 —
  P1 only stores the SBOM and ships the OSV dump directory the offline
  runner needs)
- PHP/Java support (P5); Go, C#/.NET (out of scope for v1.0.0)
- Tools outside CLAUDE.md → Analysis Tool Source Authority

## Contingency
- PDF fidelity not reached on 2026-09-04 → consume week-4 buffer; P2 starts
  anyway on the data (docs/development-phases.md → Contingencies).

## References
- `CLAUDE.md` → Hard Rules, Analysis Tool Source Authority, Release rules
- `docs/analysis-pipeline.md`, `docs/report-format.md`, `docs/threat-model.md` (rows ZIP ingest, git URL ingest, SBOM generation)
- `docs/software-inventory.md` → Documents (SBOM contract)
- OWASP ASVS 4.0.3 V5.3 (output encoding), V12.1 (file upload); CWE-829; CycloneDX 1.6
