# Task: Phase 1 — Audit MVP

> **Status: IN_PROGRESS — started 2026-09-21, seventeen days past the ◆ "P1 (PDF)"
> deadline of 2026-09-04 (plan days 6–10, critical path). Survey:
> `tasks/phase1-survey.md` (signed off "go" by `mmarin`, 2026-09-21).**

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
- [ ] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [ ] All specified tests passing (pytest / Vitest), hostile-input cases included
- [ ] Mutation pass on the normalizer and the ingest guards (phase-close)
- [ ] No secrets in diff (Gitleaks clean); locale parity check green
- [ ] `/precommit` returned `READY TO COMMIT`
- [ ] `tasks/phase1-survey.md` written and signed off before the ingest edits
- [ ] The anchor backend report is reproduced from the real repository and the
      PDF is indistinguishable in structure, section by section (day 10)
- [ ] The SBOM passes the CycloneDX 1.6 structural validation (`app/analysis/sbom.py`)
- [ ] CLAUDE.md phase status + docs/development-phases.md: Phase 1 → DONE with date and commit

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
