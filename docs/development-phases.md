# Development phases

> **Status: P0 DONE (2026-08-18); P1 IN_PROGRESS since 2026-09-21; P2 DONE (2026-09-22, `5f13ee1`); P3 DONE (2026-09-22, `80c0a3f`, closed in `37cd6cc`); P4 DONE (2026-09-22, `576993f`, `2b9680d`); P5 DONE (2026-09-23, `280ec5b`, `b801f70`; tagged v1.0.0 on the closing commit) — inventory, report sections 7–10, role split, self-audit, the E1–E8 walk on the platform itself; PHP/Java cut to a second cycle.** Phase status summary
> also lives in CLAUDE.md → Current phase status; keep both in sync.
>
> This file distills the work plan (`docs/work-plan-reference.html`, v1.0,
> 2026-08-21): 20 business days, 2026-08-24 → 2026-09-18, one engineer at full
> dedication, release **v1.0.0** with the whole P0–P5 roadmap. The HTML is the
> reference; this Markdown is what agents read. When the two disagree, fix this
> file and record it in the scope-change log below.

Phases replace sprints. A phase closes ONLY when its Definition of Done in the
corresponding `tasks/phaseN-*.md` is fully checked, its tests pass, its docs
are updated and the task file is at DONE with a commit hash. A Friday milestone
that does not close is Monday's first item.

**We run ahead of the plan on purpose.** The plan's dates are deadlines, not
start dates: a phase starts the moment the previous one closes, however early
that is. The deadlines and milestones are never moved — being early is the
margin; the buffer is the second margin. P0 closed on 2026-08-18 against a
2026-08-28 deadline; P1 starts now.

## Phases

| Phase | Delivers | Closes when |
|---|---|---|
| P0 Foundations | Repo scaffold, Docker Compose, FastAPI + React skeletons, auth (Argon2id + JWT + roles), i18n es/en, themes, CI (ruff, mypy, oxlint, tsc, license gate, no-CDN, Gitleaks, locale parity, dependency currency) | login works end-to-end for the three roles; CI green; the license gate demonstrably fails on a planted non-free dependency |
| P1 Audit MVP | Data model, ZIP/git ingest with language/framework/lockfile detection, RQ jobs; Semgrep (own rules) + Gitleaks + OSV runners in ephemeral containers **+ SBOM CycloneDX 1.6 per project**; SARIF normalizer (CWE → OWASP, CVSS 3.1, dedupe, unknown CWE as a valid state); Lizard + cloc; Jinja2 → HTML → WeasyPrint report, Markdown and basic DOCX export | the institutional backend report (MINCYT API system) is reproduced automatically, indistinguishable in structure, compared section by section |
| P2 Findings UI | Findings viewer (filters by severity, OWASP, tool, file), triage confirm / false-positive with mandatory justification, everything to the audit log; versioned report editor by section, visual executive summary (severity × OWASP distribution) | E3 gate usable start-to-finish in the UI; the current report version exports |
| P3 Workflow E1–E5 | E4 risk matrix (complexity × findings × criticality), coverage criterion per module with written rationale, server-side gates; E5 AST → Mermaid flow diagrams (JS/TS, Python); test briefs (basis paths, branches with line, boundary values, error paths, malicious cases from SAST findings); pseudocode editor with approval | gates rejected when skipped through the API directly, without UI; briefs for at least three real functions whose basis paths, counted by hand, match |
| P4 E6–E7 | Sandbox investigation gate (survey + pseudocode + verdict, no exceptions); deterministic scaffolding from AST + approved pseudocode (Jest/Vitest, pytest); sandbox (no network, CPU/RAM limits, read-only FS except workspace); statement + branch coverage vs. the E4 criterion, branch by branch; rules for assertion-less/trivial tests; mutation testing (Stryker, mutmut); the E7 → E5 loop | a surviving mutant demonstrably rejects the gate; sandbox escape tests pass and are documented in docs/threat-model.md |
| P5 Cierre | **Software inventory** (SBOM/CBOM/VEX per project and version, local OSV + NVD database, BOM ↔ CVE correlation, statistics panel, CycloneDX JSON + CSV export); PHP/Laravel + Java/Spring (detector, PHPUnit/JUnit scaffolds, own Semgrep rules, Infection + Pitest); full audit log; report sections "test debt" and "inventory", annexes (ASVS, diagrams, pseudocode, test code, SBOM/CBOM); buffer, hardening, self-audit, complete ASVS L2 checklist, final threat model; tag v1.0.0 | a real project walks E1–E8; the sandbox passes its escape tests; no high finding open without justification; docs in English; locales without missing keys |

## Day table (plan v1.0)

One task per business day, 8 h. Dates are the plan's deadlines for each task —
the actual work runs earlier. ◆ closes a weekly milestone. **crit** = on the
critical path. **gate** = the plan-first investigation gate applies before any
edit (CLAUDE.md → Agent Behavioral Rules).

| Day | Deadline | Phase | Task | Success criterion of the day |
|---|---|---|---|---|
| 1 | 2026-08-24 | P0 | Repo, docs/, tasks/ template, Conventional Commits hooks | `tasks/phase0-*.md` opens IN_PROGRESS |
| 2 | 2026-08-25 | P0 | Docker Compose (API, frontend, Postgres, Valkey, RQ worker) + FastAPI/SQLAlchemy/Alembic and React 19/Vite skeletons | `docker compose up` brings everything up, health checks green |
| 3 | 2026-08-26 | P0 | Auth (**gate**): Argon2id, short-lived JWT + refresh, lockout, roles admin/analyst/developer, minimal audit log; `standards-mapping.md` starts | — |
| 4 | 2026-08-27 | P0 | i18n es/en + light/dark theme with tokens; severities legible in both themes | — |
| 5 | 2026-08-28 | P0 ◆ | CI: lint, tests, license allowlist (Apache-2.0, MIT, BSD, MPL, LGPL, GPL), outdated-dependency detection, no-CDN check; documented negative test of the license gate | `tasks/phase0-*.md` at DONE with date and commit — **closed 2026-08-18** |
| 6 | 2026-08-31 | P1 | Data model (projects, systems with E1 metadata, analyses, findings) + ZIP/git ingest (E2) with language/framework/lockfile detection; RQ queueing, status queryable by API | — |
| 7 | 2026-09-01 | P1 | Runners in ephemeral containers: Semgrep CE with initial own rules (incl. CDN → CWE-829 / A08:2021), Gitleaks, OSV-Scanner; **SBOM CycloneDX 1.6** (Syft / cdxgen) from lockfiles + dependency tree; per-tool timeout and resource limits; raw output persisted | — |
| 8 | 2026-09-02 | P1 | SARIF normalization: CWE → OWASP Top 10:2021, CVSS 3.1, dedupe; Lizard + cloc; every finding with path:line, snippet, CWE, OWASP, CVSS, suggested mitigation; "unknown CWE" is a valid state | — |
| 9 | 2026-09-03 | P1 | Report Jinja2 → HTML → WeasyPrint with the full institutional template (cover, introduction, executive summary, system details, version control, findings); Markdown + basic DOCX export; first PDF with real data | — |
| 10 | 2026-09-04 | P1 ◆ **crit** | Full day of PDF fidelity against the existing institutional backend report, section by section | structure indistinguishable from the manual report — P1 success criterion |
| 11 | 2026-09-07 | P2 | Findings viewer + triage: filters by severity, OWASP, tool, file; confirm / false positive with mandatory justification; everything to the audit log | — |
| 12 | 2026-09-08 | P2 | Versioned report editor by section, automatic document version control, export of the current version; visual executive summary | — |
| 13 | 2026-09-09 | P3 | E4 risk matrix (complexity × findings × criticality); coverage criterion per module, justified in writing; server-side gates | proven by trying to skip the gates through the API directly, without UI |
| 14 | 2026-09-10 | P3 | E5 AST parsing of prioritized functions (JS/TS, Python) → deterministic, editable Mermaid flow diagrams | — |
| 15 | 2026-09-11 | P3 ◆ **crit** | E5 test brief: signature, basis paths (McCabe), branches with line, boundary values from comparisons, error paths, malicious cases tied to SAST findings; pseudocode editor with approval | briefs for at least three real functions with hand-counted, matching basis paths |
| 16 | 2026-09-14 | P4 **crit gate** | Sandbox investigation gate (survey, pseudocode, verdict) — no exception. Then E6: deterministic scaffolds from AST + approved pseudocode (Jest/Vitest, pytest): file, imports, case names only | — |
| 17 | 2026-09-15 | P4 **crit** | E7: Docker without network, CPU/RAM limits, read-only FS except workspace; statement + branch coverage vs. the E4 criterion, branch by branch; assertion-less/trivial test rules; mutation testing (Stryker, mutmut); E7 → E5 loop when coverage falls short | sandbox escape tests, documented in `threat-model.md` |
| 18 | 2026-09-16 | P5 | **Software inventory**: SBOM per project and version, CBOM (algorithms, key sizes, protocols, certificates), VEX; local vulnerability database synced periodically from OSV + NVD (CVE.org), no live queries; BOM ↔ CVE correlation; statistics panel (outdated, vulnerable, by severity, by project, by license, trend between versions); CycloneDX JSON + CSV export | for a real project: SBOM valid against schema 1.6, CBOM with at least the detected algorithms, panel showing which components have open CVEs and which are out of version |
| 19 | 2026-09-17 | P5 | PHP/Laravel + Java/Spring (detector, PHPUnit/JUnit scaffolds, own Semgrep rules), Infection + Pitest; full audit log; report sections "test debt" and "inventory (BOM + open CVEs)", annexes (ASVS, diagrams, pseudocode, test code, SBOM/CBOM attached) | first task cut if S2–S4 overran |
| 20 | 2026-09-18 | Buffer ◆ | Buffer for S2–S4 overruns; hardening (security headers, rate limiting, refresh rotation — largely done in P0); self-audit of the platform with its own pipeline; complete ASVS L2 checklist in `standards-mapping.md`; final `threat-model.md`; tag **v1.0.0** | a real project walks E1–E8; sandbox passes escape tests; no high finding open without justification; docs in English; locales without missing keys |

Weekly objectives, in the plan's words:

- **Week 1 — P0.** The repo is born with the rules on: CI, licenses, no CDN,
  tests from the first commit. Adding that later costs double. Risk: JWT /
  Argon2 libraries that satisfy the license and are actively maintained;
  transitive-dependency friction in the license checker.
- **Week 2 — P1.** Replicate the current manual process end to end. The
  heaviest week: its success criterion is the most concrete of the plan. Risk:
  WeasyPrint and the fine details of the template (long tables, page breaks,
  repeated headers); Semgrep findings without CWE; the public registry's
  restrictive license, hence own rules only. That is why Friday is all PDF.
- **Week 3 — P2 + P3.** The analyst works inside the platform and the
  reconstruction workflow reaches case design. Risk: boundary-value extraction
  in compound expressions; unreadable Mermaid diagrams for large functions —
  if it appears, E5 is limited to complexity ≤ 10 and recorded as a non-goal.
- **Week 4 — P4 + P5.** Close the cycle, add the software inventory (BOM + CVE)
  and release. The buffer sits on the last day because the risk is concentrated
  in S2–S4 and the margin is worth more once it is known what overran. Risk: a
  positive sandbox escape test → no release.

## Dependencies and critical path

```
 P0 auth ──────┐
 P0 CI/licences├──▶ P1 pipeline ══▶ P1 PDF ══▶ P2 triage/editor ──▶ P3 matrix (E4)
 P0 Compose ───┘                     ║                                  ║
                                     ║                                  ▼
                                     ║                    P3 AST + brief (E5) ══▶ P4 scaffolds (E6)
                                     ║                          ▲                      ║
                                     ║                          ┊ (E7 → E5 loop:       ▼
                                     ║                          ┊  coverage short)  P4 sandbox + coverage (E7)
                                     ║                          ┊                      ║
                                     ▼                          └┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┘
                              Release v1.0.0 ◀═════════════════════════════════════════╝

 ══▶  critical path        ──▶  dependency        ┈┈  loop
```

**Critical path: P1 PDF → E5 brief → E7 sandbox.** These are the three points
where an overrun cannot be dodged by working on something else. The buffer
exists for them. Everything in P5 hangs off P4 (the inventory needs the SBOM
from P1 and a project that reached E7).

## Contingencies

| Situation | Action |
|---|---|
| The PDF does not reach fidelity on the P1 Friday | Consume buffer from week 4. P2 starts anyway: it works on data, not on the PDF. |
| A sandbox escape test is positive | No release. Fixed even if it consumes the whole buffer. |
| Briefs with miscounted basis paths | Scope reduced to cyclomatic complexity ≤ 10; documented as a non-goal. |
| CI rejects a dependency by license | Substitute it. No exceptions are added to the allowlist. |
| Two consecutive weekly milestones not closed | P5 PHP/Java moves to a second cycle. The release ships with JS/TS + Python. The BOM + CVE inventory is not cut: it is a deliverable of the factory, not of a language. |
| The vulnerability database cannot sync (no internet) | Import the OSV/NVD dump by file; the last-update date stays visible in the panel. Never a live query to an external service. |

## Deliverables on 2026-09-18 (v1.0.0)

1. Repository with P0–P5 at DONE, CI green, release v1.0.0.
2. `docs/` complete: architecture, threat model, standards mapping (ASVS L2 →
   code), glossary, development phases, software inventory.
3. Platform deployable with `docker compose up`; role-based auth, i18n es/en,
   light/dark theme.
4. Audit pipeline (Semgrep + own rules, Gitleaks, OSV/Trivy, Lizard/cloc) with
   normalized SARIF output.
5. Software inventory of the factory: SBOM, CBOM and VEX in CycloneDX 1.6 per
   project/version; local CVE database (OSV + NVD) with periodic sync;
   statistics of vulnerable and outdated components.
6. Editable, versioned institutional report; PDF/DOCX/Markdown export; visual
   summary, metrics, test debt, annexes.
7. Workflow E1–E8 with server-side gates, deterministic briefs, test
   scaffolds, sandbox, mutation testing.
8. Support for JS/TS, Python, PHP/Laravel, Java/Spring.
9. Self-audit executed, no high finding open.

**Out of scope** (already "on demand" in the development plan, does not
condition the platform): language wave 3 (Go, C#/.NET) and Tauri offline
packaging.

**On the version number**: 1.0 in SemVer implies a stable API. Real stability
is confirmed by the first cycle of analyst use; breaking changes found there
are documented as 1.x → 2.0, never as "it was not finished".

## Plan-first gate

Any phase slice touching auth/sandbox/ingest/report-integrity or >200 LOC
starts with `tasks/phaseN-survey.md` (read-only survey + design pseudocode +
`## Verdict`), signed off before edits. The plan marks two days where this is
non-negotiable: day 3 (auth, done) and day 16 (sandbox).

## Scope-change log

Scope changes are recorded here with the date (work plan → footer).

| Date | Change | Source |
|---|---|---|
| 2026-08-17 | Working title "Caja Blanca Studio" replaced by **Dioptra** (`docs/name-and-identity.md`). | `mmarin` |
| 2026-08-18 | P0 closed ten days before its deadline (2026-08-28) — the intended way of working: the plan's dates are deadlines, the work runs ahead, the deadlines stay. Two plan items of P0 deferred: the RQ worker service in Compose lands with P1's first job (a worker with nothing to run is dead code), and the "no string literals in components" lint is not available in oxlint — covered by the locale-parity test and the `dioptra-mockup-fidelity` panel; revisit if oxlint ships `jsx-no-literals`. | this file |
| 2026-08-28 | Work plan v1.0 (2026-08-21) adopted as the reference. **Added**: the software inventory module (SBOM/CBOM/VEX in CycloneDX 1.6, local OSV + NVD vulnerability database, BOM ↔ CVE correlation, statistics, CycloneDX JSON + CSV export) — SBOM generation moves into P1 day 7, the module itself is P5 day 18. **Reshaped**: P5 becomes "Cierre" (inventory → PHP/Java + audit log + annexes → buffer/self-audit/release); PHP/Java is the first cut under overrun, the inventory is never cut. **Added**: Mermaid as the E5 diagram format; Markdown + basic DOCX export in P1; "unknown CWE" as a valid finding state; release v1.0.0 on 2026-09-18. **Rejected**: Docker Scout (proprietary, cloud). **Out of scope**: Go, C#/.NET, Tauri. **Clarified**: "MINCYT" names the audited form systems; the report template is "the institution's", and the institution is deliberately left unnamed in the docs. | `docs/work-plan-reference.html` |
| 2026-09-21 | **Schedule slip recorded.** No work happened between the P0 close (2026-08-18) and today; every P1–P5 deadline, including the v1.0.0 release (2026-09-18), has passed with only P0 built. P1 starts today as one push (`tasks/phase1-survey.md`). Cuts taken for that push: day 10 fidelity reduced to a first structural pass against the backend anchor; Trivy config / Checkov deferred; the Semgrep rule set is initial (JS/TS + Python). The release rule "two consecutive milestones missed → PHP/Java to a second cycle" applies on its face; the cut itself is `mmarin`'s call at the P4 close and, once taken, is recorded in CLAUDE.md → Current phase status and `tasks/phase5-closure.md`. The inventory stays either way. New dates are not set here — the deadlines are never moved; the remaining phases run in order as fast as they close. | `mmarin` ("go") |
| 2026-09-22 | **P2 started on P1's data** (contingency "PDF fidelity slips → P2 starts anyway"): triage and the versioned editor built as one push (`tasks/phase2-survey.md`). Two cuts recorded there: report sections are plain-text paragraphs, not rich text (HTML from the browser into WeasyPrint is the stored-XSS path the threat model names); "signing" is an attested lock (actor, time, justification, SHA-256, immutable row) rather than a cryptographic signature. The Proyectos tab stays; whether the cards fold back into Inicio is still `mmarin`'s call. | `mmarin` ("go") |
| 2026-09-22 | **P3 day 14 built** (`tasks/phase3-survey.md` §7): tree-sitter + the JS/TS/Python grammars (all MIT, license gate re-run) parse the planned functions into a deterministic flow graph. **Deviation recorded**: the diagram is NOT rendered by the Mermaid library — Mermaid's SVG carries inline `<style>`/`style=` that the app's CSP (`style-src 'self'`) drops; instead a deterministic layered layout is drawn as class-only SVG in the UI (and will be the PDF annex's SVG in P5). The Mermaid text remains the plan's interchange/editing format, stored and shown as text. `mmarin` may revert to Mermaid by adding `'unsafe-inline'` to `style-src`. | `mmarin` ("go then") |
| 2026-09-22 | **Analysis paths made root-relative** (found walking E2→E5 on the real MINCYT frontend): the normalizer stripped "everything up to `src/`", which ate the audited tree's own `src/` directory — findings and Lizard metrics then disagreed on every path, so the E4 risk matrix correlated no finding and E5 could not read the sources. The pipeline now passes the roots the tools actually saw (`/work`, and the jail itself in `local` runner mode) and only an exact root is stripped. | this file |
| 2026-09-22 | **E4 refuses what E5 could never approve** (`tasks/phase3-survey.md` §8 addendum): the precommit panel showed that one planned function the AST layer cannot brief, or with more basis paths than a design may hold, would strand an analysis at E5 (plan locked, stages monotonic). The plan save now parses every chosen function and refuses it with a typed error naming the function; `MAX_CASES` is 200. Additive contract change: error responses MAY carry `context` (bounded strings, rendered as text). | `mmarin` ("lo recomendado") |
| 2026-09-22 | **P4 day 17 built and P4 closed**: the E7 sandbox, the re-audit and the E7 → E5 loop. Three deviations recorded. (1) The module under test is copied FLAT into the attempt directory and the scaffold imports it by BASENAME — mutmut refuses outright to mutate a module whose dotted path starts with `src.`, and one attempt holds exactly one planned function, so nothing can collide. This changed day 16's generated imports. (2) The survey's "sized tmpfs for the runs root" cannot live in Compose: a sibling container's mount is resolved by the HOST daemon, so a tmpfs declared in the worker would be invisible to the sandbox. The size bound is an OPERATOR step on the host and the Compose file carries the command; it is recorded as a residual in the threat model. (3) Each tool's output shape is normalised by a wrapper INSIDE the image, so the host never learns a tool's format — which is what let mutmut 3.3→3.8 and Stryker's `ps` dependency be one-file fixes. Nine escape probes run with the shipped argv, all negative. | `mmarin` ("we need to end till p5 like fast") |
| 2026-09-22 | **P4 closed after the precommit panel found two integrity defects in E7.** (1) The gate scored "nothing was measured" as "everything passed": with no result document, coverage reads 100 % of no lines, JUnit reads no failure and the mutation report reads no survivor, and the container's exit code was discarded — a fail-OPEN in the one place the plan calls the release criterion. An absent or unparseable document, or a non-zero exit, is now `ERRORED` and never a verdict. (2) The three result files were produced in the single writable mount the audited code shares, as the same user and with that directory as its cwd, so the code under test could author its own verdict. They are now produced on the container's own tmpfs and copied over as the last action, once every runner has exited — which removes the easy tricks but does NOT make the verdict tamper-proof, and that is recorded as an accepted residual rather than claimed as a control. Real integrity means producing the verdict outside the container the code runs in, which is a redesign of E7. Also fixed: the server now enforces the written reason for reopening a design (it was enforced only by the screen), verifying a reopened function no longer crashes the batch, and a NUL in the audited code's stderr no longer reaches a PostgreSQL `text` column. | `mmarin` ("we need to end till p5 like fast") |
| 2026-09-22 | **Three escape probes proved nothing and were rewritten.** `capsh` is not installed in the sandbox image, `mount -t proc` is refused even when privileged because `/proc` is already mounted, and a fork bomb written with literal backslash-n died of a `SyntaxError` before forking — each test asserted a non-zero exit and got one for the wrong reason. The rewritten table had also silently dropped the CPU-spin, memory-balloon and `/proc`-write probes the PENDING version listed, narrowing the release blocker's scope without recording it. Every probe is now checked to be ATTRIBUTABLE (it fails under the shipped flags AND succeeds when the flag it targets is removed), and `docs/threat-model.md` shows both columns. The CPU-spin probe found something on its own: an endless loop does NOT die with a raw invocation — the timeout kills the docker client, not the container — so that test goes through `executor.run`, whose named container and kill hook are what actually stop it. | this file |
| 2026-09-22 | **P3 day 15 built** (`tasks/phase3-survey.md` §8): the brief is computed from the flow graph and the findings, never from anything the developer edits; its items carry stable ids (`R1` branches, `F1` boundaries, `E1` error paths, `M1` malicious cases) and the minimum case count is our cyclomatic complexity plus one per SAST finding inside the function. **Decision recorded**: "pseudocode covers every brief item" is a DECLARATION — each case ticks the items it demonstrates — because a text match would be guesswork and an AI judge is forbidden; E7 measures the declaration by line coverage. Approval is per function and separate from the stage transition (the mockup's single button is two actions: approval has no written reason, the transition does). The plan's "three real functions" are three functions of this repository copied verbatim as fixtures (`backend/tests/fixtures/ast/real_*`), hand-counted in `backend/tests/test_brief.py`; the same code produces the brief for any planned function of an ingested project. | `mmarin` ("continuemos") |
| 2026-09-22 | **P4 survey signed off** (`tasks/phase4-survey.md` §5). Three answers recorded: (1) the sandbox image is built WITHOUT pruning anything — 4.1 GB free measured at sign-off, and a build that runs the disk down stops rather than removing an image; (2) **non-goal of v1.0.0**: tests run against the module under test with NO project dependency installed — `npm install` on a hostile tree executes lifecycle scripts, which is remote code execution by design, so a test needing `axios` cannot run in the sandbox; (3) Stryker (JS/TS) + mutmut (Python) confirmed as the mutation tools. P4 code may now be written. | `mmarin` ("firmar los tres tal cual") |
| 2026-09-22 | **P4 day 16 built**: E6 scaffolds and the developer's test file. Three decisions recorded. (1) One scaffold file PER PLANNED FUNCTION, not per module — two planned functions in one module would collide; the case id (`C1 · …`, `test_c1_…`) opens every case name, which is how the gate finds a case the developer reworded. (2) The generated comments are ENGLISH while the UI is Spanish: the file is compared byte for byte, so its content may not depend on the reader's UI language — the hard rule and the mechanism agree. (3) The E6 gate PARSES the stored file with the same tree-sitter layer the briefs use and asks one question per case — is there a statement of its own, not a comment, not the title string, not `pass`, not a skipped case; a file that does not parse leaves every case unwritten and the gate never raises. Whether a test proves anything stays E7's measurement. `CaseDesign.reopened_at` also lands now (migration 0007), so day 17's E7 → E5 loop can reopen a failed function without moving the stage machine backwards. | `mmarin` ("we need to end till p5 like fast") |
| 2026-09-22 | **P5 survey signed off and day 18 built** (`tasks/phase5-survey.md`, under `mmarin`'s "bueno hagamos lo necesario para cerrar", given after the two open questions were put to him). Decisions recorded there: **(1) PHP/Laravel + Java/Spring CUT to a second cycle** — the contingency "two consecutive weekly milestones missed" fired on its face and the cut is the necessary; v1.0.0 ships JS/TS + Python, E2 still detects PHP/Java and E4 refuses their functions like any the AST layer cannot parse. (2) CBOM = our own Semgrep crypto-inventory rules (cdxgen / cbomkit rejected on footprint). (3) OSV is the correlation source, NVD the enrichment. (4) "Outdated" = a newer version known to the local copy (a fixed version in an advisory or another project's SBOM), never a registry query. (5) The sync is RQ's own scheduler with a self-rescheduling job under a fixed id, kicked once by the API lifespan; `DIOPTRA_VULNDB_SYNC_ENABLED=false` is the air gap. (6) Inventory roles: reading and exports for the three roles, sync/import for admin and analyst with a written reason; the audit-log read narrows the analyst's "own projects" to "own actions". (7) Mockup 10's "Usuarios" half is not built. | `mmarin` ("bueno hagamos lo necesario para cerrar") |
| 2026-09-22 | **P5 days 19–20 built and two defects of E7 found by the walk of the platform on itself.** Day 19: report sections 7–10 (Métricas, Deuda de pruebas, Inventario, Anexos A–E with the flow diagrams as server-side SVG) in every format; PHP/Java stayed cut. Day 20: the owner/runtime database role split (`docker/initdb/01-runtime-role.sql`, proven in CI), the ASVS L2 chapter checklist, the final threat model, `scripts/self_audit.py` and `scripts/dev.sh`. The walk (Dioptra's own tree through E1–E8, function `scaffold/text.py::slug`) found: (1) after `reopen-design`, re-approving the cases was refused with `stage_locked` — the E7 → E5 loop could never close; fixed, the flag is now cleared by the next PASSED run, not by the approval. (2) Six of the module's mutants are EQUIVALENT (`"ascii"` → `"ASCII"`, `ensure_ascii=None`, a dead `strip`) and a zero-tolerance gate closed forever. **Decision taken to close, for `mmarin` to overrule**: the developer may excuse a surviving mutant with a written, audited reason (`POST …/mutants/equivalent`), effective on the next run and shown in the report — the same discipline as a triage verdict, and the sandbox now ships each survivor's diff so the judgement can be made. | this file |
| 2026-09-22 | **P3 day 13 built** (`tasks/phase3-survey.md`): the workflow stage lives on the ANALYSIS (one ingested version walks E2→E8; E1 is the project's registration); every transition is explicit — role, gate and written reason checked by the server, one audit row each; gates whose phase has not landed (E5 on day 15, E6–E7 in P4) are closed by construction, so nothing reaches E8 through the API before P4. Risk = `ccn × (1 + findings in the file) × criticality of the worst finding` (thresholds 8 / 20) — the plan's "criticidad" has no other source until E1 metadata carries one. | `mmarin` ("go") |
