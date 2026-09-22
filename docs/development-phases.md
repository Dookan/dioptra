# Development phases

> **Status: P0 DONE (2026-08-18); P1 IN_PROGRESS since 2026-09-21; P2 and P3 IN_PROGRESS since 2026-09-22; P4–P5 DESIGN.** Phase status summary
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
| 2026-09-22 | **P3 day 13 built** (`tasks/phase3-survey.md`): the workflow stage lives on the ANALYSIS (one ingested version walks E2→E8; E1 is the project's registration); every transition is explicit — role, gate and written reason checked by the server, one audit row each; gates whose phase has not landed (E5 on day 15, E6–E7 in P4) are closed by construction, so nothing reaches E8 through the API before P4. Risk = `ccn × (1 + findings in the file) × criticality of the worst finding` (thresholds 8 / 20) — the plan's "criticidad" has no other source until E1 metadata carries one. | `mmarin` ("go") |
