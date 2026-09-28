# Dioptra — Project Memory

## Project Identity

- **Name**: **Dioptra** — after Hero of Alexandria's sighting instrument: you look *through* it, and you use it to check alignment against a reference. Brand mark `DP`, environment prefix `DIOPTRA_`. Rationale and naming rules: @docs/name-and-identity.md. "Análisis de caja blanca" stays as the name of the TECHNIQUE, never of the product.
- **Purpose**: Web platform for white-box analysis of third-party, untested systems: automated audit pipeline (SAST, SCA/CVE, secrets, metrics), a software inventory per project (SBOM / CBOM / VEX in CycloneDX 1.6, correlated against a LOCAL vulnerability database), a gated testing workflow (E1–E8) that forces plan → design → pseudocode → tests written by the developer, and an editable institutional report with OWASP/CWE/CVSS classification.
- **Institution**: deliberately unnamed — the platform serves whichever institution's software factory deploys it; docs say "the institution" and never a specific one. The anchor reports are the manual white-box analyses of the **MINCYT form systems** (`/home/user/Desktop/UTD/CAJA-BLANCA/*.pdf`) — "MINCYT" names the AUDITED SYSTEM, not the template; the template is the institution's.
- **Work plan**: @docs/work-plan-reference.html (v1.0, 2026-08-21) — 20 business days, 2026-08-24 → 2026-09-18, one engineer, release **v1.0.0** with P0–P5 complete. The HTML is the reference; its distilled form (day table, milestones, dependencies, contingencies, scope-change log) is @docs/development-phases.md, which is what agents read.
- **Target**: Self-hosted web app (Docker Compose). Backend: Python 3.13 + FastAPI. Frontend: React 19 + Vite + react-i18next, bundled and served locally. Queue: Valkey + RQ. DB: PostgreSQL + SQLAlchemy. PDF: Jinja2 + WeasyPrint.
- **Standards**: OWASP Top 10:2021, OWASP API Security Top 10, OWASP ASVS 4.x (platform targets L2 for itself), CWE, CVSS 3.1, ISO/IEC 25010, ISO/IEC/IEEE 29119, McCabe basis-path testing. Full mapping: @docs/standards-mapping.md
- **Deployment model**: On-premise inside the software factory, air-gap friendly. NO external runtime dependency of any kind — see Hard Rules → No CDNs.
- **Author / project lead**: Moises Marin (`mmarin`).

---

## When to read what

File-pattern triggers (when working on these paths):

- `backend/app/analysis/**` (tool runners, SARIF normalizer, CWE→OWASP mapper, SBOM generation): read @docs/analysis-pipeline.md
- `backend/app/inventory/**` (SBOM/CBOM/VEX store, vulnerability database sync, BOM↔CVE correlation, statistics): read @docs/software-inventory.md and @docs/threat-model.md (rows SBOM generation, Inventory rendering, Vulnerability DB sync, VEX statements)
- `backend/app/workflow/**` (stages E1–E8, gates, test briefs): read @docs/workflow-gates.md
- `backend/app/auth/**`, `backend/app/audit/**`: read @docs/roles-and-permissions.md and @docs/threat-model.md
- `backend/app/reports/**`, `backend/templates/**`: read @docs/report-format.md
- `backend/app/sandbox/**`, `docker/**`: read @docs/threat-model.md (row Test sandbox + section Sandbox escape tests)
- `backend/app/ingest/**` (ZIP/git intake): read @docs/threat-model.md (rows ZIP ingest, git URL ingest)
- `frontend/src/**`: read @docs/ui-model.md and the anchor mockups in @docs/mockups/
- `frontend/src/locales/**`: read @docs/ui-model.md → i18n rules
- `rules/semgrep/**` (our own SAST rules): read @docs/analysis-pipeline.md → Rule authoring

Task-type triggers (when doing these activities):

- Orienting to the codebase or adding new files/directories: read @docs/architecture.md
- Starting a new phase: read @tasks/_TEMPLATE.md and the specific @tasks/phaseN*.md
- Any security review or threat modeling: read @docs/threat-model.md
- Audit prep, ASVS alignment questions: read @docs/standards-mapping.md
- Planning work that crosses phase boundaries, checking dates/milestones, or applying a contingency: read @docs/development-phases.md (distills @docs/work-plan-reference.html)
- Writing a new task file: read @tasks/_TEMPLATE.md
- Naming anything the user or an operator sees — a service, an environment
  variable, a cookie, a package, a report credit: read @docs/name-and-identity.md
- Encountering an unfamiliar term: read @docs/glossary.md

---

## Normative Keywords

Normative keywords in this document follow RFC 2119 and RFC 8174: **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY**.

---

## Glossary

- **Audited system**: a third-party codebase ingested for analysis. It is HOSTILE INPUT at every layer (parsing, rendering, execution).
- **Stage (E1–E8)**: one step of the gated workflow. Register → Ingest → Analyze/Triage → Test plan → Case design → Test writing → Verification → Report. See @docs/workflow-gates.md
- **Gate**: a server-side precondition for entering the next stage. Gates are enforced by the API, never only by the UI.
- **Test brief** ("consigna"): the deterministic per-function spec (min cases from cyclomatic complexity, branches with lines, boundary values, mandatory malicious case) computed from the AST + findings. No AI involved.
- **Re-audit**: stage E7's check of the tests themselves — coverage vs. brief + mutation testing. A surviving mutant rejects the gate.
- **Finding**: one detected issue with CWE, OWASP category, CVSS severity, file:line, snippet, mitigation. An unknown CWE is a VALID state of a finding, never an error.
- **SBOM / CBOM / VEX**: the software, cryptographic and exploitability bills of materials of an audited system, all CycloneDX 1.6. The SBOM is produced at E2/E3 from lockfiles (metadata only); VEX statements come from the analyst's triage. See @docs/software-inventory.md
- **Vulnerability database**: the platform's LOCAL mirror of OSV + NVD (CVE.org), refreshed by a scheduled sync or by importing a dump file. Never a live third-party query.
- **Self-audit**: the platform's own code run through its own pipeline (last day of P5). It must come out with no high finding left open without justification.

---

## Roles — who does what

Product roles (enforced by the API on every endpoint; see @docs/roles-and-permissions.md for the full matrix):

| Role | Username format | Does | Does NOT |
|---|---|---|---|
| `admin` | `amedina` | Creates/disables accounts, assigns roles, manages projects, reads everything | Sign findings or reports in place of an analyst |
| `analyst` | `mmarin` | Runs analyses (E1–E3), triages findings (confirm / false-positive with written justification), edits and signs the final report (E8) | Write the developer's tests |
| `developer` | `cperez` | Walks E4–E7: builds the test plan, designs cases, writes ALL test assertions and logic, fixes rejected gates | Skip stages, edit findings, sign reports |

Development roles (this repository):

- **Moises Marin (`mmarin`)** — project lead. Approves BIG findings, phase closures, and any plan the precommit gate escalates.
- **Claude Code** — implementation agent, bound by every rule in this file. MUST run `/precommit` before any commit.
- **Review panel** (`.claude/agents/`) — `dioptra-security-auditor`, `dioptra-invariant-checker`, `dioptra-qa-verifier`, `dioptra-coverage-adversary`, `dioptra-mockup-fidelity`. They audit every commit via `/precommit`; see that command for selection and concurrency rules.

---

## Current phase status

Dates are the work plan's **deadlines**, not start dates: we run ahead of the plan on purpose — a phase starts the moment the previous one closes — and the deadlines are never moved. Milestones ◆ close only with tests passing, docs updated and the phase's `tasks/phaseN-*.md` at DONE with a commit hash. Full day table: @docs/development-phases.md.

- Phase 0: DONE (2026-08-18, ◆ deadline 2026-08-28) — foundations (repo scaffold, Docker Compose, FastAPI + React skeletons, auth with Argon2id + JWT + roles, i18n es/en, light/dark theme, CI with license gate). See @tasks/phase0-foundations.md. Two plan items deferred: the RQ worker service (lands with P1's first job) and a no-string-literal lint (oxlint has no such rule; parity test + mockup-fidelity panel cover it).
- Phase 1: DONE (2026-09-24; built 2026-09-21, deadline ◆ "P1 (PDF)" 2026-09-04, plan days 6–10, critical path, passed) — audit MVP: data model + ZIP/git ingest → Semgrep (own rules) + Gitleaks + OSV runners **+ SBOM CycloneDX 1.6** → SARIF normalizer (CWE/OWASP/CVSS, dedupe) → Jinja2 → HTML → WeasyPrint report + Markdown + basic DOCX export. Closed by its phase-close evidence: a mutmut pass on the normalizer and the ingest guards (normalizer 59 % → 94 % killed; `git_source.shallow_clone`'s security argv had no test at all) and the day-10 structural comparison, run against the **frontend** anchor because the MINCYT backend source is not on this machine (recorded deviation; the anchor's "Errores y prácticas" list was prose the old generator mistook for code — and `mmarin` decided the section must list what the anchor listed: the scan now has the anchor generator's breadth, reads block comments and Vue/CSS/HTML files, and reproduces 9 of its 10 files; the tenth came from that generator reading CSS `#id` selectors as comments). Pixel fidelity stays open. See @tasks/phase1-audit-mvp.md
- Phase 2: DONE (2026-09-22, commit `5f13ee1`; deadline 2026-09-08, plan days 11–12, passed) — findings viewer with filters, triage with mandatory justification (analyst only, every verdict to the audit log, a false positive leaves the report), versioned report editor (every save a snapshot, signing locks a version at the database level, plain-text sections escaped at render) with a visual executive summary. E3 was walked end to end on the real MINCYT frontend (fifteen findings triaged, report signed and exported in four formats). Survey: @tasks/phase2-survey.md. See @tasks/phase2-findings-ui.md
- Phase 3: DONE (2026-09-22, commits `820d9c1`, `8082a74`, `80c0a3f`; ◆ deadline "P2+P3" 2026-09-11, plan days 13–15, critical path, passed) — day 13 built: stage machine E1→E8 on the analysis (`Analysis.stage`, monotonic, one endpoint `POST …/stage/advance`, role + gate + written reason, audit row per transition; unbuilt gates fail closed), E4 risk matrix (`ccn × (1 + findings) × criticality`) and test plan (developer only, locked once E4 is left), "Plan de pruebas" screen, status bar; day 14 built: tree-sitter (MIT) flow graphs for JS/TS/Python → deterministic Mermaid text + a deterministic layout drawn as class-only SVG (the CSP forbids Mermaid's inline styles; survey §7), `GET|PUT …/diagram`, "Diseño de casos" screen; day 15 built: deterministic test brief per planned function (`backend/app/workflow/brief.py`: basis paths from OUR complexity, every branch with its line, boundary values from literal comparisons, error paths, one malicious case per SAST finding inside the function; items with stable ids), the developer's cases in their own words declaring which items each covers (`PUT …/cases`), approval checked server-side against the live brief (`POST …/cases/approve`), and the E5 gate `leave_design` (every planned function approved) replacing `not_built`. Closed with a mutmut pass over gates / brief / triage / test_plan and a full E2→E5 walk on the real MINCYT frontend. Survey: @tasks/phase3-survey.md. See @tasks/phase3-workflow-e1-e5.md
- Phase 4: DONE (2026-09-22, commits `576993f` and `2b9680d`; deadline 2026-09-15, plan days 16–17, critical path, passed) — E6–E7. Day 16: deterministic scaffolds per planned function (`backend/app/workflow/scaffold/` — names, imports and one case per approved case, never an assertion; every title and audited identifier escaped at the generator's boundary), the developer's test file stored as text, and the E6 gate `leave_tests`, which PARSES the stored text and asks only "did you write a body for every case". Day 17: the E7 sandbox (`backend/app/sandbox/`, `docker/sandbox.Dockerfile` — one ephemeral container per attempt, no network, read-only root, all capabilities dropped, non-root, one writable mount, nothing of the audited project installed), the re-audit (`workflow/verify.py`: tests green → every case asserts → coverage vs. the E4 criterion with each brief item checked by line → no surviving mutant), the gate `leave_verification`, and the E7 → E5 loop as an explicit `POST …/reopen-design` that never moves the stage backwards. Nine sandbox escape probes run with the shipped argv, all negative (@docs/threat-model.md → Sandbox escape tests). Survey: @tasks/phase4-survey.md. See @tasks/phase4-e6-e7.md
- Phase 5: DONE (2026-09-23, commits `280ec5b` and `b801f70`; ◆ deadline "Release" 2026-09-18, plan days 18–20, passed) — "Cierre". Day 18 BUILT 2026-09-22: **software inventory** (`backend/app/inventory/` — SBOM per project and version read from P1's stored document, CBOM from our own Semgrep crypto-inventory rules, VEX projected from the E3 verdicts, the local OSV + NVD mirror with a scheduled worker-side sync or a dump-file import, BOM↔CVE correlation by PURL + version events, the statistics panel, CycloneDX JSON + CSV export) and the audit-log read (`GET /api/v1/audit`, Bitácora screen). **PHP/Laravel + Java/Spring CUT to a second cycle** (the plan's contingency, applied 2026-09-22: v1.0.0 ships JS/TS + Python). Day 19 BUILT: report sections 7–10 with annexes A–E (`backend/app/reports/{closure,svg}.py`). Day 20 BUILT: owner/runtime database role split (`docker/initdb/01-runtime-role.sql`), ASVS L2 checklist complete, final threat model, `scripts/self_audit.py`, the self-audit (94 findings on 2026-09-22 — an artefact of the SARIF severity defect fixed 2026-09-23; **re-run 2026-09-24: 127 findings, 73 high, none a vulnerability of the platform** — rule fixtures, test passwords, one migration f-string over a constant — all 127 triaged with a written verdict on `mmarin`'s authorization, 5 dependency CVEs confirmed as 1.x debt, no high open; see @tasks/phase5-closure.md), and two E7 defects found by walking the platform through E1–E8 on itself — the E7 → E5 loop could not re-approve (fixed) and equivalent mutants closed the gate forever (the developer now excuses one with a written, audited reason; `POST …/mutants/equivalent`). Tagged **v1.0.0** on the closing commit (2026-09-23). Survey: @tasks/phase5-survey.md. See @tasks/phase5-closure.md
- **Phase 7a (PHP/Laravel): DONE (2026-09-23, commits `1b5795e` and `48528d2`)** — the first half of the language wave cut from P5. Gate: @tasks/phase7-survey.md (signed off; one sandbox image per language, PHP before Java). Built: the PHP AST profile and briefs, 17 own Semgrep PHP/Laravel rules, the PHPUnit scaffold, and `dioptra-sandbox-php` with Xdebug branch coverage and Infection. **Recorded limit**: Infection mutates only code inside a class, so a free PHP function records `mutation_measured = false` and the gate decides on the other three questions — declared on every surface, never a silent pass. Closed by a walk, not by assertion: a real Laravel application through **E1–E6** (257 written verdicts, three of the team's own PHP functions planned, briefed, designed and tested) and Dioptra's own `php-licenses.php` through **E7** (three runs, the E7 → E5 loop, a pass). The walk found and fixed two defects — the E4 risk matrix could hide the team's own code behind vendored libraries, and the E7 coverage criterion was judged over the whole module, which made it unreachable on any multi-function file. See @tasks/phase7a-php.md. **Phase 7b (Java/Spring) may now start** — the phase-7 survey covers it and needs no new survey, but its own walls (compiled sources, the package-path attempt layout, compile failure → `ERRORED`) are recorded there.
- **Phase 8 (asynchronous PDF export): DONE (2026-09-24, commits `a96233a`, `9e21b6d`, `fbc5f64`)** — survey @tasks/phase8-survey.md signed off by `mmarin`; task @tasks/phase8-async-report-export.md. Closed by a walk with a real queue (`scripts/dev.sh workers`) and a mutmut pass on `app/reports/jobs.py` (598 of 708 killed, the rest classified). The PDF is rendered by a job (`backend/app/reports/jobs.py`) in a DEDICATED `report-worker` with no Docker socket (its own `reports` queue and `ReportWorkerJob` allowlist; the socket-holding `worker` refuses the render) that the person follows from a bottom-right toast; one PDF in flight per person (partial unique index), the requester or the admin downloads, the file is deleted after download. **1.x contract change an agent must know**: `GET …/report?format=pdf` — the endpoint's default format — now refuses with 409 `report_pdf_is_queued`; HTML, Markdown and DOCX stay synchronous. The render is NOT faster (~50 s for 516 pages) and nothing may claim it is.
- **Second cycle: IN_PROGRESS since 2026-09-23** — work continues on `main` after the `v1.0.0` tag. Its first diff carries a **1.x contract change**: `systems.installed_at` becomes a real `date` (migration `0011`), so `POST /api/v1/projects` no longer accepts free text there and any stored non-ISO value becomes `N/A` in the report; it also adds the password reveal toggle, the calendar picker and the developer-facing ingest gate. Its later diffs carry two more changes an agent must know before touching either surface: **(a) SAST severity was collapsing to INFO for every finding of every language** — SARIF's `result.level` is inherited from the rule's `defaultConfiguration.level` and the normalizer read only the result's own (fixed 2026-09-23; an analysis ingested before that date is NOT comparable with one after, and no backfill was taken); **(b) a finding inside a dependency directory leaves the E3 triage queue** (`backend/app/analysis/third_party.py`, migration `0013`) — `gates.leave_analysis` counts only the audited project's own code and `POST …/findings/{id}/verdict` refuses the rest with `finding_not_triageable`, while the finding stays in every export, in the executive summary and in the inventory. **Owed to this cycle**: PHP/Laravel + Java/Spring (cut from P5) and @tasks/phase6-user-administration.md (DESIGN only, blocked behind its own survey, which must also write its justification carve-out into the Hard Rules before any code). The next release number is `mmarin`'s call — Release rules document a breaking change as 1.x → 2.0, never as "unfinished". Full entry: @docs/development-phases.md → Scope-change log, 2026-09-23.
- **Out of scope for v1.0.0** (already "on demand" in the development plan): language wave 3 (Go, C#/.NET) and Tauri offline packaging.
- **Cut order under overrun**: PHP/Java moves to a second cycle first (release ships with JS/TS + Python) — **applied 2026-09-22**. The software inventory is NEVER cut — it is a deliverable of the factory, not of a language.

---

## Analysis Tool Source Authority

Single authoritative mapping of analysis capabilities to tools. All other sections MUST be consistent with this table. Every tool MUST carry a free license (verified in CI).

| Capability | Tool | License |
|---|---|---|
| SAST engine | Semgrep CE + **our own rules** in `rules/semgrep/` (public registry rules have a restrictive license — MUST NOT be bundled) | LGPL-2.1 |
| SCA / CVE lookup | OSV-Scanner / Trivy (direct + transitive deps via lockfiles, against OSV/NVD/GitHub Advisories) | Apache-2.0 |
| Secrets | Gitleaks (including git history and CI configs) | MIT |
| Metrics / complexity | Lizard + cloc | MIT / GPL-2.0 |
| Config / IaC | Trivy config / Checkov | Apache-2.0 |
| Mutation testing | Stryker (JS/TS), mutmut (Python), Pitest (Java), Infection (PHP) | Apache-2.0 / BSD-3 |
| SBOM generation | Syft or cdxgen → CycloneDX 1.6 JSON, from lockfiles + dependency tree (metadata only — no package scripts run) | Apache-2.0 |
| CBOM (cryptographic inventory) | **Our own Semgrep crypto-inventory rules** (`rules/semgrep/crypto-inventory.yml`), diverted by the normalizer into `crypto_assets` and emitted as CycloneDX 1.6 `cryptographic-asset` components — decided at the P5 survey (§6); cdxgen CBOM and IBM cbomkit rejected on footprint, not licence | LGPL-2.1 (Semgrep CE) |
| VEX | Authored in-platform from the analyst's triage verdicts, emitted as CycloneDX VEX. No tool. | — |
| Vulnerability database | LOCAL mirror of OSV + NVD (CVE.org) dumps — scheduled sync or file import, NEVER a live query. Dependency-Track is the accepted alternative if an external component is preferred. **Docker Scout is REJECTED** (proprietary cloud service). | OSV data CC-BY-4.0 / NVD public domain / Dependency-Track Apache-2.0 |
| Flow diagrams (E5) | tree-sitter (parser) → our own deterministic flow graph → Mermaid text (interchange, editable) + our own class-only SVG layout (rendered in the UI and, from P5, in the PDF annex); the Mermaid library is not bundled — its inline styles cannot render under the app's CSP (`tasks/phase3-survey.md` §7) | MIT (tree-sitter + grammars) |
| PDF rendering | Jinja2 + WeasyPrint | BSD-3 |
| DOCX export | python-docx (candidate, confirmed at the P1 survey) | MIT |

---

## Hard Rules

- **The platform MUST NOT write tests.** No AI/LLM anywhere in the product. Scaffolding is deterministic only: file, imports, and case names derived from the AST and the approved pseudocode. Assertions, data, and logic are ALWAYS written by the developer — writing the test IS the learning.
- **No CDNs — three levels.** (1) This platform loads nothing from external servers at runtime: every dependency installed, version-pinned, served locally. (2) Factory norm: audited code that loads scripts/styles/fonts from external domains gets an automatic finding (CWE-829, OWASP A08:2021) via our Semgrep rules. (3) Vulnerability data is a LOCAL mirror of OSV + NVD refreshed by a scheduled sync or an imported dump file, with the last-sync date visible in the panel; the platform never queries a third-party vulnerability service at request time, and Docker Scout is rejected on both license and this rule.
- **Free licenses only.** Apache-2.0 / MIT / BSD / MPL / LGPL / GPL, plus **PHP-3.01 and Xdebug-1.03** for the PHP sandbox image (widened by `mmarin` 2026-09-23: both are OSI-compatible BSD-style licences with a naming clause). The criterion is FREE, not permissive; the enumeration may be widened for a licence that meets it, and `scripts/license_gate.py::ALLOWED_LICENSES` is the authoritative list. No proprietary, source-available, or non-commercial-clause dependency — that is what "the allowlist never gets exceptions" (Release rules) forbids. CI license gate MUST fail the build otherwise. Known-vulnerable npm dependencies MUST fail the build (`dependency-vulnerabilities`, `npm audit`); the Python side has no vulnerability scanner yet — OSV-Scanner covers it from P1, see Analysis Tool Source Authority; version currency is reported as a warning (`dependency-currency`), because a gate that trips on every upstream minor release gets disabled rather than obeyed.
- **Gates are server-side.** The API rejects any stage transition whose gate is not satisfied. UI state is never the enforcement mechanism.
- **Audited code is hostile.** It is parsed, rendered, and executed accordingly: ZIP ingest guards against zip-slip and size bombs; git URL ingest guards against SSRF; findings/snippets are escaped before ANY rendering (report HTML/PDF included — XSS via a hostile snippet into an analyst's browser is a real path); tests execute ONLY in Docker sandboxes with no network, CPU/RAM limits, and read-only FS except the workspace.
- **English everywhere in code**: identifiers, comments, commits, docs. Spanish appears ONLY in UI locale files (`es.json` default, `en.json` complete parity) and in REPORT CONTENT: `backend/templates/report/**` (templates, `strings.json`) and `backend/app/analysis/catalog.py` hold the institution's report prose verbatim from the anchor reports, because the report IS the institutional document. Nothing else under `backend/app/` may contain Spanish; tests may pin anchor wording literally when that wording is what they prove. Two reference artifacts kept verbatim are the other exception: `docs/work-plan-reference.html` and `docs/mockups/index.html` are in Spanish because they are what the institution approved. Two operator-facing guides are BILINGUAL (a Spanish section, then an English one with the same content) because the factory's operators read Spanish: `README.md` and `docs/deployment/README.md` (`mmarin`, 2026-09-24). Both halves must stay in step; everything else in `docs/` stays English only.
- **Usernames are initial + lastname**, lowercase, no dots: `mmarin`, `cperez`, `amedina`.
- **Auth**: Argon2id password hashing, short-lived JWT + refresh, lockout on failed attempts. Every sensitive action (confirm/discard finding, approve gate, edit report) records actor + justification in the append-only audit log.
- **No secrets in the repo.** Ever. `.env*` gitignored; CI runs Gitleaks on ourselves.

---

## Release rules (from the work plan's contingency table)

- A positive sandbox escape test means **no release** — it is fixed even if it consumes the whole buffer.
- A dependency rejected by the license gate is **substituted**; the allowlist never gets exceptions.
- Test briefs whose basis paths cannot be counted reliably → scope reduced to cyclomatic complexity ≤ 10, recorded as a non-goal.
- PDF fidelity slipping past the P1 milestone consumes buffer; P2 starts anyway (it works on data, not on the PDF).
- Two consecutive weekly milestones missed → PHP/Java goes to a second cycle; the release ships with JS/TS + Python. The inventory (BOM + CVE) is never cut.
- No internet for the vulnerability database → the OSV/NVD dump is imported by file, and the last-update date stays visible. Never a live query.
- A milestone is closed only with tests passing, docs updated and `tasks/phaseN-*.md` at DONE with a commit. A Friday that does not close is Monday's first item.
- v1.0.0 is tagged on 2026-09-18 with P0–P5 complete. Breaking changes found in the first analyst cycle are documented as 1.x → 2.0, never as "unfinished".
- Scope changes are recorded in @docs/development-phases.md → Scope-change log, with the date.

---

## Agent Behavioral Rules

- **Phase discipline is absolute.** No later-phase code during the current phase. TODO references MUST name the phase where the work lands: `# TODO(phase4): mutation re-audit hook`.
- **Plan-first investigation gate is MANDATORY for any commit touching auth, sandbox, ingestion, report-integrity surface OR with >200 LOC scope.** The gate is a read-only file survey + design-draft pseudocode, written to `tasks/phaseN-survey.md` with a `## Verdict` section, BEFORE any edits. Skipping requires explicit per-commit override from `mmarin`.
- **`/precommit` runs before every commit.** The panel's triage policy (SLIGHT → fix now / BIG → stop and bring a plan / NONE → green) is defined in `.claude/commands/precommit.md`. Commit only on `READY TO COMMIT`.
- **Mockup-fidelity audit is a verification gate for UI work.** Any screen anchored to @docs/mockups/ MUST match its tokens (hex colors, radii, spacing), copy tone (plain Spanish, buttons say what they do), both themes, and the "next step always visible" principle. `dioptra-mockup-fidelity` verifies.
- **Task files MUST include Definition of Done and Non-goals.** See @tasks/_TEMPLATE.md.
- **No new dependencies without a license + rationale comment** in the lockfile-adjacent manifest change.
- Surface trade-offs explicitly — no silent design choices.
- When instructions reference a file path, verify the file exists before acting; report discrepancies instead of creating or relocating silently.

---

## Code Conventions

- **Backend**: Python 3.13, FastAPI, SQLAlchemy 2.x. `mypy --strict` clean. Typed domain errors (exception hierarchy per module, e.g. `IngestError` → `ZipSlipDetected` / `RepoUnreachable`); raw exceptions MUST NOT reach an HTTP response — every handler maps typed errors to explicit status codes, no stack traces to clients.
- **Frontend**: React 19 + TypeScript strict. No visible string literals in components — every user-facing string through `t('key')` with `es.json`/`en.json` parity (CI check). Design tokens from `frontend/src/theme/tokens.css` only; both themes always.
- **Comments** explain the *why* and the revisit trigger, never restate the code.
- **Tests**: pytest (backend) + Vitest (frontend). Every endpoint and every gate transition has tests before its phase closes. Mutation testing (mutmut/Stryker) runs on gate/auth/analysis-normalizer modules at phase close — we apply to ourselves what we demand of the factory.
- **Quality gates in CI**: ruff + mypy (backend), oxlint + tsc (frontend), license checker, Gitleaks, locale-parity check. All MUST pass.
- **Naming**: `snake_case` Python, `camelCase` TS, `kebab-case` files in frontend, REST routes `/api/v1/<resource>`.
- **Docs**: Markdown, one topic per file, lowercase-hyphen names, prose status markers (`> **Status: DESIGN SURFACE — not yet implemented.**`, `DONE`/`IN_PROGRESS` with dates and commit hashes). Diagrams are ASCII box art or committed SVG — no external diagram services.

---

## Git Rules

- **NEVER leak secrets.** Before any `git add`/commit/push, scan staged changes for credentials/tokens/keys. Stage intended files explicitly; NEVER `git add -A` / `git add .` blindly.
- Never add Co-Authored-By or any Claude/AI attribution to commit messages.
- Commit messages follow Conventional Commits only: `type(scope): description`.
- **NEVER discard working-tree changes.** `git checkout --`, `git restore`, `git stash`, `git reset --hard`, `git clean` are FORBIDDEN without explicit user confirmation — the working tree almost always holds uncommitted work. Use `git show HEAD:<path>` to inspect committed versions.
- Commit only when `mmarin` asks, and only after `/precommit` returns `READY TO COMMIT`.
