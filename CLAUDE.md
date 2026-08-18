# Dioptra — Project Memory

## Project Identity

- **Name**: **Dioptra** — after Hero of Alexandria's sighting instrument: you look *through* it, and you use it to check alignment against a reference. Brand mark `DP`, environment prefix `DIOPTRA_`. Rationale and naming rules: @docs/name-and-identity.md. "Análisis de caja blanca" stays as the name of the TECHNIQUE, never of the product.
- **Purpose**: Web platform for white-box analysis of third-party, untested systems: automated audit pipeline (SAST, SCA/CVE, secrets, metrics), a gated testing workflow (E1–E8) that forces plan → design → pseudocode → tests written by the developer, and an editable institutional report (MINCYT template) with OWASP/CWE/CVSS classification.
- **Target**: Self-hosted web app (Docker Compose). Backend: Python 3.13 + FastAPI. Frontend: React 19 + Vite + react-i18next, bundled and served locally. Queue: Valkey + RQ. DB: PostgreSQL + SQLAlchemy. PDF: Jinja2 + WeasyPrint.
- **Standards**: OWASP Top 10:2021, OWASP API Security Top 10, OWASP ASVS 4.x (platform targets L2 for itself), CWE, CVSS 3.1, ISO/IEC 25010, ISO/IEC/IEEE 29119, McCabe basis-path testing. Full mapping: @docs/standards-mapping.md
- **Deployment model**: On-premise inside the software factory, air-gap friendly. NO external runtime dependency of any kind — see Hard Rules → No CDNs.
- **Author / project lead**: Moises Marin (`mmarin`).

---

## When to read what

File-pattern triggers (when working on these paths):

- `backend/app/analysis/**` (tool runners, SARIF normalizer, CWE→OWASP mapper): read @docs/analysis-pipeline.md
- `backend/app/workflow/**` (stages E1–E8, gates, test briefs): read @docs/workflow-gates.md
- `backend/app/auth/**`, `backend/app/audit/**`: read @docs/roles-and-permissions.md and @docs/threat-model.md
- `backend/app/reports/**`, `backend/templates/**`: read @docs/report-format.md
- `backend/app/sandbox/**`, `docker/**`: read @docs/threat-model.md → Sandbox
- `backend/app/ingest/**` (ZIP/git intake): read @docs/threat-model.md → Ingestion
- `frontend/src/**`: read @docs/ui-model.md and the anchor mockups in @docs/mockups/
- `frontend/src/locales/**`: read @docs/ui-model.md → i18n rules
- `rules/semgrep/**` (our own SAST rules): read @docs/analysis-pipeline.md → Rule authoring

Task-type triggers (when doing these activities):

- Orienting to the codebase or adding new files/directories: read @docs/architecture.md
- Starting a new phase: read @tasks/_TEMPLATE.md and the specific @tasks/phaseN*.md
- Any security review or threat modeling: read @docs/threat-model.md
- Audit prep, ASVS alignment questions: read @docs/standards-mapping.md
- Planning work that crosses phase boundaries: read @docs/development-phases.md
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
- **Finding**: one detected issue with CWE, OWASP category, CVSS severity, file:line, snippet, mitigation.

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

- Phase 0: DONE (2026-08-18) — foundations (repo scaffold, Docker Compose, FastAPI + React skeletons, auth with Argon2id + JWT + roles, i18n es/en, light/dark theme, CI with license gate). See @tasks/phase0-foundations.md
- Phase 1: DESIGN — audit MVP (ZIP/git ingest → Semgrep + Gitleaks + OSV pipeline → normalized findings → MINCYT PDF). Success criterion: automatically reproduce the existing MINCYT backend report.
- Phase 2: DESIGN — findings UI (filters, triage, false-positive-with-justification) + report editor with version control.
- Phase 3: DESIGN — workflow E1–E5 (risk matrix, AST flow diagrams, test briefs, pseudocode editor with approval).
- Phase 4: DESIGN — E6–E7 (deterministic test scaffolding, sandbox execution, coverage vs. brief, mutation re-audit).
- Phase 5: DESIGN — language wave 2 (PHP/Laravel, Java/Spring), full audit log, hardening, ASVS L2 self-audit.

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
| PDF rendering | Jinja2 + WeasyPrint | BSD-3 |

---

## Hard Rules

- **The platform MUST NOT write tests.** No AI/LLM anywhere in the product. Scaffolding is deterministic only: file, imports, and case names derived from the AST and the approved pseudocode. Assertions, data, and logic are ALWAYS written by the developer — writing the test IS the learning.
- **No CDNs — two levels.** (1) This platform loads nothing from external servers at runtime: every dependency installed, version-pinned, served locally. (2) Factory norm: audited code that loads scripts/styles/fonts from external domains gets an automatic finding (CWE-829, OWASP A08:2021) via our Semgrep rules.
- **Free licenses only.** Apache-2.0 / MIT / BSD / MPL / LGPL / GPL. No proprietary, source-available, or non-commercial-clause dependency. CI license gate MUST fail the build otherwise. Known-vulnerable npm dependencies MUST fail the build (`dependency-vulnerabilities`, `npm audit`); the Python side has no vulnerability scanner yet — OSV-Scanner covers it from P1, see Analysis Tool Source Authority; version currency is reported as a warning (`dependency-currency`), because a gate that trips on every upstream minor release gets disabled rather than obeyed.
- **Gates are server-side.** The API rejects any stage transition whose gate is not satisfied. UI state is never the enforcement mechanism.
- **Audited code is hostile.** It is parsed, rendered, and executed accordingly: ZIP ingest guards against zip-slip and size bombs; git URL ingest guards against SSRF; findings/snippets are escaped before ANY rendering (report HTML/PDF included — XSS via a hostile snippet into an analyst's browser is a real path); tests execute ONLY in Docker sandboxes with no network, CPU/RAM limits, and read-only FS except the workspace.
- **English everywhere in code**: identifiers, comments, commits, docs. Spanish appears ONLY in UI locale files (`es.json` default, `en.json` complete parity).
- **Usernames are initial + lastname**, lowercase, no dots: `mmarin`, `cperez`, `amedina`.
- **Auth**: Argon2id password hashing, short-lived JWT + refresh, lockout on failed attempts. Every sensitive action (confirm/discard finding, approve gate, edit report) records actor + justification in the append-only audit log.
- **No secrets in the repo.** Ever. `.env*` gitignored; CI runs Gitleaks on ourselves.

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
