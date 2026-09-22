# Analysis pipeline

> **Status: IN_PROGRESS — P1 slice built 2026-09-21: runners (`backend/app/analysis/runners/`), SARIF normalizer, CWE → OWASP map, CVSS 3.1, catalog, metrics; see `tasks/phase1-survey.md`.**

Tool authority lives in CLAUDE.md → Analysis Tool Source Authority. This file
covers behavior.

## Layers

Each layer runs in its own ephemeral container over the ingested code; all
output is normalized to SARIF, then mapped CWE → OWASP Top 10:2021 (API
Security Top 10 when the target is an API), severity computed with CVSS 3.1.

1. **SAST** — Semgrep CE with OUR rules (`rules/semgrep/`). The public
   registry's community rules carry a restrictive license and MUST NOT be
   bundled; our rules are an asset of the team.
2. **SBOM** — Syft or cdxgen (Apache-2.0) produce a CycloneDX 1.6 JSON from
   the lockfiles and the dependency tree, metadata only: no package script is
   ever executed. One SBOM per ingested project version; it is the single
   input of the SCA layer below and of the software inventory
   (`docs/software-inventory.md`). Generating it twice is a bug.
3. **SCA / CVE** — every dependency of the audited system, direct AND
   transitive, taken from the SBOM (lockfiles: npm, pip, composer, maven,
   go.mod) and cross-checked against LOCAL vulnerability data (plus GitHub
   Advisories as carried by OSV): in P1 the OSV dump directory the offline
   runner mounts; from P5 the OSV + NVD mirror. Each finding reports the CVE id,
   affected version, fixed version, CVSS severity. Never a live query.
4. **Secrets** — Gitleaks over the tree AND git history AND CI configs.
5. **Metrics** — Lizard (cyclomatic complexity per function) + cloc. Feeds the
   E4 risk matrix: complexity × findings × criticality.
6. **Config/IaC** — Trivy config / Checkov (Dockerfiles, CI, permissions).
7. **No-CDN rule (factory norm)** — any `<script>`, `<link>`, font or import
   pointing at an external domain → finding CWE-829 / OWASP A08:2021, with the
   mitigation "bundle and serve locally, version-pinned". It is among the
   initial own rules of P1 day 7.

Every analysis container runs with `--network none`: OSV-Scanner in offline
mode against a local OSV database directory mounted read-only (in P1 that
directory is seeded from the OSV dump file, the same dump the P5 mirror
imports — no mirror table exists before P5), Semgrep with `--metrics=off`,
Trivy with its database mounted and updates disabled. A runner that needs
the network to work is misconfigured, not an exception.

Every runner has a timeout and CPU/RAM limits, and its raw output is persisted
before normalization (the plan's day 7), so a normalizer bug never loses a
tool's result.

Languages (analysis runners and, since P3 day 14, the tree-sitter AST layer of E5): wave 1 JS/TS + Python (P1–P4); wave 2 PHP/Laravel + Java/Spring
(P5, first cut under overrun); wave 3 Go + C#/.NET is out of scope for v1.0.0.

## Rule authoring (`rules/semgrep/`)

- One YAML file per rule family; every rule carries `metadata: {cwe, owasp}`.
- Each rule ships with a `tests/` pair (positive + negative snippet).
- Re-run the full ruleset against the anchor fixtures (the MINCYT form
  systems whose manual reports are the P1 success criterion) before merging
  changes.

## Normalizer invariants

- SARIF in, internal Finding model out: `{rule, cwe, owasp, cvss, severity,
  path, line, snippet, mitigation, references}`.
- **"Unknown CWE" is a valid state, not an error.** A Semgrep rule without a
  CWE (or a tool that emits none) yields a finding with `cwe = null` and an
  OWASP bucket of "unclassified"; it still reaches triage and the report.
- Findings are deduplicated across tools on (path, line, rule-or-CWE) before
  persistence; the surviving finding keeps every source tool in `references`.
- **Paths are relative to the TREE ROOT, and only an exact root is stripped.**
  The pipeline passes the roots the tools could have seen (`/work` inside the
  container, the jail path in `local` runner mode) to the normalizer and to
  the Lizard parser. Guessing a prefix is a bug: a generic "strip everything
  up to `src/`" rule ate the audited tree's own `src/` directory on the
  MINCYT frontend (2026-09-22), so findings said `helpers/x.js` while the
  metrics said `work/src/helpers/x.js` — the E4 risk matrix then correlated
  nothing and E5 could not read the file.
- Snippets are stored raw and ESCAPED AT EVERY RENDER (UI and report) — the
  audited code is hostile input.
- A tool that fails to run is recorded as a coverage gap in the report, never
  silently skipped.
