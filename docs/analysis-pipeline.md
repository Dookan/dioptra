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

**Acquisition is the worker's** (phase 10, 2026-09-28): a ZIP reaches the
pipeline as a spooled file the API streamed to disk after authentication, and
the job extracts it (`ingest/upload.py::extract_upload`, the unchanged
`archive.py` guards) before the first runner, exactly as it clones a git URL.
Caps: 1 GiB compressed, 8 GiB unpacked, 300 000 entries.

Every analysis container runs with `--network none`: OSV-Scanner in offline
mode against a local OSV database directory mounted read-only (in P1 that
directory is seeded from the OSV dump file, the same dump the P5 mirror
imports — no mirror table exists before P5), Semgrep with `--metrics=off`,
Trivy with its database mounted and updates disabled. A runner that needs
the network to work is misconfigured, not an exception.

**Semgrep is sized to its container, not to the host** (found by the phase-10
walk, 2026-09-28): it picks its parallelism from the cores it can SEE, which
inside a `--cpus 2` container are still the host's (it ran 7 jobs on an
8-core machine), so on a 1.4 GiB tree it outgrew `--memory 2g` and the kernel
killed it (`semgrep-core exited with -9`) — the SAST layer became a coverage
gap. `runners/tools.py::semgrep_budget` now passes `--jobs` = the runner's
CPUs (cut until each job has at least 512 MiB) and `--max-memory` = its
memory over jobs + 1 (682 MiB at the defaults): a rule that would exceed that
on one file is dropped for that file instead of the whole scan dying.
**Recorded limit**: that drop is noted only in Semgrep's own raw output, which
is stored (`raw_tool_outputs`) but not read — the report's "Cobertura de
herramientas" shows Semgrep as RAN. The same was already true of the files
`--timeout 30` and `--max-target-bytes` skip; surfacing Semgrep's per-file
errors as a partial-coverage note is a 1.x item. Measured on the same
tree: 386 s, 1 034 results, under the 600 s runner timeout.

Every runner has a timeout and CPU/RAM limits, and its raw output is persisted
before normalization (the plan's day 7), so a normalizer bug never loses a
tool's result.

Languages (analysis runners and, since P3 day 14, the tree-sitter AST layer of
E5): wave 1 JS/TS + Python (P1–P4). Wave 2 was **cut to a second cycle on
2026-09-22** and is being built there: **PHP/Laravel is DONE (2026-09-23,
`tasks/phase7a-php.md`)** — the AST layer parses `.php`, so E4 now
plans PHP functions, E5 briefs them, E6 scaffolds them as PHPUnit and E7 runs
them in their own sandbox image; **Java/Spring has not started** (phase 7b,
same survey), so E4 still refuses its functions like any the AST cannot parse.
Wave 3 Go + C#/.NET stays out of scope for v1.0.0.

## Rule authoring (`rules/semgrep/`)

- One YAML file per rule family; every SECURITY rule carries `metadata: {cwe, owasp}`. Wave 2 added **17 PHP/Laravel rules** across eleven families on 2026-09-23 (`tasks/phase7a-php.md`); two of them (`laravel-model-unguarded`, `laravel-blade-unescaped-echo`) are `languages: [regex]` over `*.php` / `*.blade.php`, because a class property and a Blade directive are not valid standalone patterns for semgrep-core's PHP parser. The CBOM inventory rules (`crypto-inventory.yml`, P5) carry `metadata.category: inventory` and no CWE/OWASP instead: a strong algorithm is not a weakness. Their ids start with `crypto-inventory-` and their message has the fixed shape `crypto-asset primitive=… algorithm=… weak=yes|no`, which the normalizer parses (`backend/tests/test_runners.py` pins both contracts).
- Each rule ships with a `tests/` pair (positive + negative snippet).
- Re-run the full ruleset against the anchor fixtures (the MINCYT form
  systems whose manual reports are the P1 success criterion) before merging
  changes.

## Normalizer invariants

- SARIF in, internal Finding model out: `{rule, cwe, owasp, cvss, severity,
  path, line, snippet, mitigation, references}`.
- **Inventory results are diverted, never findings**: a SAST result whose rule
  id starts with `crypto-inventory-` becomes a `crypto_assets` row
  (`normalize_crypto`, P5) and is skipped by `normalize`; a weak algorithm
  reaches triage only through its own `weak-crypto.yml` rule.
- **"Unknown CWE" is a valid state, not an error.** A Semgrep rule without a
  CWE (or a tool that emits none) yields a finding with `cwe = null` and an
  OWASP bucket of "unclassified"; it still reaches triage and the report.
- **Severity precedence is fixed, and the last step is a FALLBACK, not a default.**
  A CVSS vector wins; then a `security-severity` property; then the result's own
  `level`; then — since 2026-09-23 — **the rule's `defaultConfiguration.level`**,
  which SARIF 2.1.0 §3.27.10 makes the inherited value for a result that omits
  one. Semgrep writes the level once per rule and omits it on every result, so
  reading only `result.level` sent every SAST finding to INFO whatever its rule
  declared (measured: 0 of 611 real results carried a level, 67 rules declared
  one; 513 INFO became 312 high + 201 medium). The step is monotone — an absent
  level used to yield INFO, the floor — so it can only raise a severity, never
  lower one, and the rules are ours, never the audited tree's.
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
- **Third-party findings are marked, never dropped.** A finding whose path has
  a dependency directory as one of its segments (`backend/app/analysis/third_party.py`)
  is persisted with `third_party = true`. It is normalised, stored, deduped,
  reported and inventoried exactly like any other; the flag only takes it out
  of the E3 triage queue (`docs/workflow-gates.md` → Third-party findings). A
  runner is never told to skip those paths — the scanners still refuse the
  audited tree's own ignore files.
- Snippets are stored raw and ESCAPED AT EVERY RENDER (UI and report) — the
  audited code is hostile input.
- A tool that fails to run is recorded as a coverage gap in the report, never
  silently skipped.
