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
7. **Sensitive artefacts (phase 11, 2026-09-28)** — our own deterministic
   walk over the jail (`analysis/artefacts.py`, in the worker, during the
   normalisation step) for data committed AS SOURCE: database dumps (a dump
   signature in the head of a `.sql`/`.dump`/`.pgdump`/`.bak`/`.sql.gz`, the
   `PGDMP` or SQLite magic), user-upload directories (≥ 10 images or
   documents under `uploads`/`upload`/`media`/`storage/app`), `.env` files
   with values (not the `.example`/`.sample`/`.dist` templates), private keys
   and logs over 1 MB. It reads a 4 KiB HEAD per candidate and `lstat` for the
   size, never follows a symlink, skips only `.git`, and stops at 300 000
   files or 500 hits with the cap recorded as a coverage gap. Its hits are
   stored raw (`raw_tool_outputs`, tool `artefacts`) before they become
   findings of category `artefact`, merged BEFORE the worst-first ordering so
   a HIGH dump competes for the cap on its severity. **A finding never carries
   the file's content**: a dump's snippet is a canonical signature label, an
   upload directory's is "N archivos · X MB", an `.env`'s is its KEY names.
   Why not a Semgrep rule: Semgrep skips targets over `--max-target-bytes`,
   so it would be silent on exactly the 234 MB dump that prompted this
   (`tasks/phase11-survey.md` §2). Measured on that tree (1.4 GiB, 19 851
   files): 0.32 s.
8. **No-CDN rule (factory norm)** — any `<script>`, `<link>`, font or import
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
**Since 1.5.1 those drops are read** (`tasks/hardening-1.5.1-survey.md` §3):
a SARIF tool declares each file it could not fully scan in
`runs[].invocations[].toolExecutionNotifications`, and
`normalizer.execution_notes` turns them into the coverage row's detail —
counts only (files, and drops by syntax error / memory / time / other), never
a file name from the audited tree — with the status left RAN. The report and
the project screen word it ("cobertura parcial: N archivos con reglas
omitidas…"). Files over `--max-target-bytes` are NOT in the SARIF, and the
report says the note does not count them. Measured on the same tree: 386 s,
1 034 results, under the 600 s runner timeout.

**A report is parsed WHOLE or not at all** (1.5.1, §1 of the same survey).
The storage cap (`DIOPTRA_MAX_TOOL_OUTPUT_BYTES`, 32 MiB) used to be the parse
cap too: on that tree Semgrep's SARIF passed 32 MiB — each result carries its
matched lines, tens of kilobytes on a minified bundle — was cut, did not
parse, and the analysis ended with Semgrep FAILED and no SAST finding; Lizard's
CSV was cut the same way and parsed SHORT, as RAN, with nothing saying so.
Now the executor reads the report once (`O_NOFOLLOW`, a regular file only — the
output directory is writable by the analysis container), stores the capped
copy as evidence and hands the normalizer the whole document up to
`DIOPTRA_MAX_TOOL_PARSE_BYTES` (256 MiB). Over that, the run is FAILED with
its size in the detail, for every tool alike — never a partial parse.

Every runner has a timeout and CPU/RAM limits, and its raw output is persisted
before normalization (the plan's day 7), so a normalizer bug never loses a
tool's result.

**An analysis a dead worker left behind is closed** (1.5.1,
`analysis/sweep.py`): at API start-up and before each ingest, an analysis
RUNNING for longer than `DIOPTRA_ANALYSIS_STALE_MINUTES` (120, floored above
the pipeline's RQ timeout) or QUEUED for longer than
`DIOPTRA_ANALYSIS_QUEUE_RETENTION_HOURS` (24) becomes FAILED
`analysis_abandoned`, audited by `system` (`analysis.abandon`), and its files
are removed; an `upload.zip` spool older than the stale window with no row, or
beside a finished row, is removed too. The pipeline claims its row QUEUED →
RUNNING and closes it RUNNING → DONE/FAILED through conditional updates, so a
duplicate message is a no-op and a worker still alive cannot revive an
abandoned row; a jail that already exists when extraction starts is refused
(`upload_missing`), never analysed as if whole.

**An analysis can be cancelled, gracefully** (phase 12,
`tasks/phase12-survey.md`; `mmarin`'s definition: not an error, stops in
seconds, never collides with the finish). `POST /api/v1/analyses/{id}/cancel`
— the creator while still an analyst, or an admin; no written reason — closes
a QUEUED analysis at once (its queue message then finds nothing to claim) and,
on a RUNNING one, only records `cancel_requested_at`. The worker polls that
column every 2 s while a tool runs (`core/process.py::run_stoppable`, the
process in its own session so the kill reaches `git-remote-https` and
`semgrep-core` too), between entries and inside large members of the
extraction, and at every step; on a yes it `docker kill`s the named container,
deletes every coverage row and raw output the run wrote, removes the files and
closes the row **CANCELLED** — its own status, never FAILED, and the tool it
killed gets no coverage row. The findings, SBOM, CBOM and metrics are written
in the SAME transaction as the DONE transition, which requires no cancel
pending, so a cancel that lands during the finish either discards everything
or is refused (409 `analysis_not_cancellable`). Measured on the analysis
image: a Semgrep run cancelled at 5 s was asked at 6.0 s and its container was
gone at 6.1 s. A cancel whose worker died is closed by the sweep after
`DIOPTRA_ANALYSIS_CANCEL_GRACE_MINUTES` (5), at the next cancel click or ingest;
when a container's kill cannot be confirmed its files are left to the sweep
rather than removed under a live mount.

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
  is persisted with `third_party = true` — except an SCA finding (its verdict feeds the VEX) and, since phase 11, a sensitive artefact (a dump under `vendor/` is still the team's). It is normalised, stored, deduped,
  reported and inventoried exactly like any other; the flag only takes it out
  of the E3 triage queue (`docs/workflow-gates.md` → Third-party findings). A
  runner is never told to skip those paths — the scanners still refuse the
  audited tree's own ignore files.
- Snippets are stored raw and ESCAPED AT EVERY RENDER (UI and report) — the
  audited code is hostile input.
- A tool that fails to run is recorded as a coverage gap in the report, never
  silently skipped.
