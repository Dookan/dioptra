# Hardening 1.5.1 survey — recorded debt, and one defect found by the read

> **Status: SIGNED OFF 2026-09-28 by `mmarin`** ("si", after the recommended
> answers to §7.1–§7.4 were put to him) — §7.1 (a), §7.2 (a), §7.3 (a),
> §7.4 (a). A cancel button for analyses was raised in the same session and is
> NOT in this batch: it is its own phase, next (§10). Written
> read-only, before any edit, as the plan-first investigation gate requires:
> item 1 touches the INGEST surface (the ZIP spool) and the pipeline's entry,
> item 5 the analysis layer's acceptance of tool output (CLAUDE.md → Agent
> Behavioral Rules). No edit to `backend/`, `scripts/`, `docker/` or
> `.github/` before the `## Verdict` is signed.
>
> Under the version scheme (CLAUDE.md → Release rules) this batch is a PATCH:
> **1.5.0 → 1.5.1**. It adds no endpoint and changes no request or response
> shape (§7.2 keeps it that way on purpose).

## 0. The batch

Four items were recorded as debt with a date; the read of the fourth
surfaced a fifth that outranks them.

| # | Item | Recorded in | Surface |
|---|---|---|---|
| 1 | Sweep `upload.zip` spools whose job never ran | `tasks/phase10-large-zip-ingest.md:132` | ingest, pipeline |
| 2 | Surface Semgrep's per-file drops in "Cobertura de herramientas" | `docs/analysis-pipeline.md:82` | analysis, report |
| 3 | Pin Gitleaks' SHA-256 in `ci.yml` and `analysis.Dockerfile` | scope-change log 2026-09-24 (b) | supply chain |
| 4 | `license_gate.py` covers GitHub Actions | scope-change log 2026-09-24 (c) | supply chain |
| 5 | **Semgrep's SARIF over 32 MiB loses the whole SAST layer** | found by this read | analysis |

## 1. Item 5 first — the SAST layer is lost on large trees

The development database holds one analysis of `caracas_sonrie-desarrollo.zip`
(`d3aff904…`, DONE, 2026-09-28 17:53). Its coverage rows:

```
semgrep      FAILED  output rejected: NormalizationError
gitleaks     RAN     osv-scanner RAN   syft RAN   lizard RAN   cloc RAN
findings: 8 SCA, 4 SECRET — zero SAST
```

and its stored raw Semgrep output is **exactly 33 554 432 bytes, `truncated =
true`**. The chain, read in the code:

1. `runners/executor.py::read_output` reads the report file back capped at
   `max_tool_output_bytes` (32 MiB) and flags `truncated`;
2. `pipeline.py::_record` hands that CAPPED buffer to `_collect`, which parses
   it as SARIF — a JSON document cut at 32 MiB cannot parse;
3. `_collect` raises `NormalizationError`, the row becomes FAILED.

So the report does say it (Cobertura: Semgrep failed) — no silent pass — but
on exactly the trees the phase-10 walk was about, **the SAST layer is gone**.
Why so large: 1 034 results over a tree whose findings are 98 % in
`node_modules`, and Semgrep's SARIF carries each match's lines as
`snippet.text` — on minified bundles one "line" is tens of kilobytes. ~32 KB
per result on average.

The phase-10 task records a walk with "all six tools RAN … 800 findings" on
the same ZIP; that analysis is no longer in the development database, so I
cannot tell whether its SARIF was under the cap (a different rule set or a
run before the phase-11 rules) or whether the record is wrong. The build
re-runs Semgrep on the ZIP and measures (§8), which settles it either way.

**The cap is doing two jobs at once**: bounding what is STORED in
`raw_tool_outputs` (sensible — a 200 MiB `bytea` row helps nobody) and
bounding what is PARSED (which must hold the whole document or parse
nothing). Options in §7.3.

## 2. Item 1 — spools whose job never ran

`ingest/upload.py`: the API streams the body to
`<workspace_root>/<project>/<analysis>/upload.zip`, `accept_zip` commits the
row QUEUED and enqueues, and the worker's `extract_upload` deletes the spool
in a `finally`. Every exception path removes it. What no `finally` survives
is a KILLED process. Four ways a spool outlives its purpose:

| Case | What is left | Row |
|---|---|---|
| a. API killed (OOM, restart, `SIGKILL`) mid-spool | the analysis directory with a partial `upload.zip` | none — never committed |
| b. Row committed, message lost (Valkey restarted without persistence) | the full spool | QUEUED forever |
| c. Worker killed during extraction | spool + partial jail | RUNNING forever |
| d. Worker killed later in the pipeline | the jail (spool already gone) | RUNNING forever |

Up to 1 GiB of spool plus up to 8 GiB of jail per case, on the volume the
operator sized for live analyses. Cases b–d also leave the person looking at
a progress bar that never ends: **nothing in the platform ever closes an
analysis that stopped** — there is a sweep for PDF jobs (phase 8), none for
analyses.

**And a latent defect beside it** (found reading `run_pipeline`): the job
sets `status = RUNNING` without checking the row was QUEUED. A second message
for the same id — a broker write (the accepted Valkey residual in
`docs/threat-model.md` names "enqueue an analysis id" as one of the four
things it can do) or a duplicate delivery — re-runs a DONE analysis: tools
again, coverage rows and raw outputs duplicated, and for a ZIP whose jail
exists `extract_upload` takes the "extracted in the request by a pre-phase-10
build" branch. After case c that branch would **analyse a partially
extracted tree as if it were whole**. The report sweep solved the same shape
with a conditional transition (`reports/jobs.py::_finish`, "conditional on
RUNNING"); the pipeline needs the same at its entry.

## 3. Item 2 — Semgrep's per-file drops

Measured on the stored SARIF documents (read structurally; no snippet or file
content printed):

| Analysis | `toolExecutionNotifications` |
|---|---|
| `cd4cc380…` (9 MiB, RAN) | 5: 3 `Timeout` (a rule on a file), 2 `Syntax error` |
| `d3aff904…` (caracas, the truncated one) | 96: 84 `Syntax error`, 6 `Out of memory`, 6 `Other syntax error` — over 96 files, 94 of them in `node_modules` |

So Semgrep DOES report every drop, in the standard SARIF place
(`runs[].invocations[].toolExecutionNotifications`, each with
`descriptor.id`, `level`, `message.text` naming the file), and it comes
first in the document. Nothing reads it today; the normalizer reads
`results` only. The coverage row says RAN with no detail.

What SARIF does NOT carry: the files `--max-target-bytes 2000000` skipped
(Semgrep lists those only in its JSON format's `paths.skipped`). The note
must not claim to be complete; §5.2 says how it words that.

## 4. Items 3 and 4 — supply chain

**Gitleaks**, two copies of the install, same shape:
`ci.yml:76–90` (`GITLEAKS_VERSION: "8.28.0"`) and
`docker/analysis.Dockerfile:19,37–41` (`ARG GITLEAKS_VERSION=8.28.0`). Both
download the tarball AND the checksum file from the same release and verify
one against the other: that catches corruption in transit, not a replaced
release. `docker/sandbox-php.Dockerfile:36–38,70–73` is the model already in
the repository: the digest is a literal in the file, `sha256sum -c` against
it. The digest can only be taken on trust once (from the release's checksum
file today, 2026-09-28); what pinning buys is that it cannot change silently
afterwards. The version and the digest then live in two files; a test keeps
them equal (the `test_upload_caps.py` pattern).

**Actions.** `.github/workflows/ci.yml` uses three: `actions/checkout@v5`,
`actions/setup-node@v6`, `astral-sh/setup-uv@v7` (14 `uses:` lines, one workflow). The
gate reads Python site-packages, `node_modules` and the PHP manifest; an
Action is none of those, which is how `gitleaks/gitleaks-action` (a
proprietary EULA) ran in CI until 2026-09-24. Two gaps, separable:

- **licence**: nothing declares or checks an Action's licence;
- **integrity**: `@v5` is a movable tag — the Action's owner (or whoever
  compromises it) can repoint it. The same argument as the Gitleaks digest.

## 5. Design pseudocode

### 5.1 Item 1 — the analysis sweep and a guarded entry

```
# analysis/pipeline.py — the entry becomes a conditional transition
run_pipeline(id):
    claimed = UPDATE analyses SET status=RUNNING, started_at=now
              WHERE id=:id AND status=QUEUED            # one statement
    if claimed.rowcount == 0:
        log "analysis %s is not queued (%s); job ignored"; return
    ... unchanged ...

# analysis/sweep.py (new) — run at API start-up, like the report sweep,
# and before each ingest request (cheap: an indexed status query + one dir walk)
sweep_analyses(db, settings, now):
    stale_running = now - analysis_stale_minutes      # floored ABOVE the
                                                       # pipeline's RQ job_timeout
    stale_queued  = now - analysis_queue_retention_hours
    for a in RUNNING with started_at < stale_running
           or QUEUED  with created_at < stale_queued:
        conditional UPDATE → FAILED, failure_code "analysis_abandoned",
                             finished_at now, current_step NULL
        remove its jail's parent directory (spool + jail + out)
        audit "analysis.abandon" by system, target the id
    for dir in workspace_root/*/*  (never following a symlink, uuid names only):
        if dir/upload.zip exists and is older than stale_running:
            row = the analysis whose id is dir.name
            if row is None:                    # case a: never committed
                rmtree(dir)
            elif row.status in (DONE, FAILED): # a finally that did not run
                unlink dir/upload.zip          # the jail stays: it IS the analysis
            # QUEUED / RUNNING: left to the pass above
```

- The RUNNING threshold is floored above `runner_timeout_seconds × 8 +
  git_clone_timeout_seconds` (the pipeline's RQ `job_timeout`), the same rule
  the report sweep applies to the render — a live pipeline can never be
  abandoned under it.
- A QUEUED row is NOT abandoned on the stale window: with one worker, a queue
  of large analyses legitimately waits for hours. It is abandoned after a
  retention window (24 h default), which is what a lost message looks like.
  Re-enqueueing it instead (what the report sweep does) is §7.1.
- The screen already renders FAILED with a code; `analysis_abandoned` gets its
  sentence ("El análisis se detuvo sin terminar; vuelve a subir el código")
  in both locales, and Bitácora a sentence for `analysis.abandon`.

### 5.2 Item 2 — the coverage note

```
# normalizer.py (or a sibling): read, never raise
execution_notes(sarif) -> (counts: {kind: n}, files: n) | None
    for run, for invocation, for n in toolExecutionNotifications (capped at 10 000):
        kind = n.descriptor.id bucketed into timeout | memory | syntax | other
        file = the path in n.message.text, only to count DISTINCT files
# pipeline._record, Semgrep only, status stays RAN:
    detail = "partial: 96 files; syntax=84 memory=6 other=6"   # ENGLISH machine
                                                               # text, as every
                                                               # detail is today
```

The stored detail stays English machine text (`pipeline.py:444` is the
precedent), with a fixed shape the readers parse: the REPORT writes the
Spanish sentence from `strings.json` (report content), including "los
archivos de más de 2 MB no se listan", and the project screen from an i18n
key in both locales; an unrecognised detail is shown as it is today. Spanish
never enters `backend/app/analysis/` (panel, invariant checker).
No file name from the audited tree enters the note — counts only — so no new
hostile string reaches the report.

### 5.3 Item 5 — parse from disk, store capped

```
executor._finish: output (stored) stays read_output(file, max_tool_output_bytes)
                  + parse_path = the file itself, and its size
pipeline._record: if status RAN:
    if size > max_tool_parse_bytes:             # new setting, per §7.3
        FAILED, detail "output too large: N MiB > M MiB"   # English machine text,
                                                            # worded by the readers
    else:
        _collect(from the FILE, not the capped buffer)
```

The raw output stored keeps its cap and its `truncated` flag: it is evidence,
never the normalizer's input. The failure, when it still happens, says why
in words instead of `NormalizationError`.

### 5.4 Items 3 and 4

```
ci.yml / analysis.Dockerfile:
    GITLEAKS_VERSION=8.28.0  GITLEAKS_SHA256=<64 hex>
    echo "${GITLEAKS_SHA256}  gitleaks_${V}_linux_x64.tar.gz" | sha256sum -c -
    # the checksums.txt download is dropped
backend/tests/test_tool_pins.py: the version and the digest are equal in both files

.github/action-licenses.json   {"actions/checkout": "MIT", ...}   # reviewed by a person
license_gate.py --workflows .github/workflows:
    every `uses:` in every workflow →
        "./…" (local)                 → ours, skipped
        "docker://…"                  → refused (no licence to check)
        "owner/repo[/path]@ref"       → owner/repo must be in the manifest
                                        with a licence is_free() accepts
        (if §7.4 b) ref must be a 40-hex commit SHA
    violations reported exactly like a package's
scripts/ci.sh and the CI supply-chain job call it
```

No YAML dependency: a `uses:` line is matched by a regex over the text,
which is exactly as strict as needed (a `uses:` the regex misses cannot be a
step). The licences go in the manifest after reading each Action's LICENSE
file in its repository at the pinned ref, recorded with the date.

## 6. Tests (hostile and failure paths first)

- Pipeline entry: a job for a DONE, FAILED or RUNNING row does nothing and
  writes no coverage row; a job for a QUEUED row runs.
- Sweep: every case of §2's table, with files aged by `os.utime`; a young
  spool is never touched; a symlinked or non-uuid directory is skipped; a
  QUEUED row inside retention is untouched; the audit row is by `system`;
  a live pipeline cannot be abandoned under the floor (settings refuse a
  lower value).
- Notes: a SARIF with no invocations, with malformed notifications, with
  10 001 notifications, with a hostile file name in the message — the
  detail carries counts only, and the RAN status is unchanged.
- Parse cap: a report over the STORAGE cap but under the parse cap is parsed
  whole and its findings stored, with `truncated = true` on the raw row; one
  over the parse cap is FAILED with the size in words.
- Gate: an unlisted Action, a non-free licence, `docker://`, a tag instead
  of a SHA (if §7.4 b), a local action accepted, the real `ci.yml` accepted.
- Pins: the test fails when either file's version or digest is edited alone.

Mutation pass on the new sweep, the pipeline entry and the gate's new reader
at close, as every phase has.

## 7. Decisions for `mmarin`

1. **Stale analyses (item 1).**
   **(a) Recommended**: the sweep closes a RUNNING analysis past the floor
   and a QUEUED one past 24 h as FAILED `analysis_abandoned` (audited, by
   `system`), removes their files, and removes orphan spools; the pipeline
   entry becomes QUEUED → RUNNING only.
   **(b)** Spools only: orphans without a row and spools of finished rows;
   stuck analyses stay stuck.
   **(c)** As (a), but a QUEUED row past the window is ENQUEUED AGAIN, like
   the report sweep, before it is abandoned. More moving parts for a case
   (a lost message) the person resolves by re-uploading.
2. **The Semgrep note (item 2).** **(a) Recommended**: status stays RAN, the
   detail column carries the counts — no enum, API or screen change, so the
   batch stays a PATCH. **(b)** A new status `partial` beside ran / failed /
   missing / timeout: clearer in the table, but a new enum value in the API
   response, the report labels and the screen, and every `status is RAN`
   check (the fail-closed rule among them) must learn it.
3. **The output cap (item 5).** **(a) Recommended**: parse from the file on
   disk under a new `DIOPTRA_MAX_TOOL_PARSE_BYTES` (default **256 MiB**),
   store capped at 32 MiB as today; the worker's memory for one parse of a
   256 MiB SARIF is the cost, measured in the build on the caracas ZIP
   before the default is fixed. **(b)** Simply raise
   `max_tool_output_bytes` — then every stored raw row grows with it.
   **(c)** Shrink Semgrep's output (drop snippets it prints) — it would need
   an option I have not verified exists for SARIF, and the snippet is what
   the finding's "Detección" shows.
4. **Actions (item 4).** **(a) Recommended**: the licence manifest AND
   commit-SHA pins (`uses: actions/checkout@<40 hex> # v5`), the gate refusing
   a tag. **(b)** The licence manifest only; tags stay.
5. Item 3 needs no decision: it copies the PHP image's pattern.

**Taken by `mmarin` 2026-09-28: §7.1 (a), §7.2 (a), §7.3 (a), §7.4 (a)** —
all four as recommended.

## 8. Acceptance

- Semgrep re-run on `caracas_sonrie-desarrollo.zip`, extracted WHOLE in a
  scratch directory and removed afterwards (the ZIP itself is evidence and is
  never trimmed; no photo or dump row is opened or printed): the real SARIF
  size, the worker's peak memory parsing it, and the analysis ending with
  Semgrep RAN and SAST findings stored — or, if the size exceeds the parse
  cap, an honest FAILED in words.
- The same run's Cobertura row shows the note of item 2.
- The sweep on the dev instance: an aged fake spool without a row is
  removed; nothing of a live analysis is.
- `scripts/ci.sh` green with the gate reading the workflows.
- Version 1.5.1 in the four places `test_version.py` pins.

## 9. Estimate

| Block | Size |
|---|---|
| pipeline entry + sweep + settings + locales + audit sentence | ~200 LOC |
| execution notes + strings | ~70 LOC |
| parse-from-file | ~40 LOC |
| Gitleaks pins + test | ~40 lines |
| gate reader + manifest + CI wiring (+ SHA pins) | ~90 LOC |
| tests | ~350 LOC |
| docs: threat-model (ZIP ingest row, Valkey residual, supply chain), analysis-pipeline, standards-mapping V14.2, development-phases, CLAUDE.md version | — |

## 10. Out of this batch — cancelling an analysis (next phase)

`mmarin` asked, reading this survey, for a button that cancels an analysis.
Agreed, and kept out of 1.5.1 on purpose: it adds an endpoint and a
`CANCELLED` status the API, the screen, the report and the Bitácora must
learn (a MINOR step, 1.6.0), and stopping a RUNNING pipeline means checking a
cancel request between steps and killing the named runner container — the
pipeline and the Docker executor, which is its own survey. It builds on this
batch's guarded entry (§5.1): with QUEUED → RUNNING conditional, cancelling a
queued analysis is marking the row, and the job becomes a no-op. The sweep of
§5.1 stays: the button is a person's decision, the sweep closes what a crash
left. Proposals to carry into that survey: the requester or the admin may
cancel, with a written reason (it discards work, and the audit trail should
say why); only QUEUED or RUNNING; whether a cancelled analysis keeps its
partial rows is `mmarin`'s call.

## 11. Precommit panel on this survey (2026-09-28) — folded in

Applied to the design above or stated here, before any code:

1. **One claim was wrong**: `ci.yml` has 14 `uses:` lines, not 12 (fixed in
   §4); the "real ci.yml accepted" test asserts no count.
2. **Item 5 covers every runner, not only SARIF** (QA verifier): the same
   analysis' **Lizard** raw output is also exactly 33 554 432 bytes,
   `truncated = true`, and its coverage row says RAN — the CSV parser took a
   cut document, so E4's metrics for that tree are probably incomplete with
   nothing saying so. Parse-from-file applies to all six runners; a runner
   whose report exceeds the parse cap is FAILED for every tool alike.
3. **No Spanish in `backend/app/analysis/`** (invariant checker): the two
   details are English machine text; the report and the screen word them
   (§5.2, §5.3 rewritten).
4. **The status column stores the member NAME** (`Enum(native_enum=False)`,
   `QUEUED`, not `queued`): every conditional UPDATE compares against the ORM
   member, and a test asserts on the raw stored value — the trap of `0013`
   and phase 8's index.
5. **The finish is conditional too** (security auditor): `run_pipeline`'s
   last write becomes `UPDATE … WHERE id AND status = RUNNING`, and `_enter`
   writes nothing once the row has left RUNNING, so a worker still alive
   cannot turn an `analysis_abandoned` row back into DONE. Test: sweep a
   RUNNING row, let the job end, the row stays abandoned. Same shape as
   `reports/jobs.py::_finish`.
6. **The widened read does not follow a link** (security auditor): `out_dir`
   is writable by the analysis container, where code execution is an
   accepted residual. The report file is opened `O_NOFOLLOW`, `fstat`-ed on
   that descriptor, required to be a regular file within the parse cap, and
   both the stored copy and the parse read from that one descriptor. Test
   with a symlinked report.
7. **Actions gate fails closed** (security auditor): a line mentioning
   `uses` in a shape the strict regex does not match (flow style
   `- {uses: …}`, a quoted key) is refused, not skipped; each pinned SHA is
   taken from the upstream repository's own tag (`git ls-remote`), never a
   fork, and recorded with its tag in a comment.
8. **The sweep builds the path it deletes** from `workspace_root / project /
   analysis` and checks `is_relative_to(workspace_root)`, never from the
   stored `workspace_path`; a notification message is length-bounded before
   it is used to count distinct files.
9. Bitácora: `analysis.abandon` joins `KNOWN_ACTIONS` in
   `frontend/src/screens/audit-screen.tsx` with its sentence.
10. **Two widenings — both TAKEN by `mmarin` 2026-09-28** ("ok si a las
    dos"):
    - **a.** Pin **OSV-Scanner and Syft** by digest too: `analysis.Dockerfile`
      downloads both exactly like Gitleaks (binary + checksum file from the
      same release). Same edit, same test.
    - **b.** Make the pre-phase-10 branch of `extract_upload` ("the jail
      already exists: nothing to do") **refuse** with `UploadMissing`
      instead of analysing whatever tree is there. With the guarded entry it
      is reachable only by a QUEUED row that already has a jail — i.e. a
      partial extraction — and no pre-phase-10 QUEUED row can still exist.

## Verdict

**PROCEED once §7.1–§7.4 are answered.** Every item reuses a shape the
repository already has: the report sweep and its conditional transition
(item 1), the coverage row's detail (item 2), the PHP image's pinned digests
(item 3), the gate's violation list (item 4). Item 5 is a real defect of the
analysis layer, larger than the four it was found beside, and its fix is
small: stop parsing the storage copy.

Signed off by: `mmarin`  date: 2026-09-28
