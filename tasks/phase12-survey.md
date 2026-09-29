# Phase 12 survey — cancelling an analysis, gracefully (1.6.0)

> **Status: SIGNED OFF 2026-09-28 by `mmarin`** — §7.1 (a), §7.2 **(b), no
> written reason**, §7.3 (a), §7.4 (5 minutes); and "graceful" DEFINED by him
> as three properties (§1). Written
> read-only, before any edit, as the plan-first investigation gate requires:
> it touches the INGEST surface (extraction and clone get a stop hook), the
> pipeline's state machine and the analysis executor (CLAUDE.md → Agent
> Behavioral Rules), and exceeds 200 LOC. No edit to `backend/`, `frontend/`
> or `docker/` before the `## Verdict` is signed.
>
> Asked by `mmarin` while reading the 1.5.1 survey (§10 there), with one
> requirement given on 2026-09-28: **"1.6 debe ser gracefully cuando se
> cancela"** — the cancel must be graceful. §1 says what that means here,
> and every part of the design is measured against it.
>
> Under the version scheme this is a MINOR step: **1.5.1 → 1.6.0** — a new
> endpoint, a new status value in `AnalysisOut.status`, and one additive
> field. No existing request or response changes shape.

## 1. What "graceful" means, concretely

**`mmarin`'s definition (2026-09-28): it is not an error — it has its own
status; it stops in seconds; it never collides with the finish.** Those are
properties 4, 1 and 5 below and they are the acceptance of this phase. The
other three follow from his answers to §7 (the partial rows are deleted, a
dead worker is covered) and from not racing the worker for its files.

1. **It stops promptly.** Seconds, not "after the current tool": Semgrep ran
   381 s on `caracas_sonrie-desarrollo.zip` (1.5.1 acceptance), so a cancel
   checked only between steps could take six minutes to take effect. The
   running container is killed, a clone is killed, an extraction stops.
2. **The worker closes its own work.** The API only RECORDS the request on a
   running analysis; the worker notices, stops its tool, removes its files and
   makes the transition. The API never deletes a jail a worker is reading or
   writing, and never races it for the row.
3. **It leaves nothing behind.** No jail, spool, `out/` or staged rules on
   disk; no finding, SBOM, metrics or CBOM row; the analysis row stays, marked
   CANCELLED, and the trail says who and when (no written reason, §7.2).
4. **It is not a failure.** Its own status, not FAILED; the tool killed by the
   cancel is not recorded as a TIMEOUT or FAILED coverage gap; the card reads
   as a decision the person took, not as an error.
5. **It never collides with the finish.** A cancel that arrives while the
   worker writes the results either wins (nothing is written) or loses (the
   analysis is DONE and the request is refused) — never both, never half.
6. **It survives a dead worker.** A cancel requested on a RUNNING row whose
   worker already died does not wait for the 120-minute stale window: the
   sweep closes it after a short grace.

## 2. What the read found

### 2.1 Nothing can interrupt a tool today

`runners/executor.py::run_argv` calls `subprocess.run(…, timeout=600)`: the
worker is blocked inside it until the tool ends or times out. The only
interruption point is `pipeline._enter`, between steps, and it raises
`AnalysisAbandoned` only once the ROW has left RUNNING — which a cancel must
not do while the worker still holds files (§1.2). The named container and the
`docker kill` hook already exist for the timeout (P1): cancelling reuses that
kill, only the trigger is new.

`ingest/git_source.py::shallow_clone` has the same `subprocess.run` shape
(timeout `DIOPTRA_GIT_CLONE_TIMEOUT_SECONDS`), and
`ingest/archive.py::_extract` loops over `infolist()` with no hook — 9 s on
caracas, up to minutes on an 8 GiB tree.

### 2.2 The status column cannot hold `CANCELLED` — on PostgreSQL only

`AnalysisStatus` is stored as the member NAME in `_text_enum(AnalysisStatus,
8)` — `VARCHAR(8)`. `CANCELLED` is **nine** characters. PostgreSQL refuses it
with a `DataError` (a 500); **SQLite, which the test suite uses, does not
enforce the length and would pass every test**. The migration widens the
column (to 16) and a step of the CI `migrations` job writes a `CANCELLED` row
on real PostgreSQL — the `0013`/`0016` lesson: only a real database proves a
stored literal.

### 2.3 The finish is two transactions

`_execute` inserts findings, SBOM, CBOM and metrics and COMMITS; then
`run_pipeline` calls `_close` (RUNNING → DONE) and commits again. Between the
two, a cancel could flip the row and leave a CANCELLED analysis with a full
set of findings (§1.5 broken). The final write and the DONE transition must be
ONE transaction, closed by a conditional `UPDATE` that also requires "no
cancel requested"; if it touches no row, the whole transaction rolls back.

### 2.4 What already refuses a non-DONE analysis

Every downstream reader already checks `status is DONE`: `gates.leave_code`
(E2 → E3), `GET …/report` (`AnalysisNotReady`), the PDF job. So a CANCELLED
analysis can never be triaged, advanced or exported with no change there — to
be pinned by a test each, not assumed.

### 2.5 The sweep treats DONE and FAILED as terminal

`sweep.py::TERMINAL` must learn CANCELLED, or an orphan spool beside a
cancelled row is never cleared; and unlike DONE, a cancelled analysis owns no
jail worth keeping, so the sweep removes its whole directory.

## 3. Design

### 3.1 Data

```
migration 0017_analysis_cancel:
    analyses.status          VARCHAR(8) → VARCHAR(16)
    analyses.cancel_requested_at  timestamptz NULL   -- what the worker polls
AnalysisStatus.CANCELLED = "cancelled"
AnalysisOut.cancel_requested: bool                   -- additive
```

### 3.2 Endpoint

```
POST /api/v1/analyses/{id}/cancel   (no body)   -> 202 AnalysisOut
    role: the analysis' creator (analyses.created_by_id) while they still
          hold an E2 role (analyst or admin — a creator since demoted to
          developer may not), or an admin; a NULL creator leaves the admin
          only; anyone else → 403 + authz.denied
    NO written reason (§7.2, CLAUDE.md → Hard Rules → Auth, the second
    recorded exception): the row names who and when, and cancelling
    loses nothing that re-sending the code does not restore
    audit "analysis.cancel.request" (actor, target id, justification None)
    QUEUED  → conditional UPDATE … WHERE status = QUEUED
                 SET status = CANCELLED, finished_at, cancel_requested_at
              remove its directory (only a spool: no worker has it)
              audit "analysis.cancel" by the actor
              (its RQ message stays; the claim finds the row not QUEUED — 1.5.1)
    RUNNING → conditional UPDATE … WHERE status = RUNNING
                 AND cancel_requested_at IS NULL  SET cancel_requested_at = now
              (a second request is a no-op answer, not a second row)
    DONE / FAILED / CANCELLED → 409 analysis_not_cancellable
    if both conditional updates touch nothing (the row moved between the
    read and the write), answer from the row as it now is
```

### 3.3 Worker — the stop hook

```
should_stop(analysis_id) -> bool
    # a NEW short session each call: the job's own session holds its rows
    SELECT cancel_requested_at IS NOT NULL OR status <> RUNNING …

run_argv(argv, …, should_stop=None, poll_seconds=2):
    Popen; loop communicate(timeout=poll_seconds):
        on TimeoutExpired: if should_stop(): on_timeout() (docker kill the
            named container) or kill the local process; drain; return
            ProcessOutcome(status=None, cancelled=True)
        the overall timeout keeps its meaning (TIMEOUT)
    # the E7 sandbox calls run_argv with should_stop=None: unchanged

shallow_clone(…, should_stop=None)      same loop
extract_zip(…, should_stop=None)        checked every 1 000 entries or 64 MiB
                                        written; raises a private Stop that
                                        the jail's existing cleanup already
                                        handles (`archive.py` removes the jail
                                        on any failure)
```

`AnalysisCancelled(AppError)` is raised by `_enter`, by a runner that came
back cancelled, and by the clone/extraction; `run_pipeline` catches it:

```
except AnalysisCancelled:
    db.rollback()
    delete this analysis' tool_runs and raw_tool_outputs        # §7.3
    remove workspace.parent (spool, jail, out, rules)
    closed = conditional UPDATE … WHERE status = RUNNING
        SET status = CANCELLED, current_step NULL, finished_at
    if closed.rowcount == 1: audit "analysis.cancel" by system
    # the sweep may have closed it after the grace: no second row. The same
    # rule holds in the sweep and in the API's QUEUED path — an audit row is
    # written only by the update that actually moved the row.
```

A killed tool writes NO `ToolRun` row (§1.4): the cancel is checked before
`_record`, so a tool the cancel killed never reads as a coverage gap.

### 3.4 The finish, in one transaction

```
_execute no longer commits its last write; run_pipeline:
    findings, sbom, cbom, metrics added to the session
    closed = UPDATE … WHERE id AND status = RUNNING AND cancel_requested_at IS NULL
                SET status = DONE, current_step NULL, finished_at
    if closed.rowcount == 0: rollback → the cancel (or the sweep) won
    else: commit                                  # results and DONE together
```

The FAILED path keeps its conditional close; a failure that races a cancel
lands as CANCELLED if the request was first (the person asked to stop; the
error is moot).

### 3.5 Sweep

```
TERMINAL gains CANCELLED; a CANCELLED row's directory is removed whole.
RUNNING with cancel_requested_at older than DIOPTRA_ANALYSIS_CANCEL_GRACE_MINUTES
    (default 5; a live worker notices within ~2 s plus a docker kill, ≤ 30 s)
    → CANCELLED by system, files removed, audit "analysis.cancel".
```

### 3.6 Screen (mockup 03, the analysis card)

- While QUEUED or RUNNING, for the roles of §7.1: a secondary button
  **"Cancelar el análisis"** that opens a native `<dialog>` (the PDF dialog's
  pattern) with ONE sentence on what happens ("Se detiene la herramienta que
  está corriendo y se borra el código subido; el análisis queda como
  cancelado") and "Cancelar el análisis" / "Volver" — no reason field, no
  second step (§7.2: fast, no friction). The dialog is the only guard against
  a mis-click on a run that may have taken ten minutes; it is one click.
- Requested: the card says **"Cancelando… la herramienta en curso se detiene
  en unos segundos"** in its `.srlive` region, the button disabled, the bar
  frozen at its step.
- Cancelled: a neutral line, not `.alert`: **"Cancelaste este análisis"** (or
  "Se canceló este análisis" for another reader) with the date; "Vuelve a
  enviar el código cuando quieras." Bitácora words `analysis.cancel.request`
  and `analysis.cancel`.
- The report sections that list tool coverage never see a cancelled analysis
  (§2.4).

## 4. Tests (graceful first)

- **Prompt**: a fake tool that sleeps 60 s; a cancel mid-run returns in under
  5 s, the named container (`docker kill` fake) or the local process is dead,
  the row is CANCELLED, no `ToolRun` for that tool.
- **Clean**: after a cancel at every step (acquire ZIP, acquire git, each tool,
  normalize) the analysis directory does not exist and no finding, SBOM,
  metrics, CBOM, tool run or raw output row remains (§7.3 a).
- **The race of §2.3**: the request lands between the findings' insert and
  the close → nothing written, CANCELLED; the request after DONE → 409.
- **QUEUED**: cancelled by the API at once; the later job message is a no-op.
- **Dead worker**: RUNNING + an aged `cancel_requested_at`, no worker → the
  sweep closes it CANCELLED by `system`; a young one is untouched.
- **Roles**: the creator and an admin may cancel; any other analyst, a
  developer, and the admin's own role check each write `authz.denied`; the
  request takes no body and its audit row carries no justification; a second
  request writes no second row; a creator demoted to developer is refused; a
  worker and the sweep closing the same row write ONE `analysis.cancel`.
- **Downstream**: stage advance, report HTML/MD/DOCX, the PDF job, triage all
  refuse a CANCELLED analysis.
- **PostgreSQL**: the CI `migrations` job writes `CANCELLED` into the widened
  column (§2.2).
- **Sandbox untouched**: `run_argv` without `should_stop` behaves exactly as
  today (the E7 suite, plus one live run).
- Frontend: the dialog, the requested state, the cancelled line in both
  locales, the button hidden from roles that may not cancel.

Mutation pass on the new pipeline paths, `run_argv`'s loop and the sweep
addition at close.

## 5. Threat model delta

- A new state-changing endpoint on an analysis: deny by default, audit rows
  with actor and time (no written reason, §7.2), conditional transitions
  (V4.1, V7.1, V11).
- Nothing new is read from the audited tree. The stop hook only KILLS; the
  kill of a named container is the P1 timeout's own path.
- Only the creator or an admin can cancel (§7.1 a); an admin cancelling
  someone's analysis is on the trail; nothing is lost that re-sending the code
  does not restore.
- The Valkey residual is unchanged: a broker write cannot cancel (the cancel
  is a database write by an authenticated person) and cannot un-cancel (the
  claim requires QUEUED).

## 6. What stays out

- Cancelling an E7 verification run or a PDF job (their own jobs, their own
  timeouts).
- A "pause / resume": a cancelled analysis is re-sent, never resumed.
- Removing the RQ message of a cancelled QUEUED analysis from the queue: the
  1.5.1 claim already makes it a no-op, and reaching into RQ's structures
  from the API is a new broker write for no gain.

## 7. Decisions for `mmarin`

1. **Who may cancel.** **(a) Recommended**: whoever sent the code
   (`analyses.created_by_id`) or an admin — the 1.5.1 survey's §10 proposal.
   **(b)** Any analyst or admin (the E2 roles), since the factory's analysts
   share projects.
2. **Written reason.** **(a) Recommended**: required, ten characters, like
   every other action that discards work (CLAUDE.md → Hard Rules → Auth).
   **(b)** None at all: the request carries no body.
3. **The partial rows of a running analysis.** **(a) Recommended**: deleted
   with the files — the coverage rows and raw outputs of the tools that ran
   before the cancel (a raw output can be 32 MiB); the analysis row and the
   two audit rows remain, which is the whole story. **(b)** Kept, and the
   cancelled card lists which tools had run.
4. **Grace for a dead worker** (§3.5): 5 minutes as the default, floored at 1.

**Taken by `mmarin` 2026-09-28**: §7.1 **(a)** the creator or an admin;
§7.2 **(b)** no written reason — "tiene que ser rápido sin trabas" — written
into CLAUDE.md → Hard Rules → Auth as the second recorded exception, beside
account creation, before any code; §7.3 **(a)** the partial rows deleted;
§7.4 **5 minutes**.

## 8. Estimate

| Block | Size |
|---|---|
| migration + model + schema + endpoint + typed errors + audit | ~180 LOC |
| `run_argv` poll loop, clone and extraction hooks | ~120 LOC |
| pipeline cancel path + single-transaction finish | ~120 LOC |
| sweep addition + setting | ~50 LOC |
| frontend: button, dialog, states, Bitácora, locales es/en | ~220 LOC |
| tests (§4) | ~450 LOC |
| docs: the "one exception" sentences in `docs/roles-and-permissions.md` (Rules) and `docs/standards-mapping.md` (V7.1) become two, and the matrix gains "Cancel an analysis (creator or admin)"; analysis-pipeline, threat-model, roles-and-permissions, ui-model, standards-mapping, development-phases, CLAUDE.md, README and the deployment guide (both halves, the new setting) | — |

## 9. Precommit panel on this survey (2026-09-28) — folded in

Applied to the design above or stated here, before any code:

1. **The sweep is not on a timer** (security auditor): it runs at API
   start-up and before each ingest, so a dead worker's cancel would read
   "Cancelando…" until the next ingest. The cancel handler calls
   `sweep_quietly` first, like both ingest routes; a second click after the
   grace closes the row. §1.6's "5 minutes" means "at the first cancel or
   ingest request after 5 minutes", and the screen keeps the button enabled
   in the requested state for exactly that reason.
2. **A demoted creator may not cancel** (security auditor, invariant
   checker): the route keeps `IngestUser` (analyst or admin) and adds
   creator-or-admin on top (§3.2 updated).
3. **The kill reaches the whole process tree and ends before the files go**
   (security auditor): local processes and `git` start with
   `start_new_session=True` and are killed with `os.killpg` (`git` leaves
   `git-remote-https` writing otherwise; the LocalExecutor, `semgrep-core`);
   after `docker kill` the worker waits, bounded, for the client to exit, and
   if it has not, leaves the directory to the sweep rather than removing it
   under a live mount.
4. **Audit rows only from the update that moved the row** (both): the
   request row `analysis.cancel.request` is written only when one of the
   conditional updates changed a row — never on the 409, never twice; the
   closing `analysis.cancel` likewise in the worker, the sweep and the QUEUED
   path. "Answer from the row as it now is" is a refreshing read
   (`populate_existing`, the phase-6 lesson).
5. **The gitleaks history run** (security auditor): `ExecutionResult` carries
   `cancelled`, and `AnalysisCancelled` is raised before `_record` and before
   the history spec starts, so no killed tool gets a coverage row and no
   history scan runs after a cancel.
6. **The QUEUED path's directory** is built by `sweep._analysis_dir`
   (`workspace_root / project / analysis`, checked with `is_relative_to`),
   never from the stored `workspace_path` — the 1.5.1 §11.8 rule.
7. **The conditional updates compare against the ORM member**, never a raw
   `'running'` literal: the column stores the NAME (the `0013` trap).
8. **The normalise step has no poll**: a cancel during it lands at the final
   conditional update and rolls everything back — correct, and bounded by the
   step's own seconds.
9. **Docs owed at the build**: the "one exception" sentences of
   `docs/roles-and-permissions.md` and `docs/standards-mapping.md` (V7.1),
   the matrix row, and a `tasks/phase12-*.md` with its Definition of Done and
   Non-goals.

## Verdict

**PROCEED** (§7 answered).

Graceful is reachable with shapes the repository already has: the named
container and its kill hook (P1's timeout), conditional transitions (1.5.1),
the sweep (1.5.1), the enqueue-and-let-the-worker-act pattern (the vulndb
import). Two things the read found would have broken it silently: the status
column is one character too short for `CANCELLED` on PostgreSQL only (§2.2),
and the finish is two transactions, so a cancel could land between the
results and DONE (§2.3). Both are designed out above.

Signed off by: `mmarin`  date: 2026-09-28
