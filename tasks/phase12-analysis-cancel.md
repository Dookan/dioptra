# Task: Phase 12 — cancelling an analysis, gracefully

> **Status: DONE 2026-09-28 — the commit hash is recorded here and in
> CLAUDE.md by a follow-up commit.** A MINOR step (1.5.1 → 1.6.0): a new
> endpoint, a new status value, two additive response fields. Survey
> `tasks/phase12-survey.md`, signed off by `mmarin` the same day (§7.1 a,
> §7.2 no written reason, §7.3 a, §7.4 five minutes; the panel's §9 folded
> in).

## Objective
Let the person who sent the code, or an admin, stop an analysis. Graceful, in
`mmarin`'s words: **it is not an error — it has its own status; it stops in
seconds; it never collides with the finish.**

## Deliverables
1. **A stoppable process** — `backend/app/core/process.py`
   - `run_stoppable(argv, *, timeout_seconds, should_stop, cwd, env, on_kill, poll_seconds) -> Stoppable`:
     `Popen` in its own session, waited on in 2 s slices; on a stop the
     `on_kill` hook runs (confirmed or not), then `os.killpg`; `Ending` is
     EXITED / TIMED_OUT / STOPPED. `Stopped` is the control-flow signal of the
     clone and the extraction.
2. **The executor** — `backend/app/analysis/runners/{executor,base}.py`
   - `run_argv(…, should_stop=None)`: without it, `subprocess.run` exactly as
     before (the E7 sandbox is untouched); with it, `run_stoppable`.
   - `ExecutionResult.cancelled` / `.kill_confirmed`; a stopped run is never
     read back. `docker kill` answers whether the container is gone.
   - `build_executor(settings, *, should_stop=None)`.
3. **The acquisition** — `ingest/git_source.py::shallow_clone(…, should_stop)`,
   `ingest/archive.py::extract_zip(…, should_stop)` (every 1 000 entries and
   every 64 MiB written, inside a member too), `ingest/upload.py::extract_upload`.
4. **The pipeline** — `backend/app/analysis/pipeline.py`
   - `_stop_check` (a fresh session per call), `_enter` conditional on no
     cancel pending, `AnalysisCancelled` from a step, a killed run or a
     `Stopped`; `_cancel` deletes the run's coverage rows and raw outputs,
     closes RUNNING → CANCELLED, audits `analysis.cancel` by `system` only if
     its update moved the row, removes the files only when the kill is
     confirmed.
   - `_execute` leaves its last rows uncommitted; `_close` commits them with
     the transition, conditional on RUNNING and no cancel pending, and rolls
     them back when no row moved.
5. **The sweep** — `backend/app/analysis/sweep.py`: CANCELLED is terminal;
   a request older than `DIOPTRA_ANALYSIS_CANCEL_GRACE_MINUTES` (5, ≥ 1) on a
   RUNNING row is closed CANCELLED by `system`; a cancelled row's leftover
   directory is removed once the stale window has passed.
6. **The endpoint** — `backend/app/analysis/{cancel,router}.py`,
   `ingest/errors.py::AnalysisNotCancellable` (409), `projects/schemas.py`
   (`cancel_requested`, `created_by_id`). `POST /api/v1/analyses/{id}/cancel`,
   no body, E2 roles then creator-or-admin, sweeps first.
7. **Data** — `AnalysisStatus.CANCELLED`, `Analysis.cancel_requested_at`,
   migration `0017_analysis_cancel` (status `VARCHAR(8)` → `VARCHAR(16)`;
   the downgrade turns CANCELLED into FAILED `analysis_cancelled`); a CI
   `migrations` step that proves it on PostgreSQL.
8. **Screen** — `frontend/src/components/cancel-analysis.tsx`, the card in
   `project-screen.tsx`, the untoned badge, Bitácora's two actions, locales
   es/en (`analysis.status.cancelled`, `analysis.cancel.*`,
   `errors.analysis.notCancellable`, `audit.action.analysis.cancel*`).
9. **Docs** — CLAUDE.md (Hard Rules → Auth exception, phase status,
   version), analysis-pipeline, threat-model (row + the Valkey residual),
   roles-and-permissions (matrix row, two exceptions), standards-mapping
   (V7.1, V11), ui-model, deployment guide and README (both halves),
   development-phases. Version 1.6.0 in the five places `test_version.py` pins.

## Constraints
- Hard Rules: English in `backend/app/`; free licences, no new dependency;
  the sandbox's `run_argv` path unchanged.
- The API never removes files a worker is using; every status transition is
  conditional; an audit row only from the update that moved the row.

## Definition of Done
- [x] Deliverables 1–9; ruff + mypy (`app tests`) + oxlint + `tsc -b` clean
- [x] Tests: 1 303 backend (non-sandbox) and 170 frontend, all green;
      `test_analysis_cancel.py` (54: the three graceful properties, QUEUED
      and RUNNING, roles, the race of §2.3, the dead worker, the downstream
      refusals, the clone and the extraction, the panel's cases, the stop
      check handed to every stoppable step, the mutation pass's gaps, the
      pipeline's `Stopped` path); frontend nine new cases (the dialog with no
      reason, the running case, a refusal as an error, one request while in
      flight, the announcement and the focus)
- [x] **Stops in seconds, on the real image**: `DockerExecutor` running
      Semgrep from `dioptra-analysis:latest` over a 3 MiB tree, cancelled at
      5 s — asked at 6.0 s, returned at 6.1 s, no `dioptra-semgrep-*`
      container left; the scratch tree removed afterwards
- [x] **PostgreSQL**: on a throwaway `postgres:18-alpine` (removed
      afterwards) — upgrade / downgrade base / upgrade, `alembic check` clean,
      and the new CI step: `CANCELLED` refused under `0016`, accepted after
      `0017`, FAILED `analysis_cancelled` after the downgrade
- [x] Mutation pass (mutmut 3.8, 2026-09-28; `cancel.py` and `core/process.py`
      joined the target list, `test_analysis_cancel.py` the tests), scoped to
      the functions this phase wrote or changed. **The functions written for
      it: 150 survived the first pass; after the tests below, 537
      killed, 45 survived, 1 timeout.** What the pass found: no test that a
      cancel touches ONLY its own row (dropping `Analysis.id ==` from the
      QUEUED, RUNNING or worker update would have cancelled every analysis);
      the audit rows' actor id, role, target and source IP, and the denial's
      outcome, unasserted; the stoppable `run_argv` path's exit code, stderr,
      duration, cwd, timeout and missing-binary results; the stoppable clone's
      success, failure, timeout and environment; the stop check reading a
      vanished or swept row; the poll interval (a one-second slice survived);
      a late cancel on a row the sweep closed. The QA verifier added one more
      class by hand: every pipeline test swallowed the `should_stop` kwarg, so
      deleting the predicate stayed green — now three wiring tests. **What
      survives, all read**: log text and log-only `detail` of typed errors
      (`Forbidden`, `AnalysisNotCancellable`, `AnalysisAbandoned`,
      `RepoUnreachable`, `Stopped`); `getattr(result, "rowcount", …)` defaults,
      always present; `_close` returning False on success (its caller then
      asks for a pending cancel, which cannot exist once the row closed);
      `_stop_reason(None, …)` in `_execute`, which `run_pipeline`'s fallback
      close turns into the same CANCELLED or abandoned outcome (applied by hand
      to confirm); `duration_ms × 1001`; `rmtree(ignore_errors=…)`, which only
      matters when the removal itself fails; `deadline + now` and `>` for `>=`
      in the wait loop, both still bounded by the next slice; the stop check's
      warning text; `_drain`'s fallback after a SIGKILL that never fails to
      reap; `_kill`'s suppression of `ProcessLookupError`, reachable only when
      the group exits between the slice and the kill. The wider scoped set
      (the pre-existing `run_argv`, `_run_process`, `_extract`, `run_pipeline`
      and sweep functions) keeps the survivors recorded at the 1.5.1 close —
      `test_runners.py` stays outside mutmut's copied tree
- [x] `/precommit` returned `READY TO COMMIT` (2026-09-28), after the panel's
      findings were applied. **Security** (MINOR): a stop check that raised —
      the database restarting during a 381 s tool — escaped the wait with the
      process group alive and the container never killed, and the loop IS the
      tool's timeout: now any interruption kills and drains, and a failing
      check keeps waiting under the deadline; the cancelled-trees docstring
      claimed a premise a failed `docker kill` breaks. **Invariants**: a run
      past the stale window with a young cancel could end FAILED
      `analysis_abandoned` (the stale pass now leaves it to the cancel pass),
      and a late worker cancel wiped a failed row's coverage (now only a
      cancelled row loses its rows); the "one exception" wording in the
      roles matrix. **QA** (SMOKE → fixed): every pipeline test swallowed the
      `should_stop` kwarg, so the predicate and its wiring could be deleted
      green — three wiring tests. **Mockup fidelity** (DRIFT, a11y): confirming
      dropped focus to `<body>` (the button unmounts on a queued cancel) and
      the cancelled state was never announced; the dialog said "el código
      subido" for a cloned repository too. **Coverage adversary** (24 hand
      mutants, 20 killed): the running-analysis button, a refusal shown as an
      error and the double-confirm guard became tests; the CANCELLED branch of
      `_clear_spools` was removed rather than tested — it could pull a jail
      from under a container whose kill was not confirmed
- [ ] On-screen look by `mmarin` (pending, his): the untoned badge beside the
      toned ones — neutral or emphasis, in dark mode especially — the dialog
      over the card with Escape and Tab, where focus lands after a cancel, and
      the spacing of the two new `.sub` lines
- [x] CLAUDE.md + development-phases: phase 12 DONE; the hash lands in the
      follow-up commit

## Non-goals (explicit)
- Cancelling an E7 verification run or a PDF job
- Pause / resume: a cancelled analysis is sent again
- Removing a cancelled QUEUED analysis' message from RQ (the claim already
  makes it a no-op)
- Making the LocalExecutor's TIMEOUT path kill the process group (it is the
  pre-existing path; only the stoppable one does)

## References
- `tasks/phase12-survey.md`; CLAUDE.md → Hard Rules → Auth, Release rules
- `docs/threat-model.md` → Analysis cancel; `docs/analysis-pipeline.md`
- OWASP ASVS 4.0.3 V4.1, V7.1, V11, V1.14
