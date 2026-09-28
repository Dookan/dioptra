# Task: Hardening 1.5.1 — recorded debt, and the tool-output cap

> **Status: DONE 2026-09-28 — commit `6e28e8e`, tag `v1.5.1`.** A PATCH
> (1.5.0 → 1.5.1): no endpoint added, no request or response shape changed.
> Survey `tasks/hardening-1.5.1-survey.md`, signed off by `mmarin` the same
> day (§7.1–§7.4 as recommended; the two widenings of §11.10 accepted).

## Objective
Close four debts recorded with a date — orphan `upload.zip` spools, Semgrep's
unread per-file drops, Gitleaks verified against a checksum file from its own
release, and a licence gate blind to GitHub Actions — plus the defect the
survey's read found: the tool-output cap bounded what was PARSED as well as
what was stored, so on a large tree Semgrep's SARIF was cut and lost the SAST
layer and Lizard's CSV was cut and parsed short in silence.

## Deliverables
1. **Parse whole or not at all** — `backend/app/analysis/runners/{executor,base}.py`,
   `backend/app/analysis/pipeline.py`, `backend/app/core/config.py`
   - `read_report(path, store_cap, parse_cap) -> ReportRead | None`: one
     `O_NOFOLLOW | O_NONBLOCK` open, `fstat` on that descriptor, a regular file
     only; the stored copy and the document come from the same read.
   - `ExecutionResult.document` (the whole report) and `.parseable` (never a
     cut copy); `_record` parses `parseable`, and a cut output with no document
     is FAILED `output truncated and not parsed`.
   - `DIOPTRA_MAX_TOOL_PARSE_BYTES` (256 MiB, never below the storage cap); a
     report over it is FAILED `output too large: N MiB > M MiB`, every tool.
   - `read_output` keeps its contract for the sandbox, now through the same
     no-follow read.
2. **Stale analyses and orphan spools** — `backend/app/analysis/sweep.py` (new),
   `pipeline.py`, `ingest/upload.py`, `main.py`, `projects/router.py`
   - `run_pipeline` claims QUEUED → RUNNING and closes RUNNING → DONE/FAILED
     by conditional `UPDATE`; `_enter` is conditional too and raises
     `AnalysisAbandoned` once the row has left RUNNING.
   - `sweep_analyses`: RUNNING past `DIOPTRA_ANALYSIS_STALE_MINUTES` (120,
     floored above the pipeline's RQ timeout by a validator) or QUEUED past
     `DIOPTRA_ANALYSIS_QUEUE_RETENTION_HOURS` (24) → FAILED
     `analysis_abandoned`, `analysis.abandon` by `system`, files removed; an
     aged spool with no row takes its directory, beside a finished row only
     itself. Paths built from ids and checked under the root; uuid-named real
     directories only; never a symlink.
   - Runs at API start-up and before both ingest routes (`sweep_quietly`).
   - `extract_upload` refuses a jail that already exists (`upload_missing`).
3. **Semgrep's drops** — `normalizer.execution_notes`, `pipeline._record`,
   `reports/context.py::tool_detail_text`, `templates/report/strings.json`
   → `tool_detail`, `frontend/src/screens/project-screen.tsx::toolDetail`
   - Counts only (files; syntax / memory / timeout / other), English machine
     text in `tool_runs.detail`, worded by the report and the screen; status
     stays RAN; 10 000 notifications and 2 000 characters per message at most.
4. **Pinned digests** — `docker/analysis.Dockerfile` (Gitleaks, OSV-Scanner,
   Syft), `.github/workflows/ci.yml` (Gitleaks); `backend/tests/test_tool_pins.py`.
5. **Actions in the licence gate** — `scripts/license_gate.py::read_workflow_actions`,
   `.github/action-licenses.json`, the 14 `uses:` of `ci.yml` pinned by commit
   SHA taken from the upstream tags; `scripts/ci.sh` passes `--skip-actions`
   inside the sandbox image.
6. Screens and locales: `errors.analysis.abandoned`, `analysis.toolDetail.*`,
   `audit.action["analysis.abandon"]` (es/en), `KNOWN_ACTIONS`, `FAILURE_KEYS`.
7. Docs: analysis-pipeline, threat-model (ZIP ingest, Analysis containers,
   Supply chain, the Valkey residual), standards-mapping V14.2,
   report-format, ui-model, deployment guide (both halves), CLAUDE.md,
   development-phases, README (both halves). Version 1.5.1 everywhere
   `test_version.py` pins.

## Constraints
- Hard Rules: English in `backend/app/analysis/` (the details are machine text;
  Spanish only in `strings.json` and the locales); free licences only; no
  new dependency.
- No endpoint, no response shape, no enum value added — a PATCH.
- The caracas ZIP is evidence: extracted whole for the acceptance run, never
  trimmed, no photo or dump row opened or printed; everything the run put on
  disk removed afterwards.

## Definition of Done
- [x] Deliverables 1–7 implemented; ruff + mypy (`app`) + oxlint + `tsc -b` clean
- [x] Tests: 1 249 backend (non-sandbox) and 160 frontend, 65 of our own
      checkers (`uv run pytest ../scripts`); new files `test_tool_output.py`
      (19), `test_analysis_sweep.py` (29), `test_execution_notes.py` (15),
      `test_tool_pins.py` (5), and the gate's Actions tests
- [x] **Acceptance on `caracas_sonrie-desarrollo.zip`** (2026-09-28, the
      production `DockerExecutor`, the tree extracted whole by `archive.py`
      in 9 s): Semgrep RAN in 381 s, a 26 156 365-byte SARIF parsed in 0.1 s
      at a 158 MiB peak, **792 findings**, and the note
      `partial: 94 files; syntax=90 memory=3 timeout=3 other=0`; Lizard RAN in
      73 s with a **34 786 914-byte CSV — over the 32 MiB storage cap** —
      stored cut and flagged, parsed whole in 0.8 s at a 340 MiB peak. The cut
      copy, parsed as before, loses **93 of the 5 000 functions** E4 ranks,
      one of them with CCN 1 050, 14 outside `node_modules`. This run's SARIF
      fell UNDER 32 MiB where the stored one of `d3aff904…` did not: the size
      moves between runs with the drops Semgrep makes (3 vs 6 out-of-memory),
      which is exactly why a cap at the edge cannot be the parse limit. The
      256 MiB default is ~7× the largest document measured. Disk: the 1.6 GB
      under `/tmp` removed afterwards; the ZIP untouched
- [x] The three digests checked against the artefacts served on 2026-09-28
      and against the binaries of the image built on 2026-09-21 — identical
- [x] No secrets in diff (Gitleaks); locale parity green (Vitest)
- [x] Mutation pass (mutmut 3.8, 2026-09-28; `sweep.py`, `pipeline.py`,
      `runners/executor.py` and `reports/context.py` joined the target list,
      with the new test files; `test_runners.py` stays out — it fails under
      mutmut's copied tree for layout reasons, as recorded at the P1 close — and
      the pass needs `DIOPTRA_RULES_DIR` pointed at the real `rules/`, or every
      pipeline test sees Semgrep MISSING). Scoped to the functions this batch
      wrote or changed: `sweep.*`, `run_pipeline`, `_close`, `_enter`,
      `_record`, `_rowcount`, `read_report`, `read_output`, `_finish`,
      `execution_notes`, `tool_detail_text`, `extract_upload`. **First pass
      563 killed, 151 survived; second 640 killed, 82 survived**, and one more
      killed by hand after it. What the pass found: **(a) a real defect** —
      `_uuid_dirs` accepted a uuid written without its dashes while the path
      the sweep rebuilds from the id has them, so such a directory was COUNTED
      as removed and left on disk; only the canonical spelling the platform
      writes is taken now; **(b)** the three conditional `UPDATE`s had no test
      that they touch ONLY their own row (dropping `Analysis.id ==` would have
      claimed, stepped or closed every queued or running analysis), nor that
      the sweep's own condition protects a row that finishes between its read
      and its update; **(c)** `_analysis_dir`'s check against a project
      directory that links outside the root; **(d)** a dropped `O_NONBLOCK`
      HUNG the FIFO test instead of failing it, which is how the mutant that
      also drops `O_NOFOLLOW` hid — the test now reads in a thread and fails
      after 5 s; **(e)** long-standing gaps in `_record` and `_finish`: the
      raw row's exit code and stderr, the `output rejected` detail, "exited
      well but wrote no report", the stderr TAIL in a crash's detail, and the
      `pipeline_error` code of a crash had no assertion. All became tests.
      **What survives, all read**: log text and log-only conditions; the
      `detail` of `AnalysisAbandoned` / `UploadMissing` (log-only, the client
      sees the code); `getattr` defaults for `rowcount` and `O_NONBLOCK`,
      which always exist here; cap off-by-ones (`[:41]`, `[:501]`, `65 * 1024`)
      bounded again by the column widths; `read(parse_cap + 2)` and
      `read(None)` — the second changes only memory, not what is returned;
      `duration_ms` scaled by 1001 or divided by 1000; `missing_ok` on a file
      that exists at that moment; `split` maxsplit variants that keep the same
      first line; defaults for a missing descriptor id or message text that
      land in the same bucket
- [x] `/precommit` returned `READY TO COMMIT` (2026-09-28), after the
      panel's findings were applied. **Security** (MINOR): every earlier finding
      (§11.4–§11.10) verified implemented; the parse cap's memory cost was
      undocumented — a parsed SARIF takes ~6× its size (measured: 26 MiB →
      158 MiB peak), so ~1.5 GiB at the default — now in the threat model and
      both halves of the deployment guide; a descriptor leaked if `fstat`
      raised. A `mem_limit` on the `worker` service is left to `mmarin` (a
      deployment change, not this batch). **Invariants** (HOLDS): the
      sandbox's no-follow read added to the Test sandbox row; the screen's
      note now says it does not count files over 2 MB, like the report's;
      the note restricted to Semgrep, whose words it uses (§5.2). **QA**
      (GENUINE): every gate and each behavioural claim shown by execution,
      each test failing when its code is reverted. **Mockup fidelity**
      (DRIFT, copy only): "la salida de la herramienta", never "informe" (a
      reader takes it for the institutional report); "Vuelve a enviar el
      código" (it may have been a repository); a plural for one file.
      **Coverage adversary** (79 hand mutants, 61 killed, 9 real gaps + 1
      frontend, all now tests): a duplicate job message for a RUNNING
      analysis would have run it twice; a declared non-free action passed
      `main`; a short or suffixed SHA passed as a pin; a `.yaml` workflow was
      covered only by the code; an aged symlinked spool; the validators'
      equality edges; the details' end anchors, in both readers
- [x] CLAUDE.md + development-phases: 1.5.1 DONE with the commit hash (`6e28e8e`)

## Non-goals (explicit)
- A cancel button for analyses — its own phase (1.6.0), survey §10
- A new `partial` tool status (§7.2 b) or re-enqueueing a lost QUEUED
  analysis (§7.1 c)
- Listing the files Semgrep skipped by size (not in its SARIF)
- Betterleaks, the informe → reporte sweep, PDF pixel fidelity
- Formatting the pre-existing ruff drift in `scripts/` (not in CI's scope)

## References
- `tasks/hardening-1.5.1-survey.md`; CLAUDE.md → Release rules, Hard Rules
- `docs/threat-model.md` (ZIP ingest, Analysis containers, Supply chain)
- OWASP ASVS 4.0.3 V12.1, V14.2, V11 (a status transition is never overwritten
  once the row has left the expected state)
