# Task: Phase 8 — The PDF export becomes asynchronous

> **Status: DONE — closed 2026-09-24; built in `a96233a`, the immediate
> feedback and `scripts/dev.sh workers` in `9e21b6d`, the mutation pass in
> `fbc5f64`, the status in the commit that carries this line. Opened
> 2026-09-23 (second cycle). Survey `tasks/phase8-survey.md` signed off by
> `mmarin` the same day (§7.1–§7.5 answered).** Not part of the work plan's P0–P5 roadmap: it answers a freeze
> `mmarin` reported on a real Laravel analysis (516-page PDF, ~50 s).

## Objective
Stop the PDF render from occupying a request and from reading as a frozen
screen. The PDF is produced by a worker job the person can watch from any
screen; the render is **not** faster (survey §2, §7.4) — it is asynchronous
and legible.

## Deliverables

1. **Model + migration** — `backend/app/reports/models.py::ReportJob`,
   `backend/alembic/versions/0014_report_jobs.py`
   - `report_jobs {id, analysis_id → analyses (CASCADE), version (int|null),
     format ('pdf'), status (queued|running|done|errored|expired),
     requested_by_username, requested_by_id, created_at, started_at,
     finished_at, downloaded_at, byte_size, detail}`.
   - **One job in flight per user is a DATABASE rule**: a partial unique index
     on `requested_by_username WHERE status IN ('queued','running')`, so two
     concurrent POSTs cannot both pass a read-then-insert check.
   - No path column: the artefact's name IS the job id (`<uuid>.pdf` in the
     spool), so no stored string ever becomes a filesystem path.

2. **Service** — `backend/app/reports/jobs.py`
   - `request_pdf(db, *, actor, analysis_id, version, source_ip) -> ReportJob`
     — analysis must be DONE, the version must exist when named; refuses a
     second job of the same user (`ReportJobInFlight`, 409, `context.job`);
     audit `report.export.request`; commit, then enqueue. A broker outage
     marks the row ERRORED and raises `ReportEnqueueFailed` (503) rather than
     leaving the person blocked by a job no worker will ever see.
   - `run_report_job(job_id: str)` — the worker entry point. Never raises.
     Refuses a malformed id. **Claims** the job only while fewer than
     `DIOPTRA_MAX_CONCURRENT_REPORT_JOBS` are RUNNING (an advisory lock on
     PostgreSQL serialises the claim); otherwise it re-enqueues itself with a
     delay and stays QUEUED. Renders with the same `engine.render_pdf` call
     the synchronous endpoint used, refuses to write when the spool would
     exceed `DIOPTRA_REPORT_SPOOL_MAX_BYTES` (`errored`, `spool_full`), writes
     `0600`, marks DONE with the size; any failure → ERRORED with a bounded
     `detail` and no stack trace. Audit `report.export` with the outcome.
   - `get_for(db, *, actor, job_id)` — the requester or the admin (§7.2);
     anyone else gets **404**, not 403, so a job id is not an existence
     oracle, and the attempt writes an `authz.denied` row.
   - `take_artefact(db, *, actor, job_id) -> (bytes, filename)` — DONE only
     (`ReportJobNotReady`, 409); reads the file; the caller deletes it once
     the response is sent and the row records `downloaded_at` (§7.3), audit
     `report.export.download`.
   - `sweep(db, settings)` — marks a RUNNING job that started longer ago than
     `DIOPTRA_REPORT_JOB_STALE_MINUTES` ERRORED (`abandoned`: a worker that
     died must not block its requester forever); a QUEUED job whose last
     enqueue (`enqueued_at`) is that old is enqueued AGAIN, and is abandoned
     only after `DIOPTRA_REPORT_JOB_RETENTION_HOURS` (panel decision); expires DONE jobs older than
     `DIOPTRA_REPORT_JOB_RETENTION_HOURS` and deletes their file, and removes
     any spool file older than the stale threshold whose name is not a DONE
     job's (a younger one may be a render a moment away from its row). Run at API start-up
     (§7.3) and at every request, which is cheap and bounds the wait for a
     start-up.
   - `queue_position(db, job)` — how many in-flight jobs were created before
     this one, so the toast can say "en cola, hay N antes" instead of claiming
     work that is not happening (§7.1).

3. **Queue** — `backend/app/core/queue.py`: `REPORT_JOB` is the ONLY entry of
   `REPORT_WORKER_JOBS`, run by `ReportWorkerJob` on the `reports` queue in a
   dedicated `report-worker` service with NO Docker socket; the socket-holding
   `worker` keeps its four `ALLOWED_JOBS` and refuses the render (panel
   decision, `mmarin`). `enqueue_report(job_id, delay_seconds=0)`; the
   argument is a uuid string only, like every other job.

4. **Endpoints** — `backend/app/reports/jobs_router.py`
   | Method | Path | Returns |
   |---|---|---|
   | `POST` | `/api/v1/analyses/{id}/report/jobs` body `{version?}` | 202 `ReportJobOut` |
   | `GET` | `/api/v1/report-jobs/mine` | `ReportJobOut \| null` — the caller's newest unfinished or undownloaded job, so a reload recovers the toast |
   | `GET` | `/api/v1/report-jobs/{job_id}` | `ReportJobOut` (poll) |
   | `GET` | `/api/v1/report-jobs/{job_id}/download` | the PDF bytes, then deleted |
   All three roles (the export row of `docs/roles-and-permissions.md`).
   **1.x contract change**: `GET /api/v1/analyses/{id}/report?format=pdf` now
   refuses with 409 `report_pdf_is_queued`; HTML, Markdown and DOCX stay
   synchronous (sub-second). Keeping the synchronous PDF would leave the
   one-per-user block bypassable by any client and keep a request busy for a
   minute — the block must be the server's, not the screen's.

5. **Settings + Compose** — `DIOPTRA_REPORT_SPOOL_DIR`
   (`/var/lib/dioptra/reports`, shared by the API and the worker like the
   vulndb spool), `DIOPTRA_MAX_CONCURRENT_REPORT_JOBS` (2),
   `DIOPTRA_REPORT_SPOOL_MAX_BYTES` (2 GiB), `DIOPTRA_REPORT_JOB_STALE_MINUTES`
   (30), `DIOPTRA_REPORT_JOB_RETENTION_HOURS` (24).

6. **Frontend**
   - `ReportJobProvider` (`frontend/src/report-jobs/`) inside the
     authenticated tree: asks `mine` on mount, starts a job, polls every 2 s,
     downloads and saves on DONE.
   - The toast (rendered by the provider): fixed bottom-right (§7.5), a
     `role="status"` region on every screen. QUEUED "Tu reporte está en cola"
     (N antes), RUNNING "Estamos preparando tu reporte" + an `aria-hidden`
     elapsed clock, DONE "El reporte está listo. La descarga empezó." then
     closes after ~4 s, ERRORED the reason in plain
     words + "Cerrar". **Not dismissible while queued or running**: it is the
     only handle on a job that blocks the person's next PDF.
   - `PdfExportButton` + its native `<dialog>`, opened by every "Descargar
     PDF" button, saying it can take a few minutes and that no other PDF can be
     started until it finishes; Escape and "Cancelar" close it.
   - Every PDF button is disabled while the person has a job and says why
     next to it — the toast is never the only place that says so.
   - i18n keys in `es.json` and `en.json`; tokens only; both themes.

7. **Tests** — `backend/tests/test_report_jobs.py`,
   `frontend/src/report-jobs/*.test.tsx`, screen tests updated.
   - The whole round trip inline: POST → DONE → download → file gone → a
     second download 409/expired; the three roles may export.
   - One per user: a second POST 409 with the first job's id; another user is
     accepted meanwhile; the partial unique index refuses a direct insert.
   - Ownership: another analyst gets 404 and an `authz.denied` row; the admin
     downloads anyone's.
   - The synchronous PDF refuses; HTML/MD/DOCX still export.
   - Worker: a malformed id is refused; a render failure → ERRORED with no
     file; the cap defers instead of running; a full spool → ERRORED
     `spool_full`; the job argument never reaches a path.
   - Sweep: a stale RUNNING job frees its requester; an old DONE job's file is
     deleted and the row EXPIRED; a stray file is removed.
   - Each worker has its own allowlist: the socket-holding one refuses the
     render, the report worker refuses everything else; the job goes to `reports`.
   - Frontend: the dialog gates the start; the toast states; the buttons
     disabled with their reason; recovery on mount.

## Constraints
- Hard Rules: the handler only enqueues; no request handler renders a PDF;
  deny-by-default roles; typed errors only; no new dependency; English in
  code, Spanish only in locales.
- The render is not claimed faster anywhere (survey §7.4).
- No cache of rendered PDFs (survey §6: sections 7–10 are composed live).

## Definition of Done
- [x] `tasks/phase8-survey.md` signed off before any edit (2026-09-23)
- [x] All deliverables implemented; ruff + mypy + oxlint + `tsc -b` clean (2026-09-23; `mypy app tests` was red at `HEAD` before this diff and is green with it)
- [x] All specified tests passing (pytest full suite; Vitest 112)
- [x] Mutation pass on `app/reports/jobs.py` (phase-close), mutmut 3.8,
      2026-09-24, with `test_report_jobs.py` + `test_queue.py` (both now in
      `[tool.mutmut]`): **708 mutants — 538 killed (76 %) in the first pass,
      598 (84.5 %) after it.** The first pass's survivors were read one by
      one; the behavioural ones became tests, and several were not small:
      `/report-jobs/mine` without its username filter returned ANOTHER
      person's job, `_finish` without its id filter closed EVERY running
      render, an enqueue failure without its id filter errored other people's
      queued jobs, the worker ignored the requested version and — with only two
      versions in any fixture — `history[1]` was indistinguishable from the
      newest, the sweep crashed on a DONE row whose file was already gone, and
      no audit row of the feature had its actor id, role or source IP
      asserted. **The pass also found a test-isolation defect**: the PDF spool
      was ONE directory for the whole session, so a PDF one test left behind
      killed mutants in another; a second pass showed those "kills" as
      survivors. Every test now gets its own spool (autouse fixture in
      `conftest.py`). The 110 survivors left, all classified: 49 log messages,
      14 the `detail` of a typed error (log-only; the client sees
      `{code, message_key}`), 12 the PostgreSQL advisory lock (the SQLite suite
      cannot observe it; exercised on real PostgreSQL during the panel), 11
      typing or ORM no-ops (`cast`, `synchronize_session`), 6 `missing_ok` on a
      path that exists, 5 exact-timestamp boundaries, and 13 more: two
      unreachable (a RUNNING job always has `started_at`; the race branch's
      winner never vanishes), two redundant filters (the ids are already
      QUEUED), two log conditions, two `continue`→`break` whose effect depends
      on directory order, two one-byte / exact-mtime boundaries, the
      one-per-person pre-check (the partial unique index gives the same typed
      409, proven by the lost-race test), and `format` twice (the model's
      default fills it)
- [x] No secrets in diff (Gitleaks clean); locale parity check green
- [x] `/precommit` returned `READY TO COMMIT` (2026-09-23, two rounds: the first raised two decisions — the socket-less report worker and re-enqueue instead of abandon, both `mmarin`'s "lo recomendado" — plus a lost-race 500, sixteen surviving mutants and the live-region defects, all fixed; the second round came back CLEAN / HOLDS)
- [x] Walked on the dev instance with the real worker: the large analysis's
      PDF requested, the toast followed across screens, the file downloaded
      and gone from the spool — confirmed by `mmarin` 2026-09-24 with
      `scripts/dev.sh workers` (`9e21b6d`): a real Valkey and the report
      worker with `ReportWorkerJob`, run on the HOST. That the Compose
      `report-worker` has no Docker socket rests on the allowlist tests and a
      live run of both job classes against Valkey (each refused the other's
      job), not on a Compose walk. The walk also found that the click gave no
      feedback until the server answered — fixed in the same commit
- [x] `docs/{report-format,threat-model,roles-and-permissions,ui-model,standards-mapping}.md`
      and the scope-change log updated
- [x] CLAUDE.md phase status + `docs/development-phases.md`: Phase 8 → DONE
      with date and commit (2026-09-24, `a96233a`, `9e21b6d`, `fbc5f64`)

## Non-goals (explicit)
- A faster render; excluding third-party findings from the report (§7.4, NO).
- Caching a rendered PDF, signed or not (§6).
- Queuing HTML, Markdown or DOCX (sub-second).
- Notifications outside the open browser tab (no mail, no push).
- More than one worker process in Compose: N is the ceiling an operator who
  runs more workers can use, not a promise of parallelism (§7.1).

## References
- `tasks/phase8-survey.md`; `docs/report-format.md` → Behavior;
  `docs/threat-model.md` → the Valkey residual; `docs/ui-model.md` →
  Descargas del reporte
- OWASP ASVS 4.0.3 V4.1 (access control), V7.1 (log content), V12 (files)
