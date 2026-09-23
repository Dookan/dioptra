# Phase 8 survey — the report export becomes asynchronous

> **Status: SURVEY — read-only. Written 2026-09-23. §7.1 and §7.4 answered
> by `mmarin`; §7.2, §7.3 and §7.5 still open, and the Verdict's condition
> (commit phase 7a first) was accepted.**
> Plan-first investigation gate (CLAUDE.md → Agent Behavioral Rules): this
> slice adds a **fifth job to the queue allowlist** — a documented security
> control (`docs/threat-model.md` → the Valkey residual: "a job class that
> refuses every callable except the four allowlisted jobs") — writes a new
> table, adds endpoints and exceeds 200 LOC. No edit to `backend/`,
> `frontend/` or `docker/` before `mmarin` signs the `## Verdict`.
>
> Asked by `mmarin` 2026-09-23, after the PDF of a real Laravel analysis was
> reported as a freeze.

## 1. What is actually wrong

Measured on this host, on the real `otroprevi` analysis (687 findings, 1 369
SBOM components) and on a 1-finding analysis for contrast:

| Report | Findings | Pages | `render()` + `write_pdf()` | Per page |
|---|---|---|---|---|
| certificates | 1 | 6 | 0.6 s | 99 ms |
| otroprevi | 687 | 515 | 45.5 s | 88 ms |
| otroprevi (again) | 687 | 516 | 50.9 s | 99 ms |

Jinja renders the HTML in **0.45 s**; WeasyPrint parses it in **2.1 s**; the
rest is layout and PDF writing. Under cProfile: 70 s of layout, 21 s of
writing. So the split is ~97 % WeasyPrint, ~3 % ours.

**The cost is linear in pages and nothing else.** ~90–99 ms per page, flat
across two orders of magnitude of document size. There is no pathology, no
N² of ours, and nothing in the hot path that we wrote.

The request is not cut off by the proxy — `docker/nginx.conf` already sets
`proxy_read_timeout 600s` on `/api/`. What breaks is the person: the button
gave no feedback (fixed in the working tree as a busy state), and the whole
export occupies a request for a minute.

## 2. Optimisation — what was tried and what it bought

`docs/report-format.md` already names the suspects ("long tables, page
breaks, repeated headers in WeasyPrint"), so those were measured first.

| Attempt | Result |
|---|---|
| `thead { display: table-row-group }` — stop repeating table headers | **48.4 s vs 46.8 s baseline: no gain.** Within the noise. |
| that plus `tr { page-break-inside: auto }` | **51.0 s: no gain.** |

**Negative result, recorded so nobody tries it again**: the CSS constructs the
plan flagged are not the bottleneck. The baseline itself moved between 46.8 s
and 57.9 s across runs on this (loaded) host, which is the scale of the
variance any micro-optimisation would have to beat.

What remains, in order of what it actually buys:

1. **Cache the rendered PDF.** A signed version is immutable by database
   trigger (`docs/threat-model.md` → Report editing), so its PDF can never
   change: render once, store, serve every later download instantly. This is
   the only change that removes the wait rather than hiding it, and it is
   worth more than any renderer tuning. For a DRAFT the key has to include
   what the render depends on, and §6 below argues that is harder than it
   looks.
2. **Fewer pages.** 516 pages because the report prints all 687 findings in
   full — and **422 of those are in `vendor/`**, third-party code the reader
   cannot fix. Excluding third-party paths would roughly halve the document
   AND the time. That is a report-CONTENT decision, not a performance one,
   and it belongs to `mmarin`.
3. **Nothing else.** Rendering cannot be parallelised across pages by us, and
   replacing WeasyPrint is not on the table (CLAUDE.md → Analysis Tool Source
   Authority).

## 3. What exists to build on

- **The queue.** `app/core/queue.py` has `enqueue_pipeline`, `enqueue_verification`,
  `enqueue_sync`, `enqueue_import` and `ALLOWED_JOBS`, a frozenset the job
  class checks before it will resolve any callable. The pattern to copy is the
  inventory sync (P5): the handler audits the request, returns 202 and
  enqueues; the worker does the work and writes its own audit row; no request
  handler performs the slow operation.
- **A spool directory** already exists as a settings-driven path for the
  vulnerability dump (`DIOPTRA_VULNDB_SPOOL_DIR`), so a per-deployment
  directory for generated reports is an established shape, not a new one.
- **The export itself** is one function, `analysis/router.py::get_report`,
  which calls `reports/engine.render_{pdf,html,markdown,docx}`. Only the PDF
  is slow; HTML is 0.5 s and Markdown and DOCX are comparable. **Only the PDF
  needs the queue**, and keeping the other three synchronous keeps the change
  small.
- **The frontend** has `AuthProvider` as its only context provider, wrapped
  around `App` in `main.tsx`; `AppShell` renders the appbar, the tabs bar,
  `main` and the status bar on every screen. There is **no modal component and
  no toast component yet** — the date picker's popover is the closest thing.

## 4. The shape `mmarin` asked for

1. Clicking "Descargar PDF" opens a **modal** that says, in plain words, that
   it can take a few minutes and that no other PDF can be generated until
   this one is done.
2. On confirming, the job is enqueued and an **unobtrusive item, visible on
   every screen**, says the report is being prepared.
3. When it finishes the item says it is ready, closes itself, and the
   download starts.
4. While a PDF job is running, **PDF generation is blocked**.

## 5. Design pseudocode

### 5.1 Server

```
table report_jobs
    id, analysis_id (FK), version (int|null), format ('pdf')
    status: QUEUED | RUNNING | DONE | ERRORED
    requested_by_username, created_at, started_at, finished_at
    artifact_path (str|null)   -- inside DIOPTRA_REPORT_SPOOL_DIR, name = id
    byte_size (int|null), detail (str|null)

POST /api/v1/analyses/{id}/report/jobs      -> 202 {job}
    role: the export row of docs/roles-and-permissions.md (all three roles)
    refuses with a typed error when ANY job is QUEUED or RUNNING  ..... §7.1
    audit row report.export.request
    enqueue_report(job_id)

GET  /api/v1/report-jobs/{job_id}           -> {job}      (poll)
GET  /api/v1/report-jobs/{job_id}/download  -> the bytes, DONE only
    the caller must be the requester or an admin ................... §7.2

worker: run_report_job(job_id)
    mark RUNNING
    render_pdf(...)                  # the same engine call as today
    write to spool as <job_id>.pdf, chmod 0600
    mark DONE with size; on any error mark ERRORED with a bounded detail
    audit row report.export
```

The job argument is a **uuid only**, like every other job — the broker can
therefore ask for nothing but an existing job row (`docs/threat-model.md` →
the Valkey residual keeps holding).

### 5.2 Client

```
ReportJobProvider (above AppShell, beside AuthProvider)
    state: job | null
    start(analysisId, version)  -> POST, then poll GET every 2 s
    on DONE   -> fetch the download, save it, show "listo", close after ~4 s
    on ERRORED-> keep the item with a plain-words message and a dismiss

AppShell renders <ReportJobBanner/> under the tabs bar on EVERY screen:
    QUEUED/RUNNING: "Estamos preparando el informe…" + elapsed, no spinner
                    that steals focus, role="status", dismissible? NO — it is
                    the only handle on a job that blocks the others
    DONE          : "El informe está listo. La descarga empezó."
    ERRORED       : the reason, plain words, and a way to try again

project-screen: the PDF button opens <ConfirmExportDialog/> (a native
<dialog>, focus-trapped, Escape closes) before starting; while a job exists
every PDF button in the app is disabled and says so.
```

## 6. What I do NOT yet know, and would have to settle while building

- **Caching a DRAFT's PDF is not safe by content hash alone.** Sections 7–10
  are composed LIVE from the workflow rows and the vulnerability mirror
  (`docs/report-format.md` → Behavior, the recorded P5 limit): the same
  signed version exported after a later verification run or a mirror sync
  legitimately differs. So a cache key would have to cover the analysis, the
  version, every verification run, the plan, the designs, the test files, the
  SBOM and the mirror's last-sync date — or the cache has to be **only for
  signed versions of sections 1–6**, which is not what an export returns.
  **Recommendation: no cache in this phase.** Land the queue first; a cache
  is a separate decision with its own invalidation surface.
- Whether the job should be **per (analysis, version, format)** or global. §7.1.
- Whether a job that outlives the browser session (the user navigates away,
  logs out, comes back) must be recoverable — I think yes, and that means
  the provider asks for "my unfinished jobs" on mount, which is one more
  endpoint.

## 7. Decisions for `mmarin` — none of these are mine

1. **What exactly is blocked → ANSWERED by `mmarin`, 2026-09-23: one job
   per USER, plus a deployment cap of N.** So a person may have one PDF job
   in flight and no more, and the installation runs at most
   `DIOPTRA_MAX_CONCURRENT_REPORT_JOBS` of them at once.

   **The honest part, which the UI must carry**: the Compose stack runs ONE
   worker process, so whatever N is, exactly one job is RUNNING at any moment
   and the rest sit QUEUED. N is therefore not a promise of parallelism — it
   is the ceiling an operator who runs more workers gets to use. The banner
   must distinguish the two states in plain words ("Tu informe está en cola,
   hay N antes" vs "Estamos preparando tu informe") so the screen never
   claims work that is not happening. A second request from the SAME user is
   refused with a typed error naming their job in flight; a request that
   would exceed N is ACCEPTED and waits, because refusing it would punish a
   person for someone else's export.
2. **Who may download a finished job.** Recommendation: the requester or the
   admin. The report itself is downloadable by all three roles today, so this
   is about not handing one person's spooled artefact to another.
3. **How long a finished PDF lives on disk**, and what removes it. There is no
   retention job in the platform and `docs/standards-mapping.md` → V8 already
   records "no data-retention schedule for old analyses" as a gap.
   Recommendation: delete on successful download, plus a cap on the spool
   directory and a start-up sweep of jobs older than N hours.
4. **Whether the report should exclude third-party paths → ANSWERED by
   `mmarin`, 2026-09-23: NO.** The institutional report keeps printing every
   finding of the audited tree, `vendor/` included. Recorded consequence: the
   only lever this survey found on render TIME is therefore not taken, and a
   516-page report stays a ~50 s render. This phase makes that wait
   asynchronous and legible; it does not shorten it, and nothing in it should
   be described as making the PDF faster.
5. **Where the banner lives**: under the tabs bar (my recommendation, it is
   the one strip present on every screen and it pushes nothing around) or
   floating bottom-right as a toast (less intrusive, but easier to miss, and
   this one has to be noticed because it blocks other exports).

## 8. Estimate

| Block | Size |
|---|---|
| model + migration + settings (spool dir, cap) | ~120 LOC |
| queue job + allowlist entry + worker function | ~120 LOC |
| three endpoints + schemas + typed errors + audit rows | ~200 LOC |
| provider + banner + modal + wiring into AppShell | ~250 LOC |
| locales (es/en), tokens for the banner | ~40 lines |
| tests: role denial, the block, the poll, the download, the modal, the banner on every screen | ~350 LOC |
| docs: ui-model, report-format, threat-model (the new spool + the fifth job), roles, development-phases | — |

Not a one-sitting job, and it lands on top of an already large uncommitted
phase-7a diff — see the Verdict.

## Verdict

**PROCEED once §7.2, §7.3 and §7.5 are answered** (§7.1 and §7.4 are now
settled above), and with one condition that is not about this feature:

**Commit phase 7a first.** The working tree already carries 44 modified and
36 new files from the PHP wave, the mutation gap and the SARIF severity fix.
Adding ~1 000 more lines on top gives the precommit panel one diff nobody can
review honestly, and the SARIF severity fix in particular deserves its own
review — it changes the severity of every finding the platform has ever
produced. Recommendation: run `/precommit` on what exists, commit it, then
build this.

On the feature itself the design holds: the queue, the audit pattern and the
"handler only enqueues" rule are all established here, and only the PDF needs
any of it. The honest part is §2 — **this phase does not make the PDF faster.**
It stops it blocking a request and tells the person what is happening. The
only real speed lever found is printing fewer pages, and that is §7.4.

Signed off by: ______________  date: __________
