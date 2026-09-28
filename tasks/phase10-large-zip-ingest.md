# Task: Phase 10 — ZIP ingest up to 1 GiB, with a streamed body cap

> **Status: IN_PROGRESS — built 2026-09-28.** Survey `tasks/phase10-survey.md`,
> signed off by `mmarin` the same day (option C, 8 GiB / 300 000, the
> existing worker, the 1.x contract change accepted). Second cycle, after
> `v1.0.0`. Phase 11 (`tasks/phase11-survey.md`) waits for this one to close.

## Objective
Let the platform ingest a real system shipped as a ZIP of up to 1 GiB
(the one that prompted it: `caracas_sonrie-desarrollo.zip`, 593 MiB,
1.42 GiB unpacked, 21 872 entries) without making the API's pre-auth memory
exposure worse — in fact closing it: the body is read only after
authentication, streamed to disk under the API's own counter, and extracted
by the worker.

## Deliverables
1. `backend/app/ingest/upload.py` (new) — `spool_body` (async, byte-counted,
   `O_EXCL` `0600`, removes its file on any failure, `ClientDisconnect` →
   `UploadInterrupted`), `display_name` (the client's file name as a capped
   label, never a path), `extract_upload` (worker side: the unchanged
   `archive.extract_zip`, spool deleted whatever happens), `too_large`
   (the refusal carrying `context.limit_mib`).
2. `backend/app/projects/router.py` — `POST …/ingest` takes the RAW body
   (`application/zip`, `application/x-zip-compressed`,
   `application/octet-stream`; anything else → 415
   `upload_media_type_unsupported`), the name in `?filename=`, declares no
   body parameter so `IngestUser` resolves first; returns 202 `QUEUED` with
   no languages yet. **1.x contract change**: multipart is refused.
3. `backend/app/ingest/service.py` — `accept_zip` replaces the in-request
   extraction; `backend/app/analysis/pipeline.py` extracts before the
   runners, removes the analysis directory on a refused archive, and the row
   records the typed code.
4. `backend/app/ingest/errors.py` — `UploadTooLarge` (code `zip_too_large`,
   own key with the limit), `UploadMediaTypeUnsupported`,
   `UploadInterrupted`, `UploadMissing`.
5. `backend/app/core/config.py` — 1 GiB / 8 GiB / 300 000.
6. `backend/app/inventory/router.py` — the dump import reads its form AFTER
   `MirrorUser` (same multipart contract; see Deviations).
7. `docker/nginx.conf`, `docker/frontend.Dockerfile`, both Compose files —
   per-route caps from `DIOPTRA_MAX_ZIP_MIB` (1024) and
   `DIOPTRA_VULNDB_MAX_DUMP_MIB` (1025 since addendum A), `proxy_request_buffering off` on the
   ingest route; `.env.example` documents both sides.
8. Frontend — `api/client.ts::apiUploadFile` (XHR, upload progress, nginx's
   HTML 413 read as "too large"), `api/projects.ts::ingestZip`, the progress
   bar and the limit in the refusal on `project-screen.tsx`, the worker's
   failure code explained on the analysis card; locales es/en.
9. Tests — `backend/tests/test_upload_ingest.py` (33),
   `backend/tests/test_upload_caps.py` (3), the migrated call sites in
   `test_projects_api.py` / `test_pipeline.py`, and four new cases in
   `frontend/src/screens/project-screen.test.tsx` over a fake XHR in
   `frontend/src/test/http.ts`.

10. `backend/app/analysis/runners/tools.py::semgrep_budget` — found by the
    walk: `--jobs` and `--max-memory` sized to the runner's container, tested
    in `tests/test_runners.py`.

11. **Analysis progress** (asked by `mmarin` after the walk, 2026-09-28: the
    upload had a bar, the 8-minute analysis did not) — migration
    `0015_analysis_progress` adds `analyses.current_step`; the worker enters
    each step (the acquisition, each tool, the normalisation) with a commit,
    and commits each tool's rows as soon as it ends (they used to wait for the
    whole loop); `analysis/progress.py` turns the step into
    `AnalysisOut.progress = {step, index, total}` while RUNNING; the project
    screen shows "Paso 3 de 8: revisando dependencias vulnerables (OSV)", a
    bar of steps done and "Lleva m:ss". The bar counts STEPS, not time —
    Semgrep was 368 of 499 s on the walk — which is why the step is named and
    the clock shown. Tests: `backend/tests/test_analysis_progress.py` (12,
    one of which reads the row from ANOTHER session while each tool runs, as
    the poll does) and three screen cases. Migration checked on PostgreSQL:
    up, down, up, `alembic check` clean.

12. **From the `/precommit` panel (2026-09-28)**: `metrics._CODE_SIGNAL`
    anchored with `\b` (a hostile tree of 999-character words cost 13.6 s per
    file under the line cap); Starlette's own form errors mapped into
    `{code, message_key}` on the dump import; `semgrep_budget` reads `2gb` /
    `2048MB` and cuts jobs the memory cannot feed; always-mounted `.srlive`
    live regions, the upload bar floored like its number, `.progress.wide`, a
    translatable `%`; a ZIP or git analysis whose enqueue fails is closed as
    FAILED `analysis_enqueue_failed` with a 503 instead of staying QUEUED
    forever (`mmarin`: "sí, sigue así"); tests for every gap the coverage
    adversary proved (receive-count before auth, commit not flush, the
    mid-upload state, the steps-done bar).

13. **Addendum A — the dump import streamed to disk** (`tasks/phase10-survey.md`
    → Addendum A, signed off by `mmarin`, "dale, con 1 GiB"):
    `backend/app/inventory/dump_upload.py` parses the multipart body with
    python-multipart's streaming parser as it arrives — exactly one `file` and
    one `justification`, the reason to memory under its 8 000-character cap,
    the file straight to `<vulndb_spool_dir>/<token>.<kind>` (`O_EXCL`,
    `0600`) under a byte counter; any refusal removes the partial file.
    The addendum's panel added: the cleanup runs synchronously so a
    cancellation cannot skip it (the ZIP spool got the same fix), a body
    without its closing boundary is refused instead of queued truncated, at
    most 8 headers per part, and a database failure on the audit row removes
    the spool too. Its coverage adversary then pinned six more edges (the
    audit row committed before the job exists, an endless justification cut
    at its byte bound, the header count per part, the disposition found in
    any header order, `boundary_of` refusing a non-multipart media type and a
    boundary over 200 bytes — over 256 the parser's own constructor would
    raise outside the typed path). Recorded as defence in depth, not as
    coverage: python-multipart 0.0.32 enforces 8 headers and 4 224 bytes per
    header line itself, so our two header caps never fire first; they stay so
    that a library upgrade that relaxes its defaults cannot relax ours.
    `sync.request_import` became `sync.accept_import` (the audit row and the
    enqueue, byte for byte). Cap 512 MiB → **1 GiB**, nginx 1025 MiB with
    request buffering off. The client contract did not move: every existing
    import test passes unchanged. Tests: `backend/tests/test_dump_upload.py`
    (40), one of which makes Starlette's `SpooledTemporaryFile` fail and was
    checked to catch a route that goes back to `request.form()`.
    Mutation pass on `dump_upload.py` (mutmut 3.8): the first run left 15
    survivors, five of them real edges that became tests (a file exactly at
    the cap, a file arriving in many small pieces, the reason's byte bound
    told apart from the audit's own 4 000-character ceiling by its code, a
    nested spool directory, a file part with no name) plus a name that is not
    UTF-8; the rest are log-only `detail` strings, codec-name spellings,
    `self.part = None` → `""` (only the two real names are ever compared), and
    the header caps' `>` → `>=`, which python-multipart's own 4 224-byte
    header limit enforces first. Test count 28.

## Open, decided by `mmarin` 2026-09-28
- **The dump import's cap is never lowered below the largest dump** —
  lowering it to 200 MiB, the panel's first suggestion, would refuse OSV's npm dump (207 MiB, measured
  that day against the public bucket; PyPI 33, Go 11, Packagist 10, Maven 10,
  RubyGems 5, crates.io 3, NuGet 2; NVD 23–31 MiB per year gzipped).
- **DONE (deliverable 13): an addendum to `tasks/phase10-survey.md`** — stream the dump
  import's multipart form part by part (python-multipart, no new dependency),
  the justification to memory and the file straight to disk, with a 1 GiB
  cap on both sides. Same contract for the client. It closes the last RAM
  residual of the two-host row. Signed off before any code.
- **1.x**: a start-up sweep of `upload.zip` spools whose job never ran.

## Deviations from the survey, recorded
- **The spool lives in the analysis directory** (`<workspace>/<project>/<analysis>/upload.zip`,
  beside `src/` and `out/`) rather than a new `DIOPTRA_DATA_DIR/uploads`
  volume. The API and the worker already share the workspaces volume, the
  operator already sizes it, the runners mount only `src/` so the archive is
  invisible to them, and a refused analysis is cleaned by removing one
  directory. No new mount, no new setting.
- **The dump import keeps multipart** instead of becoming a raw body (§5):
  its written justification (up to 8 000 characters) does not fit a header
  or a query string. The first build read the form after authentication but
  still through the API's RAM `/tmp`; **addendum A** (below) finished it: the
  body is parsed part by part, the file straight to disk.
- **The general `/api/` body cap stays 200 MiB.** No route under it takes an
  upload any more; lowering it is a separate decision.
- **The file name travels in the query string**, not in a header: a header
  cannot carry a name with accents (`código.zip`) from the browser.

## Constraints
- Hard Rules: audited code is hostile (the archive's guards are unchanged and
  still run before anything reads the tree); no new dependency (anyio and
  Starlette are already installed); English in code.
- `archive.py` is not modified.

## Definition of Done
- [x] Survey signed off before any edit
- [x] All deliverables implemented; ruff + mypy + oxlint + `tsc -b` clean
- [x] All tests passing — 1 011 backend (non-sandbox) and 141 frontend,
      2026-09-28, after addendum A and its panel; ruff, mypy, oxlint, `tsc -b` clean
- [x] nginx template renders and `nginx -t` passes in `nginx:alpine`
- [x] Walk: `caracas_sonrie-desarrollo.zip` WHOLE (593 MiB, 21 872 entries)
      through the real template in `nginx:alpine` → the API → a real RQ worker
      on Valkey → the Docker runners, 2026-09-28. Upload: **202 in 1.4 s**
      (loopback), 621 793 525 bytes. Extraction in the worker: ~20 s, 1.5 GiB
      on disk, the spool gone. Whole pipeline: **8 min 19 s**, all six tools
      RAN (Semgrep 368 s, Lizard 75 s, cloc 21 s, OSV 12 s, Gitleaks 10 s,
      Syft 2 s); 800 findings, 783 of them in `node_modules` and 17 in the
      queue; 6 languages, Express + Vue, 4 lockfiles.
      **The walk found a defect, fixed before closing**: the FIRST run had
      Semgrep killed by the kernel (`semgrep-core exited with -9`) — it sized
      its parallelism from the host's 8 cores (7 jobs) inside a 2-CPU, 2 GiB
      container. `runners/tools.py::semgrep_budget` now passes `--jobs` and
      `--max-memory` derived from the runner's limits; re-run alone on the same
      tree it finished in 386 s with 1 034 results, then the second full walk
      above. Recorded as a coverage gap the first time, never a silent pass.
- [x] The same ZIP sent to the API port with no token: **401 in 3 ms with 0
      bytes of the body read**, and nothing written under the workspaces root.
      Through nginx with an expired token: 401 after 851 968 bytes (nginx
      streams, the API refuses at the first read)
- [x] Everything the walk put on disk removed afterwards (`mmarin`,
      2026-09-28): free space 6 785 052 672 bytes before, 6 763 212 800 after;
      the ~22 MB left are the walk's rows in the development database (the
      project `caracas_sonrie-desarrollo (prueba fase 10)`, its two analyses,
      their findings and raw tool outputs), kept until `mmarin` says whether to
      drop them. The development PostgreSQL and Valkey were stopped again, as
      they were found.
- [x] **Found while running the suite, not caused by this phase**: the
      uncommitted phase-1 closing diff declared `metrics._MAX_COMMENT_LINE`
      (a guard against the quadratic comment heuristic) and never applied it,
      so `test_a_huge_comment_line_is_not_code_and_costs_nothing` spun for
      80 minutes — and a hostile tree with one megabyte-long comment would have
      hung the worker the same way. Wired into `_looks_like_code`; the test
      passes in milliseconds.
- [x] Mutation pass on `app/ingest/upload.py` (mutmut 3.8, 2026-09-28; the
      module joined the target list in `pyproject.toml`): first pass 107 of
      128 killed; three survivors were behaviour and became tests (a spool
      opened in a directory that already exists, discarding a directory that
      never existed, a pre-phase-10 row whose jail exists and whose spool does
      not); second pass **115 of 128 killed**. The 13 left, all inspected:
      6 are the log-only `detail` of a typed error (the client sees
      `{code, message_key}`); 2 are `rsplit("/", 1)` → `rsplit("/")` /
      `rsplit("/", 2)`, the same last component; 1 is the write batch's `>=` →
      `>`, the same bytes written; 4 are `missing_ok=True` → `False`/`None` on
      an unlink whose file this very function created and still holds.
- [x] `/precommit` returned `READY TO COMMIT` (2026-09-28, five agents; findings in deliverable 12, the two decisions under "Open")
- [x] The dump-import addendum signed off and built (deliverable 13)
- [ ] Both bars looked at on screen, light and dark
- [ ] CLAUDE.md phase status + `docs/development-phases.md`: Phase 10 → DONE

## Non-goals
- A streamed multipart parser for the dump import (Deviations).
- Resumable or chunked uploads from the browser.
- Anything of phase 11 (sensitive-artefact detection).

## References
- `tasks/phase10-survey.md`; `docs/threat-model.md` → ZIP ingest, the
  two-host residual; `docs/standards-mapping.md` → V12.1;
  `docs/deployment/README.md` → §3, §6, §10 (both halves)
- OWASP ASVS 4.0.3 V12.1, V13.1
