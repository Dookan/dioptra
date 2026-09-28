# Phase 10 survey — ZIP ingest up to 1 GiB, with a streamed body cap

> **Status: SIGNED OFF 2026-09-28 by `mmarin`** ("cerramos y pasamos a
> esto", given after the recommended answers to §7.1–§7.4 were put to him) —
> option C, 8 GiB / 300 000 entries, the existing worker, the 1.x contract
> change accepted; §7.5 answered by freeing space on this host (8.6 GB free).
> Written
> read-only, before any edit, as the plan-first investigation gate requires:
> this slice touches the INGEST surface (CLAUDE.md → Agent Behavioral Rules)
> and, done properly, exceeds 200 LOC. No edit to `backend/`, `frontend/` or
> `docker/` before the `## Verdict` is signed.
>
> Asked by `mmarin` 2026-09-28: a real system ships as a ZIP of more than
> 500 MB and the platform refuses it. Target chosen in session: **1 GiB
> compressed**. The same slice absorbs the item `mmarin` left as "next" on
> 2026-09-24 — an app-level streamed body cap on the upload routes
> (`docs/threat-model.md` → the two-host residual).

## 1. Why a 500 MB ZIP is refused today

Four limits in series. The first one hit decides the refusal.

| # | Limit | Value | Where | Configurable |
|---|---|---|---|---|
| 1 | nginx body cap on `/api/` | 200 MiB | `docker/nginx.conf:38` | **no** — a literal in the template |
| 2 | ZIP size, declared `Content-Length` + `UploadFile.size` | 200 MiB | `core/config.py:61` (`DIOPTRA_MAX_ZIP_BYTES`), `projects/router.py:111`, `ingest/service.py:106` | yes |
| 3 | API `/tmp`, where Starlette spools the multipart body | 512 MiB **RAM** | `docker/docker-compose.yml:98` | Compose edit |
| 4 | Unpacked total, declared and streamed | 1 GiB | `core/config.py:62` (`DIOPTRA_MAX_UNPACKED_BYTES`) | yes |

Also in play: `max_zip_entries` 50 000 and `max_zip_ratio` 100:1
(`core/config.py:63–64`), and nginx's `proxy_read_timeout 600s`.

In development (`scripts/dev.sh`, uvicorn on 127.0.0.1 with no nginx) only
limits 2 and 4 apply. Behind Compose, nginx answers 413 first.

Raising limit 2 to 1 GiB **alone does not work**, and trying it is what this
survey exists to prevent:

- limit 1 refuses at 200 MiB before the API sees a byte;
- limit 3 cannot hold even one 1 GiB spool, it is RAM, and on the two-host
  topology it is filled BEFORE authentication (§2.1);
- limit 4 refuses almost any real 1 GiB archive, since source code
  compresses 3–10×, so a 1 GiB ZIP typically unpacks to 3–10 GiB;
- limit 50 000 entries refuses almost any tree of that size that carries
  `node_modules/` or `vendor/`.

## 2. What the read found, beyond the numbers

### 2.1 The body is spooled before the caller is authenticated

`ingest_zip` declares `file: UploadFile = File()`. FastAPI parses the
multipart body while it solves the endpoint's parameters, so Starlette has
already written the whole body to `/tmp` (a `SpooledTemporaryFile` that rolls
to disk after 1 MB, and here "disk" is the RAM tmpfs) by the time
`IngestUser` could refuse an anonymous caller. The only pre-body check is the
DECLARED `Content-Length`, which a chunked body omits. This is exactly the
residual recorded on 2026-09-24. At 200 MiB behind nginx it is bounded; at
1 GiB it is not something a RAM tmpfs can bound.

### 2.2 Extraction and detection run inside the request

`ingest/service.py::ingest_zip` extracts into the jail, walks the tree for
detection, writes the audit row and commits, all in the HTTP request, with a
database transaction open since the `Analysis` row was flushed. For 200 MiB
this took seconds. For 1 GiB compressed / several GiB unpacked on a slow disk
it can take minutes. That means a transaction held open for minutes, an HTTP
request that nginx cuts at 600 s, and a browser showing nothing: `apiUpload`
uses `fetch`, which reports no upload progress.

### 2.3 A latent inconsistency found on the way (not caused by this request)

`DIOPTRA_VULNDB_MAX_DUMP_BYTES` defaults to **512 MiB** (`core/config.py:146`),
but the same nginx location caps every `/api/` body at **200 MiB**. So behind
Compose a dump between 200 and 512 MiB is refused by nginx with a 413, and the
API's own cap never speaks. This is to be fixed in the same diff, because
this survey makes the nginx cap per-route anyway.

### 2.4 The refusal does not say the limit

`errors.ingest.zipTooLarge` reads "El archivo ZIP supera el tamaño máximo
permitido." It does not say what the maximum is, so the person cannot tell
whether trimming `node_modules/` will be enough. The error contract already
allows `context` (`core/errors.py`), so the limit can be carried and
rendered.

### 2.5 This host cannot run the acceptance test

`df -h /` on 2026-09-28: **106 MB free, 100 %**. A 1 GiB upload, its jail
and the analysis containers' scratch need several GiB. The P4 rule stands: we
do not prune anything outside this repository to make room. **The acceptance
walk (§8) needs either space freed by `mmarin` or another host.** Unit tests
can prove the caps with small caps configured; only the walk proves the
numbers.

### 2.6 Downstream of ingest, nothing changes size-wise

The runners mount the jail read-only and already have a 600 s timeout, 2 GiB
RAM and 2 CPUs each (`core/config.py:76–78`). Findings are capped at 2 000,
worst first. A bigger tree makes Semgrep and Syft slower, and a runner
that exceeds its timeout is recorded as a coverage gap, never a silent pass
(`docs/analysis-pipeline.md`). That is an operator tuning question
(`DIOPTRA_RUNNER_TIMEOUT_SECONDS`), not a design change, but the walk must
say whether 600 s holds on a real 1 GiB tree.

## 3. Options

**A. Raise the numbers only.** nginx to 1 GiB, `MAX_ZIP_BYTES` to 1 GiB, the
API tmpfs to 2+ GiB. The smallest diff. **Rejected**: a 2 GiB RAM tmpfs
filled pre-auth is the residual made five times worse, the request-held
transaction and the 600 s cut remain, and the unpacked/entry caps still
refuse the archive.

**B. Stream to disk after auth, extract in the request.** The route stops
declaring `UploadFile`, authenticates first, then copies `request.stream()`
into a spool file on a disk volume, counting bytes (the vulndb import's copy
loop, `inventory/sync.py::request_import`). Then it extracts as today.
Closes §2.1. Leaves §2.2.

**C. Stream to disk after auth, extract in the WORKER (recommended).** As B,
but the handler only spools, writes the audit row, commits the analysis as
`QUEUED` and enqueues. The pipeline job extracts and detects before the
runners, exactly as the git ingest already clones in the worker. Closes §2.1
and §2.2: the request lasts as long as the upload and no longer, and a slow
unpack is the worker's time.

Trade-off of C, stated plainly: **the hostile ZIP is then parsed inside the
worker that holds the Docker socket.** Phase 8 moved WeasyPrint OUT of that
worker for exactly this reason. Two things make it acceptable here, and
`mmarin` decides (§7.3):

- the precedent: `git clone` of a hostile repository already runs in that
  worker, and git is a larger native attack surface than `zipfile`;
- `zipfile` is pure Python over zlib, and `archive.py`'s guards do not change,
  they only move.

The alternative is a third, socket-less `ingest-worker` in the phase-8 shape,
at the cost of one more service in Compose and in the two-host overlays.

## 4. Numbers to set

| Setting | Today | Proposed | Why |
|---|---|---|---|
| `DIOPTRA_MAX_ZIP_BYTES` | 200 MiB | **1 GiB** | the request |
| `DIOPTRA_MAX_UNPACKED_BYTES` | 1 GiB | **8 GiB** | code unpacks 3–10×; 8× covers the common case, and the ratio cap still refuses a bomb |
| `DIOPTRA_MAX_ZIP_ENTRIES` | 50 000 | **300 000** | a `node_modules/` tree alone runs to 10⁴–10⁵ files |
| `DIOPTRA_MAX_ZIP_RATIO` | 100 | 100 (unchanged) | still the bomb guard |
| nginx on the ZIP route | 200m | `${DIOPTRA_MAX_ZIP_MIB}m`, one variable feeding both nginx and the API default | the two caps must not drift again (§2.3) |
| nginx `proxy_request_buffering` on the ZIP route | on | **off** | nginx otherwise buffers the whole 1 GiB to its own disk before forwarding |
| nginx timeouts on the ZIP route | read 600 s | `client_body_timeout` / `proxy_send_timeout` sized for 1 GiB on a slow LAN | a 1 GiB upload at 10 MB/s is ~100 s; at 2 MB/s, ~9 min |
| API `/tmp` tmpfs | 512m | **unchanged** | the ZIP no longer goes there under B/C |
| Upload spool | — | `${DIOPTRA_DATA_DIR}/uploads`, a disk bind mount beside `vulndb/`, `0700`, files `0600`, named by the analysis uuid | the operator bounds it like the other spools |

Disk the operator must now plan for, per concurrent upload: 1 GiB spool
+ up to 8 GiB jail. The spool is deleted once extraction ends, in success
and in failure; the jail lives as long as the analysis, as today. The
deployment guide (both halves, Spanish and English) says so.

## 5. Design pseudocode (option C)

```
# projects/router.py — no UploadFile, no body parameter: auth resolves first
POST /api/v1/projects/{id}/ingest
    headers: Content-Type: application/zip
             X-Dioptra-Filename: <name>          # display only, capped, never a path
    user = IngestUser                            # 401/403 before any byte is read
    project = get_project(...)
    if declared Content-Length > cap: raise ZipTooLarge(context={limit})
    analysis = service.accept_zip(db, project, user, request.stream(), filename, ip)
    return 202 analysis                          # status QUEUED, languages empty

# ingest/service.py
accept_zip(db, project, actor, stream, filename, ip):
    analysis = Analysis(source_kind=ZIP, status=QUEUED, ...); flush
    spool = settings.upload_spool_dir / f"{analysis.id}.zip"   # uuid, never the filename
    open spool O_EXCL 0600
    written = 0
    async for chunk in stream:                   # the vulndb loop, byte-counted
        written += len(chunk)
        if written > settings.max_zip_bytes: raise ZipTooLarge(context={limit})
        write chunk
    on ANY exception: unlink spool, re-raise     # the row rolls back with the request
    if written == 0: unlink, raise InvalidArchive
    audit "analysis.ingest.zip" (target analysis.id, bytes written)
    commit
    enqueue_pipeline(analysis.id)

# analysis/pipeline.py — first step for a ZIP analysis, before the runners
if analysis.source_kind is ZIP and jail does not exist:
    try:
        extract_zip(open(spool), jail, limits)   # archive.py UNCHANGED: same guards
    except IngestError as e:
        analysis.status = FAILED, detail = e.code   # a typed code, shown to the person
        return
    finally:
        unlink spool                             # whatever happens
    detection = detect(jail); store languages/frameworks/lockfiles
# git analyses already take the equivalent branch (clone in the worker)
```

Frontend: `ingestZip` sends the `File` as the raw body with `XMLHttpRequest`,
because `fetch` cannot report upload progress. The panel shows a progress
bar in the stepped width classes and says "Subiendo… 43 %". Once the server
answers, the analysis appears as "en cola", like a git ingest does today.
The refusal names the limit: "El archivo ZIP pesa más de 1 GiB, el máximo
permitido."

The vulndb import route gets the same treatment in the same diff: raw
body, auth first, the same streamed cap, and nginx's cap for it taken from
`DIOPTRA_VULNDB_MAX_DUMP_BYTES`. It already streams into its spool; what it
gains is auth before the body and a consistent nginx cap (§2.3).

## 6. Hostile-input and test plan

Every existing `archive.py` test stays and stays green; the guards do not
move semantically, only where they run. New tests, all with SMALL caps
configured so they run on this host:

- anonymous and developer callers get 401/403 **without a byte being
  written to the spool** (assert the spool directory is empty);
- a body one byte over the cap, sent **chunked with no `Content-Length`**,
  is refused mid-stream and leaves no spool file and no analysis row;
- a lying `Content-Length` (small declared, large body) is refused by the
  counter;
- `X-Dioptra-Filename` with `../`, NUL, 10 000 characters: stored capped as
  `source_ref`, never used as a path;
- extraction failures in the worker (zip-slip, bomb, too many entries,
  not a zip) set `FAILED` with the typed code and delete the spool;
- the spool is deleted on success too;
- the pipeline refuses a ZIP analysis whose spool is missing (typed, not a
  crash);
- nginx: a rendered template test that the ZIP location's cap equals the
  API's setting (the §2.3 drift, pinned).

Mutation pass on `ingest/service.py` and the new router code at close, as
P1's close did for the ingest guards.

## 7. Decisions — taken by `mmarin` 2026-09-28

Answered together, as recommended: **§7.1 option C**, **§7.2 8 GiB and
300 000 entries**, **§7.3 the existing `worker`** (the `git clone`
precedent), **§7.4 the 1.x contract change accepted**. **§7.5**: this host is
the only test machine; space was freed on 2026-09-28 (106 MB → 8.6 GB free),
which holds the acceptance ZIP (`caracas_sonrie-desarrollo.zip`: 593 MiB
compressed, 1.42 GiB unpacked, 21 872 entries, ~2 GB on disk during the walk).
That ZIP is evidence and is ingested WHOLE — it is never trimmed.

The questions as they were put:

1. **Option C**, extraction in the worker (recommended), or **B**, extraction
   stays in the request?
2. **Unpacked cap 8 GiB and 300 000 entries**, or other numbers? Higher
   numbers mean more disk per analysis, and nothing else changes.
3. **Under C, which worker parses the ZIP?** The existing socket-holding
   `worker`, like `git clone` today (recommended: same precedent, no new
   service), or a new socket-less `ingest-worker` in the phase-8 shape?
4. **1.x contract change.** `POST …/ingest` stops accepting multipart and
   takes a raw `application/zip` body, and the analysis it returns has no
   languages yet (they arrive with the pipeline). Any script that uploads with
   `curl -F` breaks. This is the fourth 1.x change since the tag; the release
   number is still yours to set (Release rules: 1.x → 2.0).
5. **The acceptance walk (§8) needs disk.** Free space on this host, or run
   it on another machine?

## 8. Acceptance

- A real ZIP of 500 MB–1 GiB (the one that prompted this) walks E2 → E3
  behind Compose (nginx in front), with a visible progress bar, and every
  tool RAN or is recorded as a timeout gap.
- The same upload sent directly to the API port with no token is refused
  before a byte is spooled.
- The upload/jail/runner timings are written in the task file, so the next
  operator knows what 1 GiB costs.

## 9. Estimate

| Block | Size |
|---|---|
| router + service spool/stream + typed errors with `context` | ~150 LOC |
| pipeline extraction step + FAILED path + spool cleanup | ~80 LOC |
| config + Compose volume + nginx template per route + both overlays | ~60 lines |
| frontend XHR upload + progress + limit in the refusal + locales es/en | ~120 LOC |
| vulndb import route aligned | ~40 LOC |
| tests (§6) | ~300 LOC |
| docs: threat-model (ZIP ingest row, two-host residual closed), standards-mapping V12.1, analysis-pipeline, deployment guide (both halves), ui-model, development-phases | — |

## Verdict

**PROCEED with option C once §7.1–§7.4 are answered.** §7.5 does not block
the build, only the close.

The request cannot be met by raising a number: four limits in series decide
it, and the one that matters for security (§2.1: a body spooled into RAM
before authentication) gets worse, not better, if the numbers alone move.
Option C closes that residual, removes the minutes-long request, and reuses
two established shapes: the byte-counted spool of the vulndb import and the
worker-side acquisition of the git ingest. `archive.py`'s guards are kept
byte for byte.

Signed off by: `mmarin`  date: 2026-09-28
