# Software inventory (SBOM · CBOM · VEX)

> **Status: BUILT 2026-09-22 (P5 day 18, `backend/app/inventory/`,
> `frontend/src/screens/inventory-screen.tsx`, migration `0009_inventory`).**
> Added by the work plan v1.0 (2026-08-21); SBOM generation landed in P1
> (day 7), the module in P5 (day 18). It is a deliverable of the factory, not
> of a language: under overrun it is never cut (PHP/Java went first — see the
> scope-change log). Design: `tasks/phase5-survey.md`.

## What it is, in the plan's words

The bill of materials of every system: which libraries it uses, in which
version, under which license and with which cryptography. Stored in a standard
format (CycloneDX) and cross-checked against the public vulnerability
databases. When a new flaw appears in a library, the factory knows in minutes
which projects carry it and which are out of version. Without this, the answer
is "check project by project, by hand".

## Documents (all CycloneDX 1.6, JSON)

| Document | Produced by | When | Content |
|---|---|---|---|
| **SBOM** | Syft (Apache-2.0) in an ephemeral container, from lockfiles and the dependency tree — metadata only, **no package scripts ever run** | P1, alongside the E3 runners; one per project **version** (each ingest); stored raw in `sboms.document` | direct + transitive components, versions, PURLs, declared licenses |
| **CBOM** | **our own Semgrep crypto-inventory rules** (`rules/semgrep/crypto-inventory.yml`): the normalizer DIVERTS their results into `crypto_assets` instead of findings, and `inventory/documents.py::cbom_document` emits one `cryptographic-asset` component per algorithm with its occurrences. Decided at the P5 survey (§6): cdxgen's CBOM and IBM cbomkit were rejected on footprint (a Node tree or a Java service shipped air-gapped for one column of the panel), not on licence | P5 | algorithms, primitives (hash, cipher, MAC, signature, KDF), weak protocols found in code; a weak algorithm is ALSO a finding through `weak-crypto.yml` — same match, two purposes, two rules |
| **VEX** | the platform, from the analyst's triage verdicts on SCA findings (E3) — never a tool (`inventory/documents.py::vex_document`) | P5 | per advisory × component: `exploitable` (confirmed), `not_affected` (false positive, with the analyst's written justification as `analysis.detail`), `in_triage` (pending) |

The SBOM is the input of both the SCA layer (`docs/analysis-pipeline.md`) and
the inventory; generating it twice is a bug. There is deliberately no
`components` table: the stored document is parsed per request
(`inventory/components.py`), so what the panel shows is what the report
attaches.

## Vulnerability database — local, always

- A LOCAL mirror of **OSV** and **NVD** (the CVE.org feed), stored in
  PostgreSQL (`vulnerabilities`, `vulnerability_packages`), owned by the
  `inventory` module. OSV is the correlation source — it names packages by
  ecosystem + name with explicit version events, which is what an SBOM can be
  joined on; NVD names products by CPE and is stored as ENRICHMENT: an OSV
  match whose aliases carry a CVE id borrows NVD's score when OSV has none. An
  NVD-only record is never correlated by itself.
- Refreshed by a **scheduled sync** (`inventory/sync.py::run_sync_job`, an RQ
  job the worker runs at `DIOPTRA_VULNDB_SYNC_INTERVAL_HOURS`; it re-enqueues
  itself under a fixed job id, the worker runs `--with-scheduler`, and the API
  kicks it once at start-up) or by a **file import** of the dump when the
  deployment has no internet (`DIOPTRA_VULNDB_SYNC_ENABLED=false`; the panel
  then offers only the import). The dump formats are the public ones: an OSV
  ecosystem `all.zip` and an NVD `nvdcve-2.0-<year>.json[.gz]`.
- The sync is the ONLY outbound connection the platform ever opens: HTTPS
  only (a non-HTTPS endpoint refuses to boot), TLS verification on, redirects
  refused, a download byte cap, a timeout, and the two base URLs are operator
  settings never settable through the API.
- The **last-update date is visible** in the inventory panel at all times
  (`vulndb_syncs`, the newest run that brought data in), with the sync
  history underneath.
- The panel's "Actualizar la base ahora" and "Importar base de
  vulnerabilidades" buttons only **enqueue**: the handler audits the request
  (`vulndb.sync.request` / `vulndb.import.request`, written reason, admin or
  analyst) and returns 202; the worker downloads or parses, and writes its own
  row (`vulndb.sync` / `vulndb.import`). No request handler performs outbound
  I/O, and correlation never queries anything — it reads the mirror.
- The platform **never queries a third-party vulnerability service at request
  time** — Hard Rule "No CDNs", level 3. Docker Scout was rejected on exactly
  this (proprietary cloud service). Dependency-Track (Apache-2.0) remains the
  accepted alternative if an external component is ever preferred; it would
  replace this mirror, not sit beside it.

## Correlation and statistics

- BOM ↔ CVE (`inventory/correlation.py`): every SBOM component with a PURL
  the platform maps to an OSV ecosystem (npm, PyPI, Packagist, Maven, Go,
  crates.io, RubyGems, NuGet) is matched by (ecosystem, name) against the
  indexed `vulnerability_packages`, then by version: the explicit `versions`
  list first, then each range's `introduced` / `fixed` (exclusive) /
  `last_affected` (inclusive) events. `GIT` ranges are ignored (no commit
  to compare). One tolerant comparer serves every ecosystem
  (`inventory/versions.py`): numeric segments compare as integers, a
  pre-release orders before its release, epochs and build metadata are
  dropped, and a version that is really a spec (`^1.2.3`, `latest`, `*`) is
  NOT comparable — the component is listed under "versión no comparable"
  rather than guessed.
- Out-of-version: "outdated" means **a newer version is known to the local
  copy** — the smallest `fixed` version above the component's in any
  advisory, or a higher version of the same package in another stored SBOM
  of the factory. Never a registry query; the card says so.
- Panel (`inventory/service.py::overview`, `GET /api/v1/inventory`): the
  latest analysis with an SBOM per project (the previous one for the trend);
  components outdated, vulnerable, by severity, by project, by license, the
  CBOM summary, and the **trend between versions** of the same project (open
  CVEs now minus open CVEs in the previous analysis). Factory-wide, capped
  at `DIOPTRA_MAX_INVENTORY_COMPONENTS` (50 000) with the cap shown. It is
  recomputed on every request and not cached — proportionate for an
  on-premise factory; **revisit trigger**: tens of projects with
  20 000-component SBOMs, then cache the overview per sync or ingest.
- VEX applied: a CVE the analyst marked "No aplica" with justification stays
  visible but leaves the open count. The verdict is already in the audit
  log (`finding.verdict.false_positive`).

## Exports

- `GET /api/v1/analyses/{id}/sbom` (P1) — the SBOM as generated.
- `GET /api/v1/inventory/analyses/{id}/cbom`, `…/vex` — CycloneDX 1.6 JSON,
  structurally checked by `backend/tests/test_inventory_api.py` (the same
  "our own check, no JSON-Schema dependency" rule as P1's SBOM validation).
- `GET /api/v1/inventory/analyses/{id}/components.csv` — every cell quoted
  and neutralised (`' ` prefix when it starts with `=`, `+`, `-`, `@`, tab or
  CR). Headers come from `backend/templates/report/strings.json` → `inventory`,
  the report-content carve-out, because the CSV is the institution's document
  like the report.
- The report's "Inventario" section and its annex embed the same data
  (`docs/report-format.md`, day 19).

## Roles

Written at the P5 survey (§7) and enforced by `inventory/router.py`:

| Action | admin | analyst | developer |
|---|---|---|---|
| Read the panel; download SBOM / CBOM / VEX / CSV | ✓ | ✓ | ✓ |
| Request a sync; import a dump (written reason, audit row) | ✓ | ✓ | — |
| VEX verdicts | — | via E3 triage only | — |

## Hostile input reminder

Component names, versions, license strings and PURLs come from the audited
system's lockfiles: they are hostile input like any snippet. Advisory
summaries and NVD descriptions are third-party prose. Both are stored raw
and escaped at every render (React text nodes in the panel, Jinja2
autoescape in the report, neutralised CSV cells); component counts and file
sizes are capped; an imported dump is untrusted too — entry-count, size and
decompression-ratio caps on the zip, a streaming record-by-record parser for
the NVD feed, per-field caps at persistence, and a record that does not fit
the shape is counted and skipped, never raised on. Rows Inventory rendering,
Vulnerability DB sync and VEX statements in `docs/threat-model.md`.

## Acceptance (plan, day 18)

For a real project: SBOM valid against the CycloneDX 1.6 schema, CBOM with at
least the detected algorithms, and the panel showing which components have
open CVEs and which are out of version. Recorded in
`tasks/phase5-closure.md` (Definition of Done).
