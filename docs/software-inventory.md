# Software inventory (SBOM · CBOM · VEX)

> **Status: DESIGN SURFACE — not yet implemented.** Added by the work plan
> v1.0 (2026-08-21); SBOM generation lands in P1 (day 7), the module in P5
> (day 18). It is a deliverable of the factory, not of a language: under
> overrun it is never cut (PHP/Java goes first).

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
| **SBOM** | Syft or cdxgen (Apache-2.0) in an ephemeral container, from lockfiles and the dependency tree — metadata only, **no package scripts ever run** | P1, alongside the E3 runners; one per project **version** (each ingest) | direct + transitive components, versions, PURLs, declared licenses |
| **CBOM** | tool decided at the P5 survey (candidates: cdxgen CBOM output, IBM cbomkit, our own Semgrep crypto rules) | P5 | algorithms, key sizes, protocols, certificates found in code and config |
| **VEX** | the platform, from the analyst's triage verdicts on SCA findings (E3) — never a tool | P5 | per CVE × component: affected / not affected / fixed, with the analyst's written justification |

The SBOM is the input of both the SCA layer (`docs/analysis-pipeline.md`) and
the inventory; generating it twice is a bug.

## Vulnerability database — local, always

- A LOCAL mirror of **OSV** and **NVD** (the CVE.org feed), stored in
  PostgreSQL, owned by the `inventory` module.
- Refreshed by a **scheduled sync** (an RQ job; outbound only, to the two
  public dump endpoints) or by a **file import** of the dump when the
  deployment has no internet (`Contingencies` in `docs/development-phases.md`).
- The **last-update date is visible** in the inventory panel at all times.
- The panel's "Actualizar la base ahora" button only **enqueues** the same RQ
  sync job (role and justification per the P5 survey; audit-logged). No
  request handler performs outbound I/O, and correlation never queries
  anything — it reads the mirror.
- The platform **never queries a third-party vulnerability service at request
  time** — Hard Rule "No CDNs", level 3. Docker Scout was rejected on exactly
  this (proprietary cloud service). Dependency-Track (Apache-2.0) is the
  accepted alternative if an external component is ever preferred; it would
  replace this mirror, not sit beside it.

## Correlation and statistics

- BOM ↔ CVE: every SBOM component matched by PURL / version range against the
  local database → open CVEs per component, per project version, with CVSS.
- Out-of-version: latest known version per component (from the same mirror),
  so "outdated" is computed offline too.
- Panel: components outdated, vulnerable, by severity, by project, by license,
  and the **trend between versions** of the same project.
- VEX applied: a CVE the analyst marked "not affected" with justification stays
  visible but leaves the open count. The verdict goes to the audit log.

## Exports

CycloneDX JSON (SBOM, CBOM, VEX — schema-valid against 1.6) and CSV of the
component table. The report's "Inventario" section and its annex embed the
same data (`docs/report-format.md`).

## Roles

Not defined by the work plan. The permission rows are written in
`docs/roles-and-permissions.md` when P5 is designed (`tasks/phase5-survey.md`).

## Hostile input reminder

Component names, versions, license strings and PURLs come from the audited
system's lockfiles: they are hostile input like any snippet. Escape at every
render (panel, PDF, CSV cells that could be formula-injected), cap component
counts and file sizes, and treat an imported vulnerability dump as untrusted
too (schema validation, size caps). Rows SBOM generation, Inventory rendering, Vulnerability DB sync and VEX statements in `docs/threat-model.md`.

## Acceptance (plan, day 18)

For a real project: SBOM valid against the CycloneDX 1.6 schema, CBOM with at
least the detected algorithms, and the panel showing which components have
open CVEs and which are out of version.
