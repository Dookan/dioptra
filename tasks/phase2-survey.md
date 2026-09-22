# Phase 2 survey — findings UI, triage, versioned report

> **Status: written 2026-09-21 before any edit, per CLAUDE.md → Agent
> Behavioral Rules (report-integrity surface: signing and versioning; the
> phase exceeds 200 LOC).** Task: `tasks/phase2-findings-ui.md`.

## §1 What exists (read-only survey)

- `backend/app/analysis/models.py` — `Finding` has no verdict columns.
  `Analysis.findings` is ordered by `ordinal`; `finding_counts` is computed in
  `app/projects/router.py::analysis_out`.
- `backend/app/analysis/router.py` — `GET /analyses/{id}`, `/findings`,
  `/sbom`, `/report?format=`. Every route is `ActiveUser` (any role reads).
- `backend/app/audit/service.py::record()` — the only writer of the
  append-only trail; `justification` column already exists "for triage
  verdicts, gate approvals and report signing".
- `backend/app/auth/deps.py` — `require_roles()` writes `authz.denied` and
  commits before raising `Forbidden` (403). `AnalystUser` exists.
- `backend/app/reports/context.py::build_context()` — pure dict; the
  `version_control` row is the `TODO(phase2)` placeholder; the institutional
  prose of the introduction / findings intros lives INLINE in
  `templates/report/report.html.j2` and `report.md.j2`, while the DOCX path
  reads the same paragraphs from `strings.json` (`introduction`,
  `findings_intro`, `dependencies_intro`, `coverage_intro`, `commented_code`).
- `backend/app/reports/engine.py` — autoescape forced, `pre` / `md` / `fence`
  filters, restricted WeasyPrint fetcher. `render_*(analysis, project)`.
- `backend/app/analysis/catalog.py::describe(cwe, fallback_title)` — the
  Spanish institutional prose (description / impact / mitigation) per CWE.
- `frontend/src/screens/project-screen.tsx` — read-only `FindingsTable`
  inside each analysis card; `frontend/src/navigation/use-route.ts` — three
  hash routes; `components/app-shell.tsx` — tabs Inicio / Proyectos.
- Mockups: screen 04 "Hallazgos y revisión (E3)" (list of cards + detail
  panel with "¿Qué encontramos?" / "¿Cómo corregirlo?", buttons "Es real —
  incluir en el reporte" / "No aplica (explicar por qué)", nextstep banner
  with "N de M" progress); screen 09 "Reporte (E8)" (sections list with ✓,
  export buttons, "Versión 2 · editada por mmarin", preview + "✎ Editar esta
  sección").

## §2 Design — triage (day 11)

Data: four columns on `findings` (no separate history table — the
append-only audit log IS the history; a second table would duplicate it and
could drift):

```
verdict               enum('confirmed','false_positive') NULL   -- NULL = pending
verdict_justification text NULL
verdict_by_username   varchar(64) NULL
verdict_at            timestamptz NULL
```

Service `app/workflow/triage.py` (the E3 gate module P3 will call):

```
record_verdict(db, finding, actor, verdict, justification, source_ip)
    justification = justification.strip(); len < MIN → JustificationRequired (422)
    finding.verdict / _justification / _by_username / _at = ...
    audit.record(action="finding.verdict", target=f"finding:{id}",
                 justification=..., actor=...)
triage_status(analysis) -> TriageStatus(total, confirmed, false_positive, pending, complete)
    complete = total > 0 and pending == 0      # E3 gate condition, server-side
```

API (`app/workflow/router.py`): `POST /api/v1/findings/{id}/verdict`
(`AnalystUser` → developer AND admin get 403 + `authz.denied` row; the
matrix gives triage to the analyst only). Body `{verdict, justification}`;
pydantic validates the enum, the service validates the stripped length so
whitespace cannot pass. Response: the updated `FindingOut`.

`AnalysisOut.triage` (`{total, confirmed, false_positive, pending,
complete}`) so the UI banner and P3's gate read the same numbers.

`FindingOut` gains `description`, `impact`, `mitigation[]` (catalog prose —
report content shown as data, the same text the PDF prints, so the analyst
reviews exactly what the institution will sign) and the four verdict fields.

Report consequence: "Es real — incluir en el reporte" / "No aplica" mean a
finding marked `false_positive` LEAVES the report (all formats) while pending
findings stay (P1 behaviour unchanged before triage). The executive-summary
counts follow the same rule.

## §3 Design — versioned report (day 12)

Table `report_versions`:

```
id, analysis_id FK CASCADE, number int (unique with analysis_id),
sections JSON  -- {section_key: "text"} overrides of the editable prose
change_summary varchar(500)   -- "Descripción del cambio"
areas varchar(200)            -- "Áreas Modificadas" (section labels changed)
created_by_username, created_at,
signed_by_username NULL, signed_at NULL,
excluded_findings JSON NULL   -- finding ids frozen out at signing (§5), NULL on drafts
content_hash char(64) NULL
```

Editable sections (plain text, paragraphs split on blank lines, ESCAPED at
every render — no rich text, see §5): `introduction`, `summary`,
`findings_intro`, `dependencies_intro`, `practices`, `coverage_intro`. Their
defaults move from the two templates into `strings.json → sections`, which
the DOCX path already reads: one source, three renderers.

Service `app/reports/versions.py`:

```
current(db, analysis) -> ReportVersion | None          # highest number
save_sections(db, analysis, actor, sections, change_summary):
    validate keys ⊂ EDITABLE, each text ≤ MAX_SECTION_CHARS
    if no version: create #1 = baseline (empty overrides, "generated" summary)
    base = current().sections; merged = {**base, **sections}
    create #n+1 (areas = labels of keys whose text changed); audit "report.edit"
sign(db, analysis, actor, number, justification):
    version must be current() (older → VersionNotCurrent 409)
    signed already → VersionAlreadySigned 409
    if no version at all and number == 1 → create the baseline first
    signed_* = actor/now; excluded_findings = ids of findings not in_report
    content_hash = sha256(canonical json of number + sections + excluded_findings)
    audit "report.sign" with justification
```

Immutability of a signed version is enforced at the DATABASE level like the
audit log: `BEFORE UPDATE ... WHEN OLD.signed_at IS NOT NULL → raise`
(PostgreSQL trigger + SQLite trigger so the test suite proves it). Edits
after signing only ever INSERT the next number.

API (`app/reports/router.py`, prefix `/api/v1/analyses/{id}/report`):

- `GET  /current` (any role) → `{number, persisted, signed, sections:{key:
  {text, edited}}, versions:[…]}` — the merged text the editor shows.
- `PUT  /sections` (`AnalystUser`) → creates the next version.
- `POST /versions/{n}/sign` (`AnalystUser`, body `{justification}`).
- `GET  /versions` (any role).
- Existing `GET /report?format=&version=` renders that version (default
  current); unknown → 404 `report_version_not_found`.

`build_context(analysis, project, version=…)` fills `version_control` from
the rows (number, areas, change_summary, delivered_at = signed date or
created date, in the report's Spanish date format) and `sections` from
defaults ∪ overrides; the P1 placeholder row stays only when no version
exists.

Visual executive summary: a severity bar table and an OWASP-category bar
table, pure HTML/CSS in the report (WeasyPrint renders CSS widths; no JS, no
library) and the same bars in the report screen through tokens (both
themes). No charting dependency.

## §4 Frontend

Routes (`use-route.ts`): `#/projects/:id/analyses/:aid/findings` and
`#/projects/:id/analyses/:aid/report`. The shell shows the contextual tabs
Hallazgos / Reporte when the route carries an analysis (the mockups' tabs
bar); Inicio / Proyectos stay (the "cards fold into Inicio" question is
`mmarin`'s, left open in `docs/ui-model.md`).

`findings-screen.tsx`: stepper at "Análisis"; nextstep banner "Te faltan N
hallazgos por revisar" + progress "k de M"; filters severity / OWASP / tool /
file (selects fed from the loaded list); left list of cards (`.card.sel`),
right detail panel; verdict form with a mandatory textarea; buttons are the
mockup's. Snippets, titles, paths, messages render as TEXT NODES only.

`report-screen.tsx`: sections list with ✓ / ✎ state, export buttons (reuse
`downloadReport`), version hint, preview of the selected section, "✎ Editar
esta sección" → textarea + change summary + "Guardar como versión N+1",
"Firmar esta versión" + justification, the version table, the severity/OWASP
bars.

The read-only `FindingsTable` of `project-screen.tsx` becomes a link
"Revisar hallazgos" to the findings screen (one source of truth for the
list).

## §5 Trade-offs surfaced

- **Verdict columns vs. history table** — columns + audit log chosen; a
  verdict can be revised (the analyst may change their mind after reading the
  code) and every revision is a new audit row. Revisit if P5's VEX needs the
  history in a queryable form.
- **Justification mandatory for CONFIRM too** — the mockup only says
  "descartar exige explicar por qué", but CLAUDE.md → Auth and
  docs/roles-and-permissions.md require a justification on every triage
  verdict. Server rule wins; the UI keeps the field short and pre-focused.
- **Plain text sections, not rich text** — docs/report-format.md says
  "rich text"; HTML from the browser into WeasyPrint is exactly the stored-XSS
  path the threat model names. P2 ships paragraphs escaped at every render;
  a sanitized subset (bold/lists) is a later decision, recorded in
  docs/report-format.md.
- **"Signing" = attested lock + content hash, not PKI** — the actor, the
  time, the justification and a SHA-256 of the signed content are recorded and
  the row becomes immutable by trigger. The precommit panel showed the hash
  must cover the finding SET too (a verdict revised after signing would
  otherwise change a signed export): the version stores the excluded ids at
  signing time and renders that set; drafts render the live triage. A cryptographic signature needs a key
  per analyst and a verification story that the plan never asked for.
- **False positives leave the report** — implied by the mockup button copy;
  pending findings stay so an untriaged analysis still exports the full P1
  report.
- **No new dependency** — bars are CSS; no charting library.

## §6 Tests

Backend `tests/test_triage.py`: developer 403 + `authz.denied` row; admin
403; blank / whitespace / too-short justification 422
`justification_required`; verdict persisted + `finding.verdict` audit row
carrying the justification; `triage.complete` false until the last verdict;
false positive excluded from HTML / MD / DOCX and the summary counts; verdict
revision writes a second audit row.

`tests/test_report_versions.py`: first save → versions 1 (baseline) and 2;
overrides rendered escaped (`<script>` → `&lt;script&gt;`) in HTML and MD;
sign locks (409 on re-sign, 409 on signing a stale number); edit after sign
creates #3 and #2 is byte-identical; ORM `UPDATE` of a signed row raises
(trigger, SQLite and the PG DDL string asserted); developer cannot save or
sign; `?version=` exports that version; "Control de versiones" rows in HTML.

Frontend: `findings-screen.test.tsx` (list, filter, verdict POST body,
blank justification blocked, hostile title rendered as text),
`report-screen.test.tsx` (sections, save → PUT, sign → POST).

## Verdict: Proceed

Day 11 and day 12 as one push, in that order; triage first because the E3
banner and the report exclusion depend on it. Docs updated with the same
commit: `docs/report-format.md` (versioning behaviour, plain-text cut),
`docs/roles-and-permissions.md` (no change to rows), `docs/threat-model.md`
(Report editing row → built), `docs/standards-mapping.md` (V4.1 triage/sign,
V7.1 verdicts), `docs/ui-model.md` (routes, contextual tabs),
`docs/development-phases.md` + CLAUDE.md (P2 IN_PROGRESS).
