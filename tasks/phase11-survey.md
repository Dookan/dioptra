# Phase 11 survey — sensitive artefacts committed to the audited tree

> **Status: SIGNED OFF 2026-09-28 by `mmarin`** ("todo lo de la fase 11 que
> recomiendas está bien, lo firmo") — §6.3 a new `ARTEFACT` category, §6.4
> CWE-538 with 530 in the references, §6.5 uploads at medium. Built AFTER
> phase 10 is DONE. Written
> read-only, before any edit. It changes what the analysis REPORTS (new
> findings, a new catalog entry, new report prose) and will exceed 200 LOC,
> so the plan-first gate applies (CLAUDE.md → Agent Behavioral Rules). It
> runs AFTER phase 10 (ZIP ingest up to 1 GiB), which is signed off and is
> built first; the two never share a diff.
>
> Asked by `mmarin` 2026-09-28, looking at `caracas_sonrie-desarrollo.zip`:
> a 234 MB database dump at the tree root and 406 user-uploaded images under
> `backend/uploads/` shipped as source code, and nothing in the platform said
> so. Two decisions were already given in session and are recorded in §6.

## 1. What is missing

No rule in the platform reports that a tree CONTAINS a database dump, a
directory of user uploads, or a similar data artefact. Checked 2026-09-28:

- `rules/semgrep/` — fourteen families, all about code patterns; the three
  `regex` rules (`no-cdn`, `xss`, `mass-assignment`) match markup and PHP
  properties, none looks at `.sql`, `.dump`, `.bak`, images or `.env`.
- `rules/gitleaks/gitleaks.toml` — finds a secret INSIDE a dump if one is
  there (a token, a key); it never reports the dump itself. A dump full of
  personal data and Argon2/bcrypt hashes yields nothing.
- The report prints what the findings are. So today the most serious fact
  about that system — the production data sits in the repository — is absent
  from its report unless an analyst writes it into a prose section by hand.

## 2. Why a Semgrep rule is the wrong tool

The first idea is a `regex` rule on `*.sql` matching dump headers. It fails
on exactly the case that matters: Semgrep skips targets over
`--max-target-bytes` (1 MB by default), and the MINCYT-scale dump is 234 MB.
Raising the flag makes Semgrep read hundreds of MB of data for a header in
the first kilobyte. A rule that is silent on large files is worse than no
rule: it lets the report look clean.

## 3. The shape that fits: our own deterministic scan

`analysis/metrics.py::scan_commented_code` is the precedent. It is our own
walk over the jail, in the worker, after the runners. It is capped
(`max_files`, `max_bytes_per_file`), never follows a symlink, and feeds a
report section. An artefact scan is the same shape, with two differences:

- it produces FINDINGS (CWE, OWASP, severity, path, mitigation), not a list
  for a prose section, so it reaches E3 triage, the executive summary and
  every export through the path every other finding takes;
- it reads only a HEAD of each candidate (4 KiB) plus `stat()` for the size,
  so a 234 MB dump costs one small read.

No new tool, so the Analysis Tool Source Authority table gains a row
("Sensitive artefacts — our own scan, `analysis/artefacts.py`") rather than a
licence. The scan result is persisted the way the other results are, before
normalisation, so a later bug in how it is turned into findings never loses
what it saw.

## 4. What it detects (v1 of the rule set)

Deterministic, by name + size + head content. Each kind is ONE rule id.

| Rule id | Match | CWE | Severity | One finding per |
|---|---|---|---|---|
| `artefact-database-dump` | `.sql`, `.dump`, `.pgdump`, `.bak`, `.sql.gz` whose head carries a dump signature (`-- PostgreSQL database dump`, `-- MySQL dump`, `-- MariaDB dump`, `PGDMP` magic, `COPY … FROM stdin;`, or `INSERT INTO` rows); or `.sqlite` / `.db` / `.sqlite3` starting with `SQLite format 3\0` | 538 → A01, with 530 (exposure of backup file) in the references — 530 is in no Top 10:2021 list, `owasp_for(530)` is `None` (§6.4) | high | file |
| `artefact-user-uploads` | a directory named `uploads`, `upload`, `media`, `storage/app`, `public/uploads` holding ≥ 10 image/document files (`.jpg .jpeg .png .gif .webp .pdf .doc(x) .xls(x)`) | 538 → A01 | medium | directory, with count and total size in the message |
| `artefact-env-file` | `.env`, `.env.*` except `.env.example` / `.env.sample` / `.env.dist`, with at least one `KEY=non-empty` line | 538 → A01 | high | file |
| `artefact-private-key` | `.pem`, `.key`, `id_rsa`, `.p12`, `.pfx` whose head carries `-----BEGIN … PRIVATE KEY-----` or PKCS#12 magic | 321 → A02 (already in the map) | high | file |
| `artefact-log-file` | `.log` files over 1 MB | 532 → A09 | low | directory |

**Not matched on purpose** (false positives that would bury the real ones):

- `.sql` files with only DDL (`CREATE TABLE`, `ALTER`) and no data rows:
  migrations and schema files are legitimate source. This covers
  `migrations/*.sql` and `schema.sql` whatever their names.
- `seed*.sql` / `fixtures/` under a size floor (100 KB): small, hand-written
  test data is normal. Over the floor it is reported; a 5 MB "seed" is a dump.
- images under `assets/`, `static/`, `public/img`, `src/`: those are the UI's
  own images, not user uploads. Only the upload-named directories above count.

The snippet of a finding is **never the file's content**. For a dump it is
the signature line only (e.g. `-- PostgreSQL database dump`), for an upload
directory it is `406 archivos · 206 MB`, and for an `.env` file it is the KEY
names without their values. A dump's rows and an image are never copied into
the database, the report or the screen. The finding's job is to say the data
is there, not to republish it.

## 5. Dependency directories — the one exception, by `mmarin`

`third_party.finding_is_third_party` takes every SAST/secret finding under
`node_modules/`, `vendor/`, … out of the E3 queue (phase 9). **`mmarin`,
2026-09-28: an artefact finding inside a dependency directory must still be
flagged, and ONLY this kind of finding gets that treatment.** So:

```
finding_is_third_party(category, path):
    if category is SCA:       return False     # phase 9 (VEX input)
    if category is ARTEFACT:  return False     # phase 11: a dump in vendor/ is still ours to judge
    return is_third_party(path)
```

- The artefact finding stays in the queue and needs a verdict, wherever it
  sits.
- The phase-9 rule for every OTHER finding in `vendor/` does not change.
- The findings-cap sort key (own code < vendored SCA < vendored rest) gains
  the same exemption in its second level, so a vendored dump is never evicted
  before vendored SAST noise.
- **The migration backfill trap from phase 9 does not recur**: there are no
  stored artefact findings to backfill, because the category is new.

Why this is right, not just asked for: a library does not ship a
`production.sql`. A dump or an `.env` under `vendor/` was put there by the
team (a copied folder, a deploy script), so it is their data, whatever the
directory is called.

## 6. Decisions

1. **Dependency directories → TAKEN by `mmarin` 2026-09-28**: flagged and in
   the queue, this finding kind only (§5).
2. **Report wording → TAKEN by `mmarin` 2026-09-28**: each rule gets its
   `CatalogEntry` in `analysis/catalog.py` (description, impact, mitigation,
   references), written in the anchor reports' register, like every other
   entry. Mitigation for a dump: remove it from the repository AND its
   history, treat the data as exposed, rotate every credential it contains.
3. **The category → TAKEN by `mmarin` 2026-09-28, as recommended.** A new `ToolCategory.ARTEFACT` (`"artefact"`,
   exactly 8 characters, the column's length; stored as text, so no
   migration adds a member — to be confirmed that `native_enum=False` emits no
   CHECK constraint on the existing rows) versus filing them as `SECRET`.
   **Recommended: a new category.** `SECRET` would inherit the third-party
   rule without the exemption and mislabel a photo directory as a secret; the
   report, the executive summary and the tool filter already group by
   category.
4. **The CWE for a dump → TAKEN by `mmarin` 2026-09-28, as recommended.** CWE-530 ("Exposure of Backup File to an
   Unauthorized Control Sphere") names the case exactly but sits in no OWASP
   Top 10:2021 list, so today it would print "sin clasificar". CWE-538 is in
   A01 and describes it well enough. **Recommended: 538 for the OWASP bucket,
   with 530 in the references**, so the report classifies it and still names
   the precise weakness.
5. **Uploads severity → TAKEN by `mmarin` 2026-09-28, as recommended.** Medium by default; the analyst can raise it
   at triage with a written verdict. Uploaded identity documents would be
   high, but the scan cannot tell a passport from a product photo and must
   not open the images to try. **Recommended: medium, and the message says
   "revisar si contienen datos personales".**

## 7. Design pseudocode

```
# backend/app/analysis/artefacts.py  (new, pure, no DB)
scan_artefacts(root, *, max_files=300_000, head_bytes=4096) -> list[ArtefactHit]
    walk root, followlinks=False, sorted, symlinks skipped   # scan_commented_code's walk
    DO NOT skip node_modules/vendor here — §5; only .git is skipped
    per file: classify by name → if candidate: stat size, read head (≤ 4 KiB)
    per directory: count upload-type files in upload-named dirs
    return hits sorted by (rule_id, path)            # deterministic

ArtefactHit {rule_id, path, size, detail}            # detail: signature line, count, key names

# pipeline.py, after the runners, before normalize():
hits = scan_artefacts(workspace)
persist raw (ToolRun "artefacts" RAN + RawToolOutput JSON of the hits)
findings += [to_finding(hit) for hit in hits]        # CWE / OWASP / severity from the rule table
# then the existing sort, cap and insert — with category ARTEFACT
```

The walk honours the analysis' jail exactly as `scan_commented_code` does,
and has a file cap: an over-cap walk is a recorded coverage gap
("artefactos: revisados 300 000 de N archivos"), never a silent pass.

## 8. Tests (hostile input first)

- Each rule: a positive and a negative fixture, including a DDL-only
  migration (negative), a 150 KB `seed.sql` with rows (positive), a 5 KB one
  (negative), `.env.example` (negative), an `.env` with empty values
  (negative), and a `.pem` holding only a PUBLIC key (negative).
- A dump inside `node_modules/pkg/` → finding with `third_party = False`, in
  the queue; a SAST finding in the same directory keeps `third_party = True`
  (the exemption applies to ONE kind only, §5).
- A 50 MB dump: the scan reads ≤ 4 KiB (assert with a counting file
  wrapper), and the finding's snippet holds the signature line and nothing
  from the rows.
- An `.env` finding carries key NAMES and never a value (assert the value
  string is absent from the finding, the report HTML and the Markdown).
- Symlinked dump pointing outside the jail → not followed, no finding.
- A file named `x.sql` holding `<script>`: escaped in every export, like any
  snippet.
- Determinism: the same tree yields byte-identical findings across runs.
- The acceptance tree (below).

Mutation pass on `artefacts.py` and the changed `third_party.py` at close.

## 9. Acceptance

`caracas_sonrie-desarrollo.zip`, ingested WHOLE once phase 10 lands (it is
evidence and is never trimmed), yields at least:

- `artefact-database-dump` on `respaldo_sonrei_Mon009072026_21132576.sql`,
  high, in the E3 queue;
- `artefact-user-uploads` on `backend/uploads/despachos-pregira`, "406
  archivos · 206 MB";
- and every export of the report shows both with their catalog prose,
  without a byte of the dump or an image in it.

## 10. Estimate

| Block | Size |
|---|---|
| `artefacts.py` (walk, classifiers, signatures) | ~220 LOC |
| pipeline wiring, raw output, cap gap, `ToolCategory.ARTEFACT`, the `third_party` exemption | ~60 LOC |
| five `CatalogEntry` texts + `strings.json` / locale keys for the category | ~120 lines |
| frontend: the category in the tool filter and in the finding card | ~30 LOC |
| tests (§8) | ~350 LOC |
| docs: analysis-pipeline (new layer), CLAUDE.md tool table, workflow-gates (the exemption), threat-model (hostile artefacts read by the worker), report-format, development-phases | — |

## Verdict

**PROCEED after phase 10 is DONE.** Every question of §6 is answered.

The detector is our own deterministic walk in the established
`scan_commented_code` shape. It reads only file heads, never republishes the
data it finds, and turns what it sees into ordinary findings, so triage, the
report and the exports need no new path. The one rule it bends, the phase-9
dependency exemption, bends for this finding kind only and in the direction
that keeps a human looking.

Signed off by: `mmarin`  date: 2026-09-28
