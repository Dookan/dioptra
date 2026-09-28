# Task: Phase 11 — Sensitive artefacts committed to the audited tree

> **Status: DONE — closed 2026-09-28, commit `77d4300`.** Survey
> `tasks/phase11-survey.md`, signed off by `mmarin` the same day ("todo lo de
> la fase 11 que recomiendas está bien, lo firmo"). Opened after phase 10
> closed (`bb81328`); the two never shared a diff.

## Objective
Report, as ordinary findings, the data an audited system ships AS SOURCE — a
database dump, a directory of user uploads, an `.env` with values, a private
key, large logs — without ever copying that data into the platform. Asked by
`mmarin` looking at `caracas_sonrie-desarrollo.zip`: a 234 MB PostgreSQL dump
at the root and 405 uploaded photos, and nothing in the report said so.

## Deliverables
1. `backend/app/analysis/artefacts.py` (new) — `scan_artefacts(root, *,
   max_files=300_000) -> ArtefactScan` and `to_finding(hit) ->
   NormalizedFinding`. Five rules (`artefact-database-dump`,
   `-user-uploads`, `-env-file`, `-private-key`, `-log-file`) with the CWE and
   severity of survey §4 / §6. 4 KiB head per candidate, `lstat` for the
   size, regular files only, no symlink followed, `.git` skipped, dependency
   directories walked (§5), 500 hits at most; both caps are a coverage gap.
2. `backend/app/analysis/models.py` — `ToolCategory.ARTEFACT = "artefact"`.
   The column stores the member NAME (`ARTEFACT`, 8 characters, the column's
   length) and carries no CHECK constraint, verified on the dev PostgreSQL:
   **no migration**.
3. `backend/app/analysis/pipeline.py` — `_scan_artefacts` runs in the
   normalisation step, stores the hits raw (`raw_tool_outputs`, tool
   `artefacts`) and a `ToolRun` (RAN, FAILED on `OSError`, the cap in
   `detail`) BEFORE turning them into findings, then merges them before the
   worst-first ordering (`normalizer.report_order`, extracted for this).
4. `backend/app/analysis/third_party.py` — `ARTEFACT` is never third-party,
   this category only.
5. `backend/app/analysis/catalog.py` — `ARTEFACT_CATALOG` (prose per rule,
   anchor register; 530 in the dump's references), `ARTEFACT_MESSAGES`, and
   `describe(…, artefact_rule=)`, passed ONLY for this category by
   `reports/context.py` and `projects/schemas.py`, so no other tool's rule id
   can select this prose.
6. `backend/app/reports/{context,closure}.py` — the category prints in
   "Hallazgos de vulnerabilidades" and counts in annex A.
7. Frontend: the findings screen shows tool names as they are (product
   names), so the platform's own scan is named in words instead —
   "archivos sensibles" in the tool filter and the detail (`findings.toolNames`,
   mockup-fidelity panel). The progress
   sentence of the normalisation step now says it also looks for backups and
   sensitive files (es/en).
8. `backend/tests/test_artefacts.py` (new, 100 tests) and one screen test
   in `frontend/src/screens/findings-screen.test.tsx`.

## Constraints
- Hard Rules: audited code is hostile; no new dependency; Spanish only in the
  catalog (report content carve-out).
- **A finding never carries the file's content.** Pinned against the stored
  finding, the raw output and the HTML, Markdown and DOCX exports.

## Definition of Done
- [x] Deliverables implemented; ruff + mypy clean (`app tests`)
- [x] Tests passing — 100 new, the whole non-sandbox backend suite green, 142
      frontend; `tsc -b` and oxlint clean; Gitleaks clean on the tree and the
      history
- [x] Acceptance on `caracas_sonrie-desarrollo.zip`, extracted WHOLE with
      `archive.py`'s guards (19 851 files, the scan in **0.32 s**, extraction
      removed afterwards): `artefact-database-dump` high on
      `respaldo_sonrei_Mon009072026_21132576.sql` (snippet
      `-- PostgreSQL database dump`), `artefact-user-uploads` medium on
      `backend/uploads/despachos-pregira` ("405 archivos · 206 MB" — the
      survey's 406 counted the directory entry of the ZIP), and one the survey
      did not list: `artefact-env-file` high on `backend/.env`, carrying the
      key names `DATABASE_URL, PORT, HOST, JWT_SECRET` and no value. The
      rendering in every export is proven by the end-to-end test rather than
      by a second Docker walk of the whole pipeline.
- [x] Mutation pass on `artefacts.py` and `third_party.py` (mutmut 3.8,
      2026-09-28; both joined the target list, with `test_artefacts.py` and
      `test_third_party.py`): **first pass 361 killed of 419; after the tests
      it asked for, 399 killed, 17 survived, 1 timeout.** `third_party.py`
      has no survivor. What the pass found: the gzip head's `max_length` —
      the one bound on how much a hostile `.sql.gz` expands in memory — had
      no test; neither did any exact boundary (the seed floor, the log floor,
      ten uploads, the hit cap, 1 MB in the size print), nor `continue` →
      `break` with two artefacts in ONE directory (a dump would have hidden
      the key beside it), nor a FIFO or an unreadable file before a dump,
      nor two upload roots each below the threshold (a grouping key of
      `None` merged them), nor the message of each rule. All written. It
      also found `or "."` on the log path to be dead code — removed.
      **The 17 survivors, all inspected**: `decode("ascii")` →
      `"ASCII"` and `encode("utf-8")` → `"UTF-8"` (codec names are
      case-insensitive, 3); `17 + MAX_WBITS` (zlib's automatic header
      detection accepts gzip too) and a `b"XXXX"` fallback that matches no
      signature (2); `filled = None` (falsy like `False`); `describe(None, …)`
      in `to_finding` (the artefact rule wins before the CWE is read);
      `followlinks` False → None / default / True and `is_symlink()` on the
      wrong path (5 — the two defences are redundant on purpose: symlinked
      directories are pruned AND `os.walk` does not follow them, so removing
      either alone changes nothing); `(rel_dir.parts) or True` (the tree
      root has no upload root either way); `detail` → `None` for the upload
      and log hits (their snippet and message use the counts, never
      `detail`); and `_common_dir`'s loop start and first index (3, the
      timeout among them), equivalent because every path it compares shares
      the upload root as prefix and arrives in walk order.
- [x] `/precommit` returned `READY TO COMMIT` after the first round. **First round applied**
      (2026-09-28). Security: the `.env` line regex had a lazy tail before
      `\s*$` — quadratic, 40 ms per 4 KiB line, times every `.env*` a hostile
      tree can ship — now greedy and stripped afterwards, pinned by a timing
      test; the 500-hit cap sorted by rule id, so 500 LOW log directories
      evicted every HIGH private key — now worst first; `.git` was skipped at
      any depth, so `x/.git/prod.sql` hid a dump — now only at the root.
      Invariants: `roles-and-permissions.md`, `ui-model.md` and
      `analysis-pipeline.md` still said every dependency-directory finding
      leaves the queue; a Spanish phrase in a code comment; the
      `workflow-gates.md` insertion split a paragraph. Fidelity: the new tool
      showed as the English word "artefacts" on a Spanish screen. QA: every
      verifiable claim GENUINE; its one gap (a vendored artefact outranking
      vendored SAST in the cap) now has a test. A quoted blank (`Q='  '`) no
      longer counts as a value. **Coverage adversary** (alone, after the
      fixes): 27 hand mutants over what mutmut does not reach — 18 killed, 2
      equivalent (a `db.commit()` in `_scan_artefacts`: `run_pipeline`
      commits at the end whatever happens), 7 real gaps, all now tests: the
      raw output's `truncated` flag, the artefact prose reaching the report
      context, the category gate in the report context AND the API schema
      (an artefact rule id on a SAST finding must not select this prose),
      the annex-A count, and the documented hit order. Tree verified
      unchanged after the adversary. **Still open, not this diff's**: the
      migration-`0013` backfill defect, recorded in the scope-change log for
      `mmarin`.
- [x] CLAUDE.md phase status + `docs/development-phases.md`: Phase 11 → DONE with date and commit (`77d4300`)
- [ ] On-screen look by `mmarin` (not a gate): the longer step-8 sentence beside the clock, and "archivos sensibles" in the tool filter

## Deviations from the survey
- **Where an upload directory is reported.** "One finding per directory" is
  made precise as: per upload-named root, the DEEPEST directory holding all
  its image/document files, counting every file under it. A tree fanned out
  per user (`storage/app/public/u1/…`, `u2/…`) is therefore one finding, not
  zero; `caracas_sonrie`'s lands on `despachos-pregira`, as §9 expected.
- **Seed floor.** "`seed*.sql` / `fixtures/`" also covers `seeds/` and
  `seeders/` directories (Laravel's name).
- **No new progress step.** The scan runs inside "normalize" (0.32 s on
  1.4 GiB), so `pipeline_steps()` and the screen's step count are unchanged.
- **Gitleaks may also report a private key** at its line; the two findings
  do not dedupe (different CWE and line) and say different things — the
  secret, and the file.

## Non-goals (explicit)
- Opening an image or a document to judge whether it holds personal data —
  the analyst raises the severity at triage (§6.5).
- Reading past the head of a dump to count rows or tables.
- A setting to switch rules off: a knob that silences findings without a
  trace in the repository is the wrong shape (the phase-9 reasoning).

## References
- `tasks/phase11-survey.md`; `docs/analysis-pipeline.md` → Layers;
  `docs/workflow-gates.md` → Third-party findings; `docs/threat-model.md` →
  Sensitive artefacts scan; CWE-530, CWE-538, CWE-321, CWE-532.
