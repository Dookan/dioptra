# Phase 9 survey — third-party findings leave the triage queue, and the list gets paged

> **Status: SIGNED OFF 2026-09-23 by `mmarin`; BUILT the same day.**
> Plan-first investigation gate (CLAUDE.md → Agent Behavioral Rules): this
> slice changes **the E3 gate** — which findings `leave_analysis` demands a
> verdict for — and adds a column with a migration. No edit before `mmarin`
> signs the `## Verdict`.
>
> Asked by `mmarin` 2026-09-23, from real use: a Laravel application produced
> 687 findings, the screen froze, and E3 could not be closed.

## 1. What actually happens today, measured

On the real analysis (`otroprevi`, 687 findings, 1 369 SBOM components):

| | |
|---|---|
| `GET …/findings` — load 687 rows | **0.08 s** |
| serialise them | **0.04 s**, **0.6 MiB** |
| `gates.check(ANALYSIS, …)` | **0.00 s**, correctly closed, `triage_pending` |
| findings without a verdict | **686 of 687** |

**The server is not the problem.** `findings-screen.tsx:401` renders
`visible.map(...)` — one card per finding, no page, no window, no cap — so the
browser paints 687 cards. That is the freeze `mmarin` reported, and clicking
"Pasar al plan de pruebas" is not involved: the transition is refused server
side in under a millisecond, correctly.

The second problem has no workaround: E3's gate wants an individual written
verdict for all 687, and **422 of them are in `vendor/`** — Symfony, Laravel
and DomPDF source the analyst cannot fix and should not be adjudicating one at
a time. Reaching E4 on a real application is therefore weeks of work today.

## 2. What the platform already knows about "third-party"

- `analysis/metrics.py:23` already skips `node_modules`, `vendor`, `dist`,
  `build`, `venv`, `.venv`, `__pycache__`, `.git` when it reads Lizard/cloc,
  so the idea exists in the analysis layer; it just never reached findings.
- `ingest/detection.py::SKIPPED_DIRS` does the same for language detection.
- The runners deliberately do NOT honour the audited tree's own ignore files
  (`--no-git-ignore`, `--x-ignore-semgrepignore-files`) — a hostile tree must
  not be able to silence the scanner. **That must not change**: the findings
  are still produced, still stored, still reported. What changes is only
  whether the analyst is required to adjudicate them.

## 3. Where the CVEs land, and why the rule works

The SCA findings are attributed to the **lockfile** that declared the
dependency (`composer.lock`, `resources/views/client/package-lock.json`), not
to a path under `vendor/`. So a path rule leaves them in the queue — which is
required, because `docs/software-inventory.md` builds the **VEX** document
from exactly those E3 verdicts. Measured split for `otroprevi`:

| Layer | In `vendor/` | Own code |
|---|---|---|
| SAST | 422 | 91 |
| SCA (CVE) | 0 | 164 |
| SECRET | 8 | 2 |

So the queue goes from **687 to 257**, and every verdict the VEX needs is
still in it.

## 4. Design pseudocode

```
app/analysis/third_party.py
    THIRD_PARTY_SEGMENTS = {vendor, node_modules, bower_components, Pods,
                            site-packages, .bundle, vendor/bundle, third_party}
    def is_third_party(path) -> bool
        any segment of the POSIX path is in the set
        (segments, never a substring: `my-vendor-api/` is OUR code)

Finding.third_party: Mapped[bool]      # migration 0013, backfilled by path
    set where findings are persisted, from the normalised path, once

workflow/triage.py
    triage_status(analysis) counts ONLY `not f.third_party`
    TriageStatus gains `third_party: int` so the UI can say how many exist
    post_verdict REFUSES a third-party finding: typed error, not silence

gates.leave_analysis  unchanged in shape — it reads triage_status().complete
```

Frontend:

```
findings-screen
    the working queue lists first-party findings, PAGED (25 per page,
    filters apply before the page, the page resets when a filter changes)
    a separate collapsed section "Hallazgos en código de terceros (N)" —
    read-only, paged, no verdict form, one sentence saying these come from
    dependencies, are in the report, and are the inventory's business
```

**Pagination stays client-side.** The payload is 0.6 MiB for 687 and the cap
is `max_findings_per_analysis` = 2000, so the worst case is ~1.8 MiB in one
response — proportionate for an on-premise tool on a LAN. **Revisit trigger**:
raising that cap, or a deployment where the browser is remote over a slow link.

## 5. What does NOT change, deliberately

- The findings are still produced, stored and **printed in the report**,
  `vendor/` included (`mmarin`, 2026-09-23, recorded in `tasks/phase8-survey.md`
  §7.4). This phase changes the analyst's QUEUE, not the document.
- The scanners still ignore the audited tree's ignore files.
- The executive summary keeps counting what the report contains.
- No Hard Rule is touched: every verdict still carries a written
  justification. There is no bulk verdict here — the queue simply stops
  containing work that was never the analyst's.

## 6. Decisions for `mmarin`

1. **The segment list** (§4). Proposed: `vendor`, `node_modules`,
   `bower_components`, `Pods`, `site-packages`, `vendor/bundle`, `.bundle`,
   `third_party`. Deliberately NOT `dist` and `build`: those are the audited
   project's OWN build output, and a finding in built code is still theirs.
   Deliberately matched on a whole path SEGMENT, so `my-vendor-api/` stays in
   the queue.
   **Widened at build time, recorded here rather than left silent** (found by
   the precommit security auditor, 2026-09-23): the shipped set also carries
   `dist-packages` (Debian's system site-packages) and `vendored` (pip's and
   urllib3's convention), and drops `vendor/bundle` because `vendor` already
   subsumes it. Both additions are in the spirit of what was signed off, but
   this set is exactly the knob that decides what skips mandatory review, so
   a change to it belongs in writing. `mmarin` to overrule if either is wrong.
2. **Existing analyses**: the migration backfills by path, so `otroprevi`'s
   422 leave the queue retroactively and its E3 becomes closeable. The
   alternative — only new analyses — would leave the one real test case stuck.
   Recommendation: backfill.
3. **Does a third-party finding still block the gate if someone DID triage it
   before this change?** Recommendation: no — the gate reads the first-party
   set only, and an existing verdict on a third-party finding is kept and
   shown, never deleted.

## 7. Estimate

| Block | Size |
|---|---|
| `third_party.py` + the column + migration 0013 with backfill | ~120 LOC |
| `triage_status`, the refusal in `post_verdict`, the schema field | ~80 LOC |
| findings screen: paging, the third-party section, locales | ~220 LOC |
| tests: the split, the gate, the refusal, the backfill, paging | ~250 LOC |
| docs: workflow-gates, ui-model, analysis-pipeline, roles | — |

## Verdict

**PROCEED once §6.1 is confirmed.** The design needs no new concept: the
platform already has a third-party directory set in two places, the CVE
findings land on lockfiles rather than inside `vendor/`, and the gate keeps
its shape — only the set it counts gets smaller. Nothing here weakens a
control: the findings are still produced, stored, reported and visible; what
stops is requiring an analyst to write 422 justifications about Symfony.

The pagination half is independent and could land first if `mmarin` wants the
screen usable before the queue decision is built.

Signed off by: **`mmarin`** date: **2026-09-23** — §6.1 confirmed as proposed ("Solo directorios de dependencias"), §6.2 backfill, §6.3 as recommended; pagination built first at his request ("paginación primero").
