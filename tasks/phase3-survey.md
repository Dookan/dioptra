# Phase 3 survey — stage machine, gates, E4 risk matrix (day 13)

> **Status: written 2026-09-22 before any edit, per CLAUDE.md → Agent
> Behavioral Rules (gate logic; the slice exceeds 200 LOC).** Task:
> `tasks/phase3-workflow-e1-e5.md`. Days 14–15 (AST → Mermaid, briefs,
> pseudocode) get their own sections appended here BEFORE their edits.

## §1 What exists (read-only survey)

- No stage column anywhere. `Analysis.status` is the PIPELINE state
  (queued/running/done/failed), not the workflow stage.
- E3's gate condition exists: `app/workflow/triage.py::triage_status(...)
  .complete` (`pending == 0`), exposed as `AnalysisOut.triage`.
- E8 exists: `app/reports/versions.py::sign()` (analyst only).
- `CodeMetrics.functions` = Lizard rows `{path, function, line, end_line,
  nloc, ccn, params}` sorted by `-ccn` (`app/analysis/metrics.py`),
  capped; `Finding.path` uses the same jail-relative POSIX form.
- Roles: `require_roles()` → `AnalystUser`, `DeveloperUser`, `AdminUser`;
  `IngestUser` = admin|analyst (`app/projects/router.py`).
- Audit: `audit.record(action, target, justification)`; append-only.
- Frontend: `STAGES` (`components/stages.ts`) already names the eight
  stages in order; `Stepper current=N` is hard-coded per screen; routes
  `findings` / `report` carry `{id, analysisId}`; the shell shows contextual
  tabs. Mockup 05 "Plan de pruebas (E4)": risk-ranked `.rowline` list with
  `.prio` number, plain-words reason, `Riesgo alto/medio/bajo` badge,
  Incluir / Dejar fuera; coverage `.radios` (Sentencias — básica /
  Decisiones 100 % — recomendada / Caminos — exhaustiva); "Guardar plan y
  diseñar los casos →"; status bar "cperez · Programador · Paso 4 de 8 ·
  Plan de pruebas · v0.1.0".
- docs/workflow-gates.md is the gate table; docs/roles-and-permissions.md
  gives E4–E7 to the developer, E1–E3 and E8 to the analyst.

## §2 Design — stage machine

The unit that walks E1→E8 is an ANALYSIS (one ingested version). E1 is the
project's registration, satisfied the moment the analysis exists, so an
analysis is born at `code` (E2).

```
Analysis.stage  enum(register, code, analysis, plan, design, tests,
                     verification, report)   default 'code'
```

Same names as the frontend `STAGES`; stored as text like every other enum.

Transitions are explicit, monotonic and gated, in `app/workflow/stages.py`:

```
STAGE_ORDER = (register, code, analysis, plan, design, tests, verification, report)

advance(db, analysis, actor, justification, source_ip) -> Analysis
    current = analysis.stage; nxt = STAGE_ORDER[index+1]  (report → StageIsFinal 409)
    role check: LEAVING code/analysis → analyst (code also admin);
                LEAVING plan/design/tests → developer;
                LEAVING verification → developer (P4 wires the system result);
                → GateForbidden 403 + authz.denied-style audit row
    gate(current, analysis) → GateClosed 409 {code: gate_closed, reason: <gate code>}
    justification = clean_justification(...)    (mandatory, same rule as triage)
    analysis.stage = nxt
    audit "stage.advance" target f"analysis:{id}:{current}->{nxt}"
```

Gates (`gates.py`, pure predicates returning `GateResult(open, reason)`):

| leaving | condition | reason code when closed |
|---|---|---|
| code | `analysis.status is DONE` | `analysis_not_done` |
| analysis | `triage_status(analysis).complete` | `triage_pending` |
| plan | test plan saved with ≥1 function, a criterion and a rationale | `test_plan_missing` |
| design | **not built** (day 15) — always closed | `gate_not_built` |
| tests | not built (P4) — always closed | `gate_not_built` |
| verification | not built (P4) — always closed | `gate_not_built` |

Fail closed by construction: a stage whose gate is not built yet cannot be
left, so nothing can reach `report` through the API before P4 exists. The
report can still be signed at any time (P2 behaviour, unchanged) — signing
is the E8 output, not a transition.

No backwards transition in P3; the E7 → E5 loop is P4's and will be a
distinct, gated action, never a generic "set stage".

## §3 Design — E4 risk matrix and test plan

Risk matrix, computed on demand (`app/workflow/risk.py`), never stored:

```
for each Lizard row f:
    findings_in_file = [x for x in analysis.findings if x.in_report and x.path == f.path]
    max_severity     = worst severity among them (None when no finding)
    criticality      = {critical: 4, high: 3, medium: 2, low: 1, info: 1, none: 1}
    score            = ccn * (1 + len(findings_in_file)) * criticality
    level            = high if score >= 20 else medium if score >= 8 else low
sorted by (-score, path, line); capped at 200 rows for the API
```

Thresholds are documented constants; the plain-words reason is UI copy
(i18n keys with `count` / `ccn` params), the API ships data only.

`GET /api/v1/analyses/{id}/risk-matrix` (any role) →
`[{path, function, line, ccn, nloc, findings, max_severity, score, level}]`.

Test plan (`app/workflow/models.py`):

```
test_plans: id, analysis_id UNIQUE FK CASCADE,
            criterion enum(statements, decisions, paths) default decisions,
            rationale text, functions JSON [{path, function, line, ccn}],
            created_by_username, created_at, updated_at
```

`PUT /api/v1/analyses/{id}/test-plan` (`DeveloperUser`) body
`{criterion, rationale, functions:[{path, function, line}]}`:
- every function must exist in the metrics (`TestPlanFunctionUnknown` 422);
  ≥1 required (`TestPlanEmpty` 422); rationale through `clean_justification`;
  `functions` capped at 200;
- refused with `StageLocked` 409 once the analysis is past `plan` (the plan
  is E4's deliverable; E5 works on it);
- upsert (one plan per analysis); audit `testplan.save` with the rationale.

`GET /api/v1/analyses/{id}/test-plan` (any role) → the plan or 404.

`POST /api/v1/analyses/{id}/stage/advance` body `{justification}` — the one
transition endpoint; `AnalysisOut.stage` exposes the current stage.

## §4 Frontend

- `analysis.stage` drives the Stepper everywhere (`STAGES.indexOf`), no
  more hard-coded `current`.
- Status bar (mockup screens 02–11) in the shell when a route names an
  analysis: avatar · `username · Rol` · "Paso N de 8 · <stage name>" ·
  version (from `app.version` key fed by `import.meta.env` — the P0 shell
  already has the version string? verified during build; else the
  package version).
- Route `#/projects/:id/analyses/:aid/plan` → `test-plan-screen.tsx`
  (mockup 05): pagehead "¿Qué vamos a probar?", nextstep banner, ranked
  `.rowline` list with Incluir / Dejar fuera toggles, coverage `.radios`,
  rationale textarea, "Guardar plan" and "Guardar plan y diseñar los casos →"
  (save + advance, developer). Tab "Workflow" appears with the analysis
  context and points here.
- Advance buttons where the gate opens: project screen analysis card
  "Empezar la revisión" (code → analysis, analyst); findings screen banner
  "Pasar al plan de pruebas" (analysis → plan, analyst, only when triage is
  complete); plan screen (plan → design, developer). Each asks for the
  written reason (same textarea pattern as triage).

## §5 Trade-offs surfaced

- **Stage on the analysis, not the project** — a project has many ingested
  versions; the report and the tests belong to one of them. The project's
  "current stage" for the Inicio cards (P2 open question) is the stage of
  its latest analysis.
- **Explicit transitions with a written reason, even E2 → E3** — the docs
  say every transition records actor + justification; an automatic hop
  would have no actor. Cost: one click and a sentence per stage.
- **Unbuilt gates fail closed** rather than "open until built": phase
  discipline and the gate-skip suite both need the future stages to be
  unreachable today.
- **Risk score formula** — `ccn × (1 + findings) × criticality` with
  criticality from the worst finding severity in the file; the plan's
  "criticidad" has no other source until E1 metadata carries one. Recorded as
  the P3 definition; revisit if the analyst wants to tag critical modules.
- **Plan editable only while in E4** — otherwise E5's brief would be
  computed against a moving target. The panel extended the same rule to E3's
  verdicts (locked once E3 is left; `mmarin` chose the lock over tolerating
  re-triage) and narrowed the plan to "only AT E4" (not before either).

## §6 Tests

`tests/test_gates.py` — the gate-skip suite (plan, day 13): advance from
`code` while the pipeline is not DONE → 409 `gate_closed`/`analysis_not_done`;
from `analysis` with one pending verdict → 409 `triage_pending`; from `plan`
with no plan → 409; from `design` → 409 `gate_not_built` (fail closed);
developer advancing `analysis` → 403; analyst advancing `plan` → 403; admin
advancing `analysis` → 403; blank justification → 422; a full happy walk
`code → analysis → plan → design` with the audit rows and `stage` in
`AnalysisOut`; nothing moves backwards (no endpoint; `advance` from `report`
→ 409 `stage_final`); plan saved after leaving E4 → 409 `stage_locked`.

`tests/test_risk_matrix.py` — ordering, score, level thresholds, false
positives ignored, functions without findings, empty metrics, cap.

`tests/test_test_plan.py` — validation (empty, unknown function, blank
rationale, bad criterion), developer only, upsert, audit row.

Frontend: `test-plan-screen.test.tsx` (ranked list, include/exclude, PUT
body, advance POST), stepper driven by `analysis.stage`, status bar text.

## Verdict: Proceed

Day 13 only. Days 14–15 append §7+ here before their edits.
