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

## §7 Day 14 — AST → flow diagrams (appended 2026-09-22, before any edit)

### What exists
- The plan (`test_plans.functions`) names each function by `(path, function,
  line)` as Lizard reported it; Lizard's `function` is the bare name (methods
  arrive as `Class::method` / `Class.method` — match on the last segment).
- The jail (`analysis.workspace_path`) is shared by API and worker
  (`DIOPTRA_DATA_DIR`), so the API can read the source file itself.
- CSP is `style-src 'self'` in both nginx and the API (P0), no
  `unsafe-inline`.

### Parser
tree-sitter (MIT) + the JS, TS/TSX and Python grammars (MIT), added to
`pyproject.toml` with license + rationale; the license gate re-verified
(215 packages, OK). One engine for wave 1 and for PHP/Java in P5. Language by
extension: `.js .mjs .cjs .jsx` → javascript, `.ts .mts .cts` → typescript,
`.tsx` → tsx, `.py` → python; anything else → `UnsupportedLanguage` (422).

### Extraction (`app/workflow/ast/`)
```
load_source(analysis, path) -> bytes
    resolved = (jail / path).resolve(); must be relative_to(jail) else FunctionNotFound
    size > MAX_SOURCE_BYTES (512 KiB) → SourceTooLarge (422)
find_function(tree, name, line) -> node
    candidates: function_definition / function_declaration / method_definition /
    arrow_function or function expression bound by a variable_declarator, whose
    name's last segment == name; prefer start line == line, else nearest;
    none → FunctionNotFound (404). A tree with ERROR nodes inside the function → ParseFailed (422).
build_graph(node, language) -> FlowGraph(name, params, nodes[], edges[], complexity)
    nodes: start, end, process (consecutive simple statements collapsed, label =
    "line a–b"), decision (if / elif / while / for / switch-case / try),
    return, throw/raise; edges labelled true / false / loop / except.
    depth capped (MAX_DEPTH 40 → TooDeep 422); nested functions are opaque process nodes.
    complexity = 1 + if/elif/else-if + loops + case + except/catch + ternary
                 + boolean operators (&&, ||, ??, and, or) — Lizard's counting.
```
Determinism: node ids are assigned in source order; the same bytes give the
same graph, the same Mermaid text and the same layout (tested: two runs,
byte-identical).

### Rendering — trade-off surfaced
The plan says "rendered by the bundled Mermaid library". Mermaid renders an
SVG that carries its own `<style>` element and `style=` attributes; under
our CSP (`style-src 'self'`, no `unsafe-inline`) the browser drops both and
the diagram comes out black-on-black. Two ways out: (a) add
`'unsafe-inline'` to `style-src` for the whole app, or (b) render the
diagram ourselves from the same graph with a deterministic layered layout and
CSS classes only — no inline style, no new frontend dependency, and the SAME
layout function produces the SVG the P5 report annex embeds server-side
(docs/threat-model.md → Flow diagrams already requires that). Chosen: (b).
The Mermaid TEXT stays the interchange and editing format (shown and
editable under the diagram, exportable, escaped as text everywhere); the
rendered picture is always the AST's, so "the brief is computed from the
AST, never from the edited diagram" holds by construction. Recorded in
docs/ui-model.md and docs/workflow-gates.md; `mmarin` may revert to (a).

### Storage and API
```
case_designs: id, analysis_id FK, path, function, line,
              diagram_text NULL (developer's edited Mermaid, ≤ 20 000 chars),
              created_by_username, updated_at; UNIQUE (analysis_id, path, function, line)
              -- day 15 adds pseudocode + approval columns to the same row
GET /api/v1/analyses/{id}/diagram?path=&function=&line=   (any role)
    → {language, mermaid, complexity, graph, layout, edited_text}
PUT /api/v1/analyses/{id}/diagram   (DeveloperUser, only AT design; body {path, function, line, text})
    → saves diagram_text (text only), audit "design.diagram.edit"
```
The function must belong to the saved plan (`FunctionNotInPlan` 422) —
diagrams exist for what E4 chose.

### Frontend
Route `#/…/design` → `case-design-screen.tsx` (mockup 06): function
selector from the plan; `FlowDiagram` draws `<svg>` from the layout JSON
with `<rect>/<text>/<path>` and class names; the Mermaid text below in a
textarea (developer, at design) with "Guardar diagrama"; the note "La
consigna se calcula del código, no del diagrama". The right column (brief +
pseudocode) is day 15 — a banner says so. The Workflow tab points at plan
or design by stage.

### Tests
`tests/test_ast_js_ts.py`, `test_ast_python.py`: fixtures with hand-counted
nodes/edges/complexity (if/else, elif chain, loops, try/except, switch,
ternary, boolean operators, nested function opaque, arrow function bound to
const, method); `test_diagrams.py`: determinism, Mermaid escaping of hostile
names (`"`, `<`, newlines), layout invariants (every node placed, no NaN,
edges reference existing nodes); hostile source: 600 KiB file → 422, 60-deep
nesting → 422, syntax error inside the function → 422, `../../etc/passwd` →
404, `.rb` → 422; API: function outside the plan → 422, developer-only PUT,
PUT refused off the design stage. Frontend: screen renders the SVG nodes,
PUT body, read-only for the analyst.

## §8 Day 15 — E5 test brief, pseudocode, gate (appended 2026-09-22, before any edit)

### What exists (read-only)
- `build_graph` (day 14) yields `FlowGraph{nodes, edges, complexity, params}`
  with decision / loop / return / throw nodes carrying their source line;
  `complexity()` is OUR McCabe count (decisions + loops + cases + handlers
  + ternaries + boolean operators, nested functions excluded). The brief's
  minimum case count is this number: cyclomatic complexity = number of
  basis paths (docs/glossary.md).
- Comparisons are NOT collected yet: the boundary values need a second walk
  over the function node (same skip-nested-function rule as `complexity`).
- `case_designs` has one row per planned function with `diagram_text`; the
  service already refuses writes off the DESIGN stage (`StageNotReached` /
  `StageLocked`) and functions outside the plan (`FunctionNotInPlan`).
- `Finding.path` / `Finding.line` / `Finding.category` (`sast`, `sca`,
  `secret`, `sbom`, `metrics`) and `Finding.in_report`: a SAST finding whose
  line falls inside the function is "associated" to it. Verdicts are locked
  once E3 is left, so the association is stable during E5.
- `gates.GATES[Stage.DESIGN] = not_built`; gates are pure over the analysis
  (no I/O), which rules out re-parsing the source inside the gate.
- Mockup 06: "La consigna te pide" as a bullet list under the diagram
  ("Al menos 5 casos (uno por camino)", boundary of `price ≤ 0` with 0, −1
  and 0.01, "Un caso con entrada maliciosa (hay un hallazgo de validación)");
  right panel "Tus casos, con tus palabras": numbered cases `C1 · …` and the
  button "Aprobar mis casos y pasar a escribir los tests →".

### Brief (`app/workflow/brief.py`) — deterministic, no AI
```
Brief(function, path, line, language, signature, params, complexity,
      min_cases, items: list[BriefItem])
BriefItem(id, kind, line, text, values)        kinds and ids:
  branch   Rn  one per decision/loop node × {true,false} (switch: one per case label)
  boundary Fn  one per comparison against a literal: values = (lit−1, lit, lit+1)
               integers; (lit−step, lit, lit+step) floats with step = 10^-decimals;
               string literal with == / != / === / !==: (literal, "")
  error    En  every throw/raise node; every except/catch handler; every early
               return (a return node whose line < the line of the function's
               last top-level statement)
  malicious Mn one per SAST finding in the report (not false positive) with
               finding.path == path and function.line ≤ finding.line ≤ end line
min_cases = complexity + number of malicious items   (the mockup's 5 = 4 paths + 1)
```
Ids are assigned in source order, so the same source and findings always
give the same brief (tested: two runs, equal). The graph builder gains
`comparisons` (line, text, operator, literal) and `end_line`; `graph_as_dict`
stays additive. Compound expressions (`a > 0 && b <= 10`) give two boundary
items — the walk descends into every operand.

### Pseudocode ("Tus casos, con tus palabras")
The developer writes cases as plain text and DECLARES which brief items each
case demonstrates — the platform never interprets the prose:
```
case_designs += cases JSON [{title ≤ 500 chars, covers: [item ids]}] (≤ 50 cases)
               + brief JSON (snapshot at approval) + approved_at, approved_by_username
PUT  …/cases   (DeveloperUser, only AT design, function in plan)
     titles: control chars stripped, whitespace collapsed, 3..500 chars; ids must
     exist in the CURRENT brief (CaseItemUnknown 422); saving CLEARS any approval;
     audit "design.cases.save"
POST …/cases/approve (DeveloperUser, only AT design)
     recomputes the brief now; every item id covered by ≥ 1 case AND
     len(cases) ≥ min_cases, else BriefNotCovered 422 / CasesTooFew 422;
     stores the brief snapshot + approved_at/by; audit "design.cases.approve"
GET  …/brief?path&function&line (any role) → brief + cases + approval
```
Trade-off surfaced: coverage of the brief is a DECLARATION (a case ticks the
items it covers) rather than a text match — the only deterministic option
without AI; E7 measures the truth of the declaration by line coverage
(docs/workflow-gates.md → E7). Approval carries no separate written
justification: the cases ARE the developer's words and the stage transition
that follows requires its reason; the audit row records actor and function.
Editing after approval reopens it (approval cleared) rather than being
refused — the developer may still be at E5; once E5 is left, `StageLocked`.

### Gate E5 (`gates.leave_design`) — pure, replaces `not_built` for DESIGN
```
for every function in the plan: a case_designs row with approved_at IS NOT NULL
else closed "cases_not_approved"  → errors.workflow.gate.casesNotApproved
```
Approval is where the brief is checked against the live source (the jail is
immutable after ingest), so the gate needs no I/O and stays a pure predicate;
the approval snapshot is what P4's scaffold names its cases from.
`Analysis.case_designs` relationship added (string target like `test_plan`).
Migration `0006_case_briefs`: four nullable columns, no data change.

### Frontend (screen 06)
Left panel gains "La consigna te pide" (bullets from the brief: min cases,
each branch with its line, boundaries with values, error paths, malicious
cases). Right panel: the cases editor — a numbered list (`C1`, `C2`, …), one
text input per case and the brief items as toggle chips under it; "Añadir
un caso", "Guardar mis casos", then "Aprobar mis casos" (enabled when every
item is ticked and the count is met — the server re-checks). Deviation
recorded: the mockup's one button "Aprobar mis casos y pasar a escribir los
tests →" is two actions here — approval is per function, the transition is
per analysis and needs a written reason (`AdvanceStage`, "Pasar a escribir
los tests →", enabled when every planned function is approved). The analyst
sees brief and cases read-only. i18n `design.brief.*`, `design.cases.*`.

### Tests
`tests/test_brief.py`: three real functions copied verbatim as fixtures
(`tests/fixtures/ast/real_*.{py,ts}`, origin in a header comment) with
basis paths counted by hand in the test; boundary extraction on `<, <=, >,
>=, ==, !=, ===, !==`, negative and float literals, chained Python
comparisons, compound expressions; error paths (throw, catch, early return —
the final return is not one); malicious items only for SAST findings inside
the function and never for a false positive; determinism; item ids stable
across runs. `tests/test_cases_api.py`: developer-only, stage guards, unknown
item id → 422, approval refused with an uncovered item / too few cases,
approval clears on edit, `leave_design` closed until every planned function
is approved and open afterwards (gate-skip proof extended: E5 rejected
without approval through the API directly), hostile titles stored as text.
Frontend: brief renders from the payload, chips toggle `covers`, PUT body,
approve button state, read-only for the analyst.

### Addendum (precommit panel, 2026-09-22) — no way out of E5
The security auditor showed a terminal state this section had not
considered: `leave_design` needs every planned function approved, approval
needs a brief AND `min_cases ≤ len(cases) ≤ MAX_CASES`, the plan is locked
once E4 is left and the stages are monotonic — so one planned function the
AST layer refuses (non-wave-1 file Lizard measured, syntax error, > 400
nodes, > 40 deep, > 512 KiB, a name tree-sitter does not find) or with more
basis paths than `MAX_CASES` (was 50) strands the analysis at E5. And the
risk matrix ranks the complex functions first. Decided by `mmarin` ("lo
recomendado"): **fail early at E4** — `test_plan.save_test_plan` parses
every chosen function (`check_briefable`: what `GET …/brief` costs, once,
at the only moment the set is editable) and refuses with a typed 422
naming the function (`test_plan_function_unbriefable`,
`test_plan_function_too_complex`); `MAX_CASES` rises to 200 (a legacy
function with 61 paths is real). Contract change, additive: an `AppError`
MAY carry `context` (bounded strings the UI interpolates as text) — the
error envelope gains an optional field. The threshold E4 checks is the one
approval demands — `min_cases` (basis paths + one per SAST finding inside,
frozen with E3), not the bare complexity. No class of the deadlock remains:
the jail is immutable after ingest, so what parsed at E4 parses at E5.
