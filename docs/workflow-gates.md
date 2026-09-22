# Workflow gates (E1–E8)

> **Status: IN_PROGRESS — stage machine, gates for leaving E2/E3/E4/E5, the E4 risk matrix and test plan, the E5 diagrams, brief and cases built 2026-09-22 (`backend/app/workflow/{stages,gates,risk,test_plan,design,brief}.py`); E6–E7's gates land in P4 — until then those stages are CLOSED (fail closed), proven by `backend/tests/test_gates.py` and `test_cases_api.py`.**

## How the machine works (P3)

- The unit that walks the stages is an analysis (one ingested version);
  `Analysis.stage` is born at `code` (E2) because E1 is the project's
  registration. Names, never E-codes, in the API too.
- One endpoint, `POST /api/v1/analyses/{id}/stage/advance` with a written
  reason: the server checks the ROLE that may leave the current stage (E2:
  analyst or admin; E3: analyst; E4–E7: developer), then the reason (ten
  characters after whitespace collapse), then the GATE below; the transition
  writes an audit row `stage.advance` and a refused role writes `authz.denied`.
- Monotonic: there is no endpoint that sets a stage. `report` is final
  (`stage_final`). The E7 → E5 loop is P4's own gated action.
- A gate whose phase has not landed returns `gate_not_built`: the stage cannot
  be left. Phase discipline is enforced by the machine, not by trust.
- The E4 deliverable (test plan) is written only while the analysis IS at
  E4 (`stage_not_reached` before, `stage_locked` after): E5 computes the brief
  against a fixed plan. The E5 deliverables (diagram text, cases, approval)
  follow the same rule. The same lock applies to E3's verdicts once E3 has
  been left — the risk matrix and the brief are computed on them; a
  re-review means a new ingested version (decided by `mmarin`, 2026-09-22).

Gates are enforced SERVER-SIDE: the API rejects any transition whose gate is
unsatisfied. UI state is presentation only. The proof, per the plan (day 13),
is a test suite that tries to skip every gate through the API directly, with
no UI in the loop.

Why so many stages, in the plan's words: the code that arrives never brings
planning, design or tests — only code. The platform rebuilds what was
missing, in the order it should have existed, and the gates make sure the
discipline does not depend on anyone's goodwill.

| Stage | Who | Produces | Gate to leave it |
|---|---|---|---|
| E1 Register | analyst | system metadata (feeds report "Detalles del sistema") | required fields present |
| E2 Ingest | analyst | stored codebase + language/framework detection | ingest completed without fatal error — `gates.leave_code` (built) |
| E3 Analyze + triage | analyst | findings (CWE/OWASP/CVSS) + triage verdicts | EVERY finding confirmed or discarded-with-justification — `gates.leave_analysis` (built) |
| E4 Test plan | developer | risk matrix selection + coverage criterion + written rationale | ≥1 function selected, criterion chosen, rationale non-empty — `gates.leave_plan` (built); the plan save itself refuses a function E5 could never approve (the AST layer cannot parse it, or its basis paths exceed `MAX_CASES` = 200), naming it — `test_plan.check_briefable` (built) |
| E5 Case design | developer | AST flow diagrams (Mermaid, deterministic, editable) + test brief + the developer's cases with approval | every planned function has its cases approved — `gates.leave_design` (built); approval itself (`design.approve_cases`) is refused until every brief item is covered by a case and there are at least `min_cases` cases |
| E6 Test writing | developer | tests (assertions/logic 100% human) over deterministic scaffolds | all planned cases have non-empty test bodies |
| E7 Verification | system | coverage vs. brief + mutation results | coverage meets E4 criterion AND zero surviving mutants AND no assertion-less tests |
| E8 Report | analyst | editable versioned report | analyst signs; export enabled |

## Test brief (deterministic — no AI)

Computed per selected function from the AST + findings
(`backend/app/workflow/brief.py`, built 2026-09-22), as a list of ITEMS with
stable ids in source order:
- signature and parameters;
- cyclomatic complexity (our count, `docs/glossary.md` → Basis path) →
  `min_cases`, plus one per malicious case below;
- `R<n>` — every branch/condition with its line, true AND false (a `switch`
  gives one per case label; a loop gives "enter" and "skip");
- `F<n>` — boundary values from literal comparisons (`age >= 18` → 17, 18,
  19; a float steps by its last decimal; a string under `==` gives the literal
  and the empty string); compound expressions yield one item per comparison;
- `E<n>` — error paths: throw / raise, every except / catch handler, every
  early return (a return above the function's last statement);
- `M<n>` — one mandatory malicious-input case per SAST finding in the report
  (false positives excluded) whose line falls inside the function.

The developer's cases ("Tus casos, con tus palabras") are plain text, one
title per case, and each case DECLARES the item ids it demonstrates. The
platform never interprets the prose: approval checks that the union of the
declarations covers every item and that the case count reaches `min_cases`,
against the brief recomputed from the source at that moment; the brief is
snapshotted on the approved row (P4's scaffold names its cases from it).
Saving the cases again clears the approval. Because the plan save already
refused every function the brief cannot handle (E4 row above), approval
never faces a function it cannot brief — that is what keeps `leave_design`
from becoming a dead end.

E7 verifies the declaration line-by-line via coverage data — compliance is
measured, never judged by eye.

Acceptance for the brief (plan, day 15): briefs for at least three real
functions whose basis paths, counted by hand, match the platform's count —
`backend/tests/test_brief.py` over three functions of this repository copied
verbatim (`widthClass` 3, `mermaid_escape` 7, `risk_matrix` 9).
Contingency: if basis paths cannot be counted reliably, the brief is limited
to functions with cyclomatic complexity ≤ 10 and that limit is recorded as a
non-goal of v1.0.0.

## Flow diagrams (E5)

Generated deterministically from the same AST (JS/TS and Python in wave 1,
tree-sitter, `backend/app/workflow/ast/`) — built 2026-09-22. The graph is
emitted twice from one source: as Mermaid text (the interchange and editing
format the plan names) and as a deterministic layered layout that the UI
draws as class-only SVG (`frontend/src/components/flow-diagram.tsx`) and
the P5 annex will embed server-side. The Mermaid library itself is not used
for rendering: its SVG needs inline styles the app's CSP refuses
(`tasks/phase3-survey.md` §7). The developer may edit the Mermaid text
(`PUT …/diagram`, developer, only AT E5, stored and shown as text); the
picture and the brief are computed from the AST, never from the edited
text. Large functions can produce unreadable diagrams — the same ≤ 10
contingency applies. Limits: files ≤ 512 KiB, nesting ≤ 40, ≤ 400 nodes,
syntax errors inside the function → typed refusal.

## Scaffolds (E6)

Deterministic only: file name, imports and case names derived from the AST
and the approved pseudocode. Jest/Vitest for JS/TS and pytest for Python in
P4; PHPUnit and JUnit in P5. The scaffold never contains an assertion.

## E7 re-audit rules

1. Coverage (statements + decisions) measured in the sandbox against the E4
   criterion; each brief branch checked by line.
2. Assertion-less / trivial tests detected by our own rules → reject.
3. Mutation testing (Stryker/mutmut/Pitest/Infection) over the branches the
   tests claim to cover. A surviving mutant → gate rejected → back to E5 with
   the exact mutant shown to the developer.
4. Coverage below the E4 criterion → also back to E5 (the plan's loop): when
   coverage falls short the problem is almost always case design, not the
   test.
