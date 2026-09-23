# Workflow gates (E1–E8)

> **Status: IN_PROGRESS — every gate E2→E7 is built (2026-09-22): the stage machine, the E4 risk matrix and test plan, the E5 diagrams, brief and cases, the E6 scaffolds and test files, and the E7 sandbox run with its re-audit (`backend/app/workflow/{stages,gates,risk,test_plan,design,brief,authoring,verify}.py`, `workflow/scaffold/`, `backend/app/sandbox/`). E8 has no gate of its own — the analyst signs. Proven by `backend/tests/{test_gates,test_cases_api,test_tests_api,test_verify,test_sandbox,test_sandbox_live}.py`.**

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
| E6 Test writing | developer | tests (assertions/logic 100% human) over deterministic scaffolds | every approved case has a body the developer wrote — `gates.leave_tests` (built) |
| E7 Verification | system | coverage vs. brief + mutation results | the LATEST run of every planned function passed — `gates.leave_verification` (built) |
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

The success edge of a `try` carries no label, so a function whose whole body
is a `try/catch` yields one item (the handler) and `min_cases` 2: the happy
path is required by the count, not named as an item. Observed on the MINCYT
frontend's `validarUrl`; revisit if E7 coverage shows the distinction matters.

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

Built 2026-09-22 (`backend/app/workflow/scaffold/`). Deterministic only: file
name, imports and one named case per APPROVED case, derived from the AST and
from the design snapshot. Vitest for JS/TS and pytest for Python in P4;
PHPUnit and JUnit move to the second cycle with the PHP/Java cut (2026-09-22). **The scaffold never contains an assertion**, test
data or an oracle. Per case it writes a `TODO(developer)` line and, above it,
one comment per brief item that case declared, repeating the item's own text,
its detail and its boundary values — the brief's INPUTS, which the developer
is required to exercise anyway, never an expected value.

- One file per planned function:
  `<stem>.<function>.<6 hex>.dioptra.test.<ext>` /
  `test_<stem>_<function>_<6 hex>_dioptra.py`. The six hex characters are a
  digest of `path:line`: the name is otherwise built from basenames, so
  `components/index.ts::render` and `utils/index.ts::render` would collide —
  and E7 copies every planned function's file into ONE run directory. The same
  design row always yields the byte-identical file, checked across processes
  with different hash seeds (an in-process comparison cannot see a `set()`
  ordering regression).
- The case id opens every case name (`it("C1 · …")`, `def test_c1_…`): that
  is how the gate finds a case after the developer rewords the title, and the
  generated comment says so.
- Case titles are the developer's words and the brief items are audited
  source: both are escaped AT THE GENERATOR'S BOUNDARY
  (`scaffold/text.py`) before becoming an identifier, a string literal or a
  comment — quotes, backslashes, `*/` and the JavaScript line terminators
  U+2028/U+2029 included.
- The generated comments are ENGLISH, unlike the UI. The rule (CLAUDE.md →
  English everywhere in code) and the mechanism agree: the file is compared
  byte for byte, so its content may not depend on the reader's UI language.
- A function whose Python module path is not importable (a `my-lib/` segment)
  gets a `TODO(developer)` import line instead of a broken import.

The developer stores their file through `PUT …/tests` (developer, at E6 —
or at E7 for a function the verification loop reopened), as TEXT, control
characters stripped, size-capped. It is NEVER executed outside the E7
sandbox. `gates.leave_tests` parses the stored text with the same tree-sitter
layer the briefs use and asks one question per case: is there a statement of
its own — not a comment, not the title string, not `pass`/`...`, and not a
skipped case (`it.skip`)? A file that does not parse leaves every case
unwritten; the gate never raises. Whether a test PROVES anything is E7's
measurement, not this gate's opinion.

## E7 re-audit rules

Built 2026-09-22 (`backend/app/workflow/verify.py`, `backend/app/sandbox/`).
Four questions per planned function, in this order; any "no" closes the gate
and each one is shown to the developer BY NAME, never as a score:

1. **Did the tests pass?** Read from the run's JUnit document.
2. **Does every case assert something?** Our own rule over the test file's AST
   (`scaffold/inspect.py::assertion_free_cases`): a case whose body calls no
   `expect`/`assert` family function, or holds no `assert` statement, is
   rejected. Deliberately generous — whether the assertion is a GOOD one is
   question 4's answer, not this one's.
3. **Coverage.** Measured in the sandbox and normalised to one shape for both
   languages. The E4 criterion is applied to the module (`statements` ⊂
   `decisions` ⊂ `paths`), AND every brief item's line is checked
   individually: an item counts only when its line executed *and* its branch
   was fully taken — a half-taken branch covers neither side.
4. **Mutation.** Stryker (JS/TS) / mutmut (Python) over the module under test.
   A surviving mutant rejects the gate, and the developer is shown the exact
   mutant with its diff. **Equivalent mutants** (P5, found by the walk of the
   platform on itself): some mutants no test can kill — `"ascii"` → `"ASCII"`
   is the same codec, `ensure_ascii=None` is `False` — and a zero-tolerance
   gate would then close forever. The developer may excuse ONE survivor of the
   function's latest run with a written reason (`POST …/mutants/equivalent`,
   developer only, audit row `verification.mutant.equivalent`, the same
   ten-character floor as every verdict); it takes effect on the NEXT run —
   the run rows stay immutable and the gate a row predicate, so the
   developer re-runs to prove it — and the run records what was excused so
   the report shows it beside the real survivors. An excusal names the mutant
   by id AND by its text at the time of the mark: ids are index-based, so a
   tool bump that renumbers them makes the excused mutant a real survivor
   again rather than silently excusing a different one. The judgement is a
   person's and it is on the record, exactly like a triage verdict.

The loop back to E5 is an explicit action, `POST …/reopen-design` (developer,
written reason, audited) — **not** a backwards stage move: the machine stays
monotonic. It clears the approval of the functions whose latest run failed and
sets `CaseDesign.reopened_at`, which is what lets E5's and E6's writers accept
those functions again while the analysis sits at E7 — the cases, their
approval AND the test file, in that order. The flag is cleared by the next
PASSED run of that function (not by the approval: the developer still has to
rewrite the tests after re-approving — a defect the P5 walk on the platform
itself found and fixed, 2026-09-22); until every planned function has a
PASSED latest run, the gate stays closed.

The run itself happens in the WORKER, never in a request: it starts
containers, and only the worker holds the Docker socket. The handler enqueues
and returns.

**Recorded non-goal of v1.0.0**: the sandbox installs nothing of the audited
project, so a test that needs the project's own dependencies cannot run —
`npm install` on a hostile tree executes lifecycle scripts, which is remote
code execution by design (`tasks/phase4-survey.md` §5).
