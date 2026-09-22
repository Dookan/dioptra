# Workflow gates (E1–E8)

> **Status: IN_PROGRESS — stage machine, gates for leaving E2/E3/E4, the E4 risk matrix and test plan built 2026-09-22 (`backend/app/workflow/{stages,gates,risk,test_plan}.py`); E5's gate lands on day 15, E6–E7's in P4 — until then those stages are CLOSED (fail closed), proven by `backend/tests/test_gates.py`.**

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
  against a fixed plan. The same lock applies to E3's verdicts once E3 has
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
| E4 Test plan | developer | risk matrix selection + coverage criterion + written rationale | ≥1 function selected, criterion chosen, rationale non-empty — `gates.leave_plan` (built) |
| E5 Case design | developer | AST flow diagrams (Mermaid, deterministic, editable) + test brief + approved pseudocode | pseudocode covers every brief item; approval recorded |
| E6 Test writing | developer | tests (assertions/logic 100% human) over deterministic scaffolds | all planned cases have non-empty test bodies |
| E7 Verification | system | coverage vs. brief + mutation results | coverage meets E4 criterion AND zero surviving mutants AND no assertion-less tests |
| E8 Report | analyst | editable versioned report | analyst signs; export enabled |

## Test brief (deterministic — no AI)

Computed per selected function from the AST + findings:
- signature and parameters;
- cyclomatic complexity → minimum case count (basis paths);
- every branch/condition with its line, to cover true AND false;
- boundary values extracted from literal comparisons (`age >= 18` → 17, 18, 19);
- error paths (throw / early return / catch);
- associated SAST findings → mandatory malicious-input case.

E7 verifies the brief line-by-line via coverage data — compliance is measured,
never judged by eye.

Acceptance for the brief (plan, day 15): briefs for at least three real
functions whose basis paths, counted by hand, match the platform's count.
Contingency: if basis paths cannot be counted reliably, the brief is limited
to functions with cyclomatic complexity ≤ 10 and that limit is recorded as a
non-goal of v1.0.0.

## Flow diagrams (E5)

Generated deterministically from the same AST (JS/TS and Python in wave 1) as
Mermaid text, rendered by the bundled Mermaid library (MIT) — no diagram
service. The developer may edit the diagram; the brief is computed from the
AST, never from the edited diagram. Large functions can produce unreadable
diagrams — the same ≤ 10 contingency applies.

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
