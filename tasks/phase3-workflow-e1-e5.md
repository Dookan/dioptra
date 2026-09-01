# Task: Phase 3 — Workflow E1–E5

> **Status: DESIGN — deadline ◆ "P2+P3" 2026-09-11 (plan days 13–15); starts
> the moment P2 closes.** Day 15 is on the critical path.

## Objective
Bring the reconstruction workflow up to case design: the developer plans what
to test (E4) against a risk matrix, sees the flow diagram and the test brief
for each chosen function, writes the pseudocode and gets it approved (E5). All
gates enforced by the API.

## Deliverables
1. **Day 13 — E4 risk matrix + gates** — `backend/app/workflow/{stages,gates,risk}.py`, `frontend/src/screens/test-plan-screen.tsx`
   - Risk matrix = cyclomatic complexity × findings × criticality, from the
     P1 metrics and findings; the developer selects functions, chooses the
     coverage criterion per module (statements / decisions — default 100 %
     decisions / paths) and writes the rationale.
   - Plan-first gate applies (gate logic, and the phase exceeds 200 LOC):
     `tasks/phase3-survey.md` with `## Verdict` BEFORE the stage-machine edits.
   - Stage machine E1 → E8, monotonic, server-side gates per
     docs/workflow-gates.md; every transition records actor + justification
     in the audit log; typed `GateError` variants → explicit status codes.
   - **Proof**: a test suite that tries to skip every gate through the API
     directly (no UI) and is rejected each time.
   - Mockup anchor: "Plan de pruebas (E4)"; stepper uses stage NAMES, never
     E-codes; "siguiente paso" banner.
2. **Day 14 — E5 AST → Mermaid** — `backend/app/workflow/ast/{js_ts,python}.py`, `backend/app/workflow/diagrams.py`
   - AST parsing of the prioritized functions (JS/TS and Python in wave 1);
     deterministic Mermaid flowchart text (same input → byte-identical
     output); rendered in the UI by the bundled Mermaid library (MIT —
     license + rationale in `package.json`); editable by the developer, but
     the brief is computed from the AST, never from the edited text.
3. **Day 15 — E5 brief + pseudocode** — `backend/app/workflow/brief.py`, `frontend/src/screens/case-design-screen.tsx`
   - Brief per function: signature and parameters; basis paths (McCabe) →
     minimum case count; every branch/condition with its line (true AND
     false); boundary values from literal comparisons (`age >= 18` → 17, 18,
     19); error paths (throw / early return / catch); mandatory
     malicious-input case for each associated SAST finding. No AI.
   - Pseudocode editor with approval; gate: pseudocode covers every brief
     item AND approval recorded.
   - Mockup anchor: "Diseño de casos (E5)" / "¿Qué vamos a probar?".
4. Tests — `backend/tests/test_gates.py`, `test_risk_matrix.py`, `test_ast_*.py`, `test_brief.py`
   - Gate-skip suite (deliverable 1); AST fixtures with hand-counted basis
     paths; boundary extraction on `<, <=, >, >=, ==, !=` including compound
     expressions; determinism (two runs, identical Mermaid and brief);
     hostile source (deeply nested, huge, syntactically broken) handled as
     typed errors within time limits.

## Constraints
- Hard Rules: gates server-side; the platform never writes tests; no AI;
  deterministic analysis only.
- Wave 1 languages only (JS/TS, Python). Own parsers or libraries with a
  free license and a rationale comment.
- Forbidden: computing the brief from anything the developer can edit.

## Definition of Done
- [ ] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [ ] All specified tests passing (pytest / Vitest)
- [ ] Mutation pass on `gates.py` and `brief.py` (phase-close)
- [ ] No secrets in diff (Gitleaks clean); locale parity check green
- [ ] `/precommit` returned `READY TO COMMIT` (including mockup fidelity)
- [ ] `tasks/phase3-survey.md` written and signed off before the gate edits
- [ ] Briefs produced for at least THREE real functions of the P1 project
      whose basis paths, counted by hand, match the platform's count (plan day 15)
- [ ] The gate-skip suite proves every E1–E5 transition is rejected without its gate
- [ ] CLAUDE.md phase status + docs/development-phases.md: Phase 3 → DONE with date and commit

## Non-goals (explicit)
- Scaffolds, sandbox, coverage, mutation (P4)
- PHP/Java AST (P5); Go, C#/.NET (out of scope)
- Any diagram service or CDN-loaded renderer

## Contingency
- Basis paths miscounted or Mermaid unreadable on large functions → limit E5
  to cyclomatic complexity ≤ 10 and record it here as a non-goal of v1.0.0
  (docs/development-phases.md → Contingencies).

## References
- `CLAUDE.md` → Hard Rules, Agent Behavioral Rules
- `docs/workflow-gates.md`, `docs/ui-model.md`, `docs/mockups/index.html`
- McCabe basis-path testing; ISO/IEC/IEEE 29119 test design; OWASP ASVS 4.0.3 V4.1
