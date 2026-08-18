# Workflow gates (E1–E8)

> **Status: DESIGN SURFACE — not yet implemented.**

Gates are enforced SERVER-SIDE: the API rejects any transition whose gate is
unsatisfied. UI state is presentation only.

| Stage | Who | Produces | Gate to leave it |
|---|---|---|---|
| E1 Register | analyst | system metadata (feeds report "Detalles del sistema") | required fields present |
| E2 Ingest | analyst | stored codebase + language/framework detection | ingest completed without fatal error |
| E3 Analyze + triage | analyst | findings (CWE/OWASP/CVSS) + triage verdicts | EVERY finding confirmed or discarded-with-justification |
| E4 Test plan | developer | risk matrix selection + coverage criterion + written rationale | ≥1 function selected, criterion chosen, rationale non-empty |
| E5 Case design | developer | AST flow diagrams + test brief + approved pseudocode | pseudocode covers every brief item; approval recorded |
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

## E7 re-audit rules

1. Coverage (statements + decisions) measured in the sandbox against the E4
   criterion; each brief branch checked by line.
2. Assertion-less / trivial tests detected by our own rules → reject.
3. Mutation testing (Stryker/mutmut/Pitest/Infection) over the branches the
   tests claim to cover. A surviving mutant → gate rejected → back to E5 with
   the exact mutant shown to the developer.
