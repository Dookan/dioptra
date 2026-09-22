# Task: Phase 4 — E6–E7

> **Status: IN_PROGRESS — started 2026-09-22 (deadline 2026-09-15, plan days
> 16–17, passed); survey `tasks/phase4-survey.md` SIGNED OFF by `mmarin`
> 2026-09-22 (§5 answered: build without pruning, dependency-less tests as a
> v1.0.0 non-goal, Stryker + mutmut confirmed).** Both days on the critical
> path; day 16 opened with the mandatory sandbox investigation gate.

## Objective
Close the cycle where the workflow stops being theoretical: the developer
writes tests over deterministic scaffolds (E6), the platform runs them in a
sandbox, measures coverage branch by branch against the E4 criterion and
re-audits the tests with mutation testing (E7). A surviving mutant
demonstrably rejects the gate.

## Deliverables
1. **Day 16 — sandbox investigation gate, then E6 scaffolds** — `tasks/phase4-survey.md`, `backend/app/workflow/scaffold/{jest,pytest}.py`, `frontend/src/screens/test-writing-screen.tsx`
   - `tasks/phase4-survey.md`: read-only survey, sandbox design pseudocode
     (image, user, mounts, limits, timeout, result extraction) and
     `## Verdict`, signed off BEFORE any sandbox edit. No exception.
   - Scaffolds derived ONLY from the AST + approved pseudocode: file name,
     imports, one named case per brief item (Jest/Vitest for JS/TS, pytest
     for Python). Never an assertion, never data, never logic. The approved
     `case_designs.cases[].title` and the `brief` snapshot are the inputs
     (P3 day 15): titles are one-line text but still hold quotes,
     backslashes, `*/` and any Unicode — the generator slugs/escapes them at
     ITS boundary before they become identifiers or strings in a test file.
   - Gate to leave E6: every planned case has a non-empty body written by the
     developer. Mockup anchor: "Escribir los tests (E6)".
2. **Day 17 — E7 sandbox, coverage, mutation** — `backend/app/sandbox/`, `docker/sandbox-*.Dockerfile`, `backend/app/workflow/verify.py`, `frontend/src/screens/verification-screen.tsx`
   - Docker sandbox: `--network none`, CPU / RAM / pids limits, read-only
     rootfs + tmpfs workdir, timeout, non-root user, `no-new-privileges`, no
     Docker socket, no host mounts beyond the workspace; only declared result
     files read back, size-capped, parsed as data.
   - Coverage (statements + decisions) vs. the E4 criterion, each brief branch
     checked by line; own rules for assertion-less / trivial tests → reject.
   - Mutation testing (Stryker for JS/TS, mutmut for Python) over the claimed
     branches; a surviving mutant → gate rejected → back to E5 with the exact
     mutant shown ("rompimos el código a propósito; un buen test debe
     fallar"). Coverage short → back to E5 too.
   - **Sandbox escape tests** executed and recorded in docs/threat-model.md →
     Sandbox escape tests (network, FS writes, fork bomb, privilege
     escalation, socket/host mounts, exfiltration via result files).
   - Mockup anchor: "Verificación (E7)".
3. Tests — `backend/tests/test_scaffold.py`, `test_sandbox.py`, `test_verify.py`
   - Scaffold determinism and assertion-freedom; the gate rejects an
     assertion-less test, a surviving mutant, coverage below criterion; every
     escape test from the threat-model table automated where the host allows.

## Constraints
- Hard Rules: the platform MUST NOT write tests; audited code executes ONLY in
  the sandbox; plan-first gate is mandatory for sandbox work.
- Wave 1 only (JS/TS, Python). Stryker / mutmut licenses verified in CI.
- Forbidden: running the audited tests on the API host; relaxing a sandbox
  limit to make a test pass.

## Definition of Done
- [x] `tasks/phase4-survey.md` written and signed off before the sandbox edits
      (written and signed off 2026-09-22, `mmarin`)
- [ ] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [ ] All specified tests passing (pytest / Vitest)
- [ ] Mutation pass on `verify.py` and the gate module (phase-close) — we apply
      to ourselves what we demand of the factory
- [ ] No secrets in diff (Gitleaks clean); locale parity check green
- [ ] `/precommit` returned `READY TO COMMIT` (coverage adversary included)
- [ ] A surviving mutant demonstrably rejects the E7 gate on the P1 project
- [ ] Every sandbox escape test negative and recorded in docs/threat-model.md
- [ ] CLAUDE.md phase status + docs/development-phases.md: Phase 4 → DONE with date and commit

## Non-goals (explicit)
- PHPUnit/JUnit scaffolds, Infection, Pitest (P5)
- Report sections for test debt and annexes (P5)
- Any form of generated assertion, test data or oracle

## Contingency
- A positive escape test → **no release**; fixed even if it consumes the whole
  buffer (CLAUDE.md → Release rules).

## References
- `CLAUDE.md` → Hard Rules, Agent Behavioral Rules, Release rules
- `docs/workflow-gates.md` → E7 re-audit rules; `docs/threat-model.md` → Test sandbox, Sandbox escape tests
- OWASP ASVS 4.0.3 V1.14 (configuration architecture), V14.1; ISO/IEC/IEEE 29119
