# Task: Phase 4 — E6–E7

> **Status: DONE — closed 2026-09-22; day 16 in commit `576993f` and day 17 in
> the commit that carries this file. Deadline 2026-09-15 (plan days 16–17,
> critical path), passed. Survey `tasks/phase4-survey.md` signed off by
> `mmarin` 2026-09-22.** Both days on the critical path; day 16 opened with
> the mandatory sandbox investigation gate.

## Objective
Close the cycle where the workflow stops being theoretical: the developer
writes tests over deterministic scaffolds (E6), the platform runs them in a
sandbox, measures coverage branch by branch against the E4 criterion and
re-audits the tests with mutation testing (E7). A surviving mutant
demonstrably rejects the gate.

## Deliverables
1. **Day 16 — sandbox investigation gate, then E6 scaffolds** — BUILT 2026-09-22 (`tasks/phase4-survey.md`, `backend/app/workflow/scaffold/{__init__,text,inspect}.py`, `backend/app/workflow/authoring.py`, `backend/alembic/versions/0007_test_files.py`, `frontend/src/screens/test-writing-screen.tsx`)
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
   - Gate to leave E6: every approved case has a body the developer wrote —
     `gates.leave_tests`, which PARSES the stored text (tree-sitter) and never
     executes it. Mockup anchor: "Escribir los tests (E6)".
   - **Deviation recorded**: the scaffold is one file PER PLANNED FUNCTION
     (`<stem>.<function>.dioptra.test.<ext>`), not one per module — two
     planned functions in one file would otherwise collide. The case id opens
     every case name so the gate still finds a case the developer reworded.
   - **Decision recorded**: the generated comments are English, unlike the
     UI. The rule and the mechanism agree — the file is compared byte for
     byte, so it may not depend on the reader's UI language.
   - **Carried into day 17 from the precommit panel**: `leave_tests` is the
     first gate that is not a pure row predicate — it parses every planned
     function's stored file on each advance attempt (bounded, developer
     authored, reachable only from `stages.advance` and `GET …/test-files`,
     and the bound is now stated in `docs/threat-model.md`). Day 17 stores the
     per-case result when the file is SAVED, which turns the gate back into a
     row predicate and takes the parse out of the request entirely.
   - **Open question for `mmarin`**: CLAUDE.md's Hard Rule enumerates the
     scaffold as "file, imports, and case names". The generator additionally
     emits a header comment, the `describe()`/docstring wrapper and one
     comment per declared brief item repeating the item's text and boundary
     values. That is within the rule's intent (no assertion, no oracle) and
     `docs/workflow-gates.md` now says it explicitly, but the Hard Rule's own
     wording is narrower than what is emitted. Decide whether to widen it.

2. **Day 17 — E7 sandbox, coverage, mutation** — BUILT 2026-09-22 (`backend/app/sandbox/{workspace,executor,results,errors}.py`, `docker/sandbox.Dockerfile` + `docker/sandbox/`, `backend/app/workflow/{verify,verify_job}.py`, `backend/alembic/versions/0008_verification_runs.py`, `frontend/src/screens/verification-screen.tsx`)
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
   - **Deviations recorded.** (a) The module under test is copied FLAT into the
     attempt directory and the scaffold imports it by basename: mutmut refuses
     outright to mutate a module whose dotted path starts with `src.`, and one
     attempt holds exactly one planned function so nothing can collide. This
     changed day 16's generated imports. (b) The survey's "sized tmpfs for the
     runs root" cannot be a Compose setting — a sibling container's mount is
     resolved by the HOST daemon, so a tmpfs declared in the worker would be
     invisible to the sandbox. The size bound is an OPERATOR step on the host
     and `docker/docker-compose.yml` carries the command. (c) Each tool's
     output shape is normalised by a wrapper INSIDE the image
     (`docker/sandbox/run-{python,js}.sh`), so the host never learns a tool's
     format and a version change stays a one-file problem.
   - **Carried over from day 16 and DONE**: `leave_verification` is a pure row
     predicate — the worker measures and writes the verdict down. (The same
     treatment for `leave_tests` is left as it is: it is correct, bounded, and
     its cost is documented in `docs/threat-model.md`.)
3. Tests — `backend/tests/test_scaffold.py` and `test_tests_api.py` (day 16, written), `test_sandbox.py`, `test_verify.py` (day 17)
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
- [x] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [x] All specified tests passing (pytest / Vitest), including twelve live
      sandbox tests behind the `sandbox` marker
- [x] Mutation pass on `verify.py` and the gate module (phase-close) — we apply
      to ourselves what we demand of the factory. mutmut 3.8 over
      `gates / verify / brief / triage / test_plan / sandbox.results`,
      2026-09-22: **1 276 mutants, 1 192 killed (93.4 %)**, and
      **`gates.py` has ZERO survivors** — no mutant of any gate lives. Four
      passes: the first left 206 survivors, and each round turned the
      behavioural ones into tests (83 % → 88.9 % → 93 % → 93.4 %). What the
      rounds actually found, and what was written because of it:
      the sandbox-error path was never exercised (so the `finally` that
      discards the attempt directory when the run RAISES was unpinned); the
      reopen loop was only tested with a single failing function, so nothing
      proved that a function which PASSED keeps its approval; the audit rows
      of `verification.run` / `verification.reopen` did not have their actor
      id, role, target and source IP asserted; `POST …/verify` had no
      successful path at all; and `results.py` had never seen a half-shaped
      document (a `statementMap` without its counters, a branch with no line
      of its own, a survivor entry with no fields, non-UTF-8 JUnit, a
      self-closing `<testcase/>` followed by a failing one).
      The 84 remaining survivors, all inspected: 23 in `brief.py`, 12 in
      `test_plan.py` and 5 in `triage.py` are P3's, already classified in
      `tasks/phase3-workflow-e1-e5.md`; the 44 new ones are
      **(a)** `or True` guards mutmut cannot make observable, **(b)** the
      `detail` string of a typed error, which is log-only — the client sees
      `{code, message_key}` (the same class as P3's 13), **(c)** cap
      off-by-one (`[:255]`→`[:256]`, `[:400]`→`[:401]`), observable only at
      exactly the boundary, **(d)** default values for a dict key that is
      present in every reachable document (`item.get("id", "")` →
      `"XXXX"`), **(e)** `continue`→`break` in loops whose fixtures hold one
      element after the skipped one, and **(f)** `decode("utf-8")` →
      `decode("UTF-8")`, which is exactly equivalent: Python codec names are
      case-insensitive
- [x] No secrets in diff (Gitleaks clean on the tree AND the history); locale
      parity check green; the licence gate also run INSIDE the sandbox image
      (230 packages, all free) — its runners are installed at build time and
      are invisible to the repository's own lockfiles, so `scripts/ci.sh`
      mounts the gate into the image. Where the image is not built that stage
      prints a warning and passes, so it is BLOCKING only on a host that has
      built it; the image's own `package-lock.json` is committed, so the tree
      it checks is the tree that ships
- [x] `/precommit` returned `READY TO COMMIT` (coverage adversary included).
      Two rounds, and the panel earned its keep both times. Day 16: four UI
      drifts and a locale-parity allowlist four keys short. Day 17: the E7
      gate scored "nothing was measured" as "everything passed" (no result
      document reads as 100 % of no lines, no failing test, no surviving
      mutant, and the container's exit code was discarded); the audited code
      could author its own verdict, because the three result files were
      produced in the one directory it can write, as the same user;
      `POST …/reopen-design` enforced its ten-character justification only in
      the browser; verifying after a reopen crashed the job and rolled back
      every row already written for the batch; a NUL in the audited code's
      stderr would have done the same through the PostgreSQL driver; JUnit
      failure attribution bled across `</testcase>`, so a passing case
      inherited the next one's failure; **three of the nine escape probes
      proved nothing** (`capsh` is not in the image, `mount -t proc` is
      refused even privileged, and a fork bomb written with literal
      backslash-n died of a `SyntaxError` before forking) and the rewritten
      table had silently dropped the CPU, memory and `/proc` probes the
      PENDING version listed. Every one is fixed, and every escape probe is
      now checked to be ATTRIBUTABLE — it fails under the shipped flags and
      succeeds when the flag it targets is removed. The coverage adversary
      then found that `planned_keys`, the defence added DURING the panel, had
      no test at all; writing one exposed a fail-OPEN the refactor had
      introduced (a `functions` column that is not a list passed a truthiness
      guard and then iterated zero times, opening the gate)
- [x] A surviving mutant demonstrably rejects the E7 gate — proven twice: on a
      crafted run (`test_verify.py::test_a_surviving_mutant_is_shown_to_the_developer_by_name`)
      and on a real mutmut run against a real module
      (`test_sandbox_live.py::test_a_weak_suite_leaves_surviving_mutants`)
- [x] Every sandbox escape test negative and recorded in docs/threat-model.md
      (nine probes, run 2026-09-22 with the shipped argv)
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
