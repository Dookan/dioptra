# Task: Phase N<letter> — <short name>

## Objective
One to three sentences stating what this task delivers and why. Reference the
phase boundary it belongs to (see docs/development-phases.md).

## Deliverables
Numbered list of files to create or modify, with signatures, types, and
behavioral notes.

1. `backend/app/<module>/<file>.py`
   - `function_name(arg: Type) -> ReturnType`
   - Input/output constraints; typed error variants raised
   - Server-side gate or authz requirements if applicable

2. `backend/tests/<file>_test.py`
   - Specific cases required
   - Edge cases that MUST be covered (hostile-input cases for any surface
     touching audited code)

3. `frontend/src/screens/<screen>.tsx`
   - Mockup anchor in docs/mockups/ it must match
   - i18n keys added to BOTH es.json and en.json

## Constraints
- Hard Rules apply (see CLAUDE.md → Hard Rules): no AI-written tests, no CDN,
  free licenses only, gates server-side, English-only code, hostile-input
  handling.
- Phase boundary constraints (see CLAUDE.md → Current phase status).
- Forbidden approaches, explicit.

## Definition of Done
- [ ] All deliverables implemented; ruff + mypy + oxlint + tsc clean
- [ ] All specified tests passing (pytest / Vitest)
- [ ] Mutation pass on gate/auth/normalizer modules touched (phase-close only)
- [ ] No secrets in diff (Gitleaks clean); locale parity check green
- [ ] `/precommit` returned `READY TO COMMIT`
- [ ] Task-specific item 1
- [ ] CLAUDE.md phase status updated: this task → DONE

## Non-goals (explicit)
- Functionality belonging to later phases
- Tools outside CLAUDE.md → Analysis Tool Source Authority
- New dependencies without license + rationale
- Task-specific non-goal 1

## References
- `CLAUDE.md` → `<section>`
- `docs/<file>.md` → `<section>`
- Relevant OWASP/ASVS/ISO references with numbers
