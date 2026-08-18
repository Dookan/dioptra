---
description: Fire the Dioptra review panel over the uncommitted diff, fix slight findings, surface big ones for a plan, else pass green.
argument-hint: "[optional scope: a path, or 'staged' — default = whole working-tree diff]"
---

You are running Dioptra's pre-commit review gate. Do NOT commit anything — this is a review gate, not a commit. Per the repo Git Rules, commit only when the user explicitly asks.

## Scope

Review the uncommitted change. Scope = `$ARGUMENTS` if given (a path, or `staged` → review only `git diff --cached`); otherwise the whole working-tree diff. First run `git status` + `git diff --stat` (scoped) to see what changed. If there is no change in scope, say so and stop.

## Panel

Select agents by what the diff touches:

- **Always:** `dioptra-security-auditor`, `dioptra-invariant-checker`, `dioptra-qa-verifier`.
- **If the diff adds/changes code with behavior to verify or tests:** also `dioptra-coverage-adversary`.
- **If the diff touches `frontend/src/**`, tokens, locales, or assets:** also `dioptra-mockup-fidelity`.
- Skip an agent only when it is plainly irrelevant (e.g. mockup-fidelity on a pure-backend diff) and say which you skipped and why.

**Concurrency rule — the read-only agents run together; the writer runs alone.** `dioptra-coverage-adversary` MUTATES tracked source files to verify "would a revert stay green?" (it backs up → mutates → tests → restores). Every other panel agent only READS. If a reader samples a file during the adversary's mutation window, it reports a false finding against transient mutated code. Therefore:

1. Fire the **read-only** agents (`dioptra-security-auditor`, `dioptra-invariant-checker`, `dioptra-qa-verifier`, and `dioptra-mockup-fidelity` when selected) CONCURRENTLY — one message, multiple Agent calls.
2. Run `dioptra-coverage-adversary` in a SEPARATE, non-overlapping step (after the readers return, or before they start) — never in the same concurrent batch as any reader.
3. After the adversary returns, confirm the working tree is clean of its mutations (`git diff --stat` of the file(s) it touched matches the pre-panel state; no stray `# MUTATION` markers) before trusting any result.

Give each agent the scope and tell it to report findings with `file:line`, be proportional, and pass clean concisely rather than manufacture findings.

## Triage each finding — the core policy

After the panel returns, sort every finding into exactly one bucket:

**SLIGHT → fix it now, no asking.** Mechanical, unambiguous, single obviously-correct answer, reversible, no behavior/API/schema/trust change. Examples: a missing HTML-escape on a snippet render the docs already mandate, a typo, a stale doc pointer, a missing locale key with an obvious translation, adding the exact regression test the coverage-adversary already specified, a missing entry in the license allowlist for a dep already approved in the plan. Apply the fix, then re-verify it (re-run the affected test, or re-fire just that one agent).

**BIG → stop and bring me a plan; do NOT edit yet.** Anything touching auth/session BEHAVIOR, the sandbox configuration, ingestion validation, gate logic, the report signing/versioning model; an API or DB-schema change; a multi-file refactor; a design choice with more than one reasonable option; or any fix that could itself introduce risk. Present a short plan (what, why, options + your recommendation) and wait for the go-ahead from `mmarin`.

**When unsure which bucket → treat as BIG and ask.** Default to surfacing, not silently changing security/gate/report surface.

**NONE → pass green.** No fixes, no plan — just report the clean verdict per agent.

## Output

End with a one-screen summary:
1. Which agents ran (and any skipped, with reason).
2. Each agent's verdict line.
3. **Fixed (slight):** what you changed + the re-verification result. **Needs decision (big):** the plan(s) awaiting an answer. **Green:** agents with no findings.
4. A final line: `READY TO COMMIT` only if every agent is green AND nothing is awaiting a decision; otherwise `BLOCKED — <n> awaiting decision`.
