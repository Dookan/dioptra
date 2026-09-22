# Phase 4 survey — E6 scaffolds and the E7 sandbox

> Plan-first investigation gate (CLAUDE.md → Agent Behavioral Rules; the work
> plan marks day 16 as non-negotiable). Read-only survey + design pseudocode +
> `## Verdict`, written BEFORE any edit. Read: `backend/app/analysis/runners/`
> (executor, base, tools), `docker/{analysis.Dockerfile,docker-compose.yml}`,
> `backend/app/workflow/{design,brief,gates,models}.py`,
> `docs/threat-model.md` (rows Test sandbox, Analysis containers, Sandbox
> escape tests), `docs/workflow-gates.md` (E6, E7), `tasks/phase4-e6-e7.md`.

## §1 What exists and can be reused

- **A hardened container executor already ships** (`runners/executor.py`,
  P1): `docker run --rm --name … -w /tmp --network none --read-only --tmpfs
  /tmp:rw,size=256m --memory/--memory-swap (equal, no swap) --cpus
  --pids-limit --cap-drop ALL --security-opt no-new-privileges --user
  <non-root> -v <jail>:/work:ro -v <out>:/out:rw -e HOME=/tmp`, a timeout
  that KILLS THE NAMED CONTAINER (not just the client), output read back
  from `/out` with a byte cap, and `ToolStatus` coverage rows for MISSING /
  FAILED / TIMEOUT. The E7 sandbox is this executor with a different image,
  a writable workspace and stricter limits — not a second implementation.
- **Only the worker holds the Docker socket** (`docker-compose.yml`); the API
  never does. E7 runs in a job, like the analysis pipeline.
- **The jail is read-only for analysis** and immutable after ingest. Tests
  must NOT be written into it: the sandbox needs a separate, writable run
  directory per attempt (the jail stays the evidence of what was audited).
- **E5 hands over exactly what a scaffold needs**: `case_designs.brief`
  (the snapshot taken at approval: items with ids, kinds, lines, values) and
  `cases[] = {title, covers[]}`, plus the plan's `(path, function, line)`
  and the language from the file suffix. Nothing else is needed, and nothing
  else may be used — the scaffold is deterministic.
- **Gates**: `gates.GATES[Stage.TESTS]` and `[Stage.VERIFICATION]` are
  `not_built` (closed by construction), so nothing reaches E8 before this
  phase lands. `leave_design` is the model to copy: a pure predicate over
  rows, never I/O.

## §2 Threat model deltas (E7 vs the analysis runners)

The analysis containers PARSE hostile code; the sandbox EXECUTES it. Every
delta below is a control that does not exist yet:

| Delta | Why it matters | Control |
|---|---|---|
| The workspace must be writable (the runner writes coverage/mutation output, npm/pytest write caches) | A writable mount is the obvious escape lever, and an UNBOUNDED one is a disk-exhaustion DoS against the host (PostgreSQL included) | `--read-only` root stays; ONE writable mount, the per-attempt run dir, `nosuid,nodev` where the daemon allows it; `/tmp` tmpfs sized and `noexec` is NOT possible (test runners exec there) — so the run dir is the only writable path and it is discarded after extraction. **It is size-bounded**: the runs root is a sized tmpfs declared in `docker/docker-compose.yml` (`sandbox_runs_size`, default 512m, per-attempt dirs inside it), so a test that writes forever hits ENOSPC in its own mount and dies with the attempt — never the host filesystem. `docs/threat-model.md` → Test sandbox names resource exhaustion (D) as in scope |
| Dependencies of the audited project | `npm install` runs arbitrary lifecycle scripts — this is remote code execution by design | **No installation, ever.** The sandbox image ships the runners (vitest/jest, pytest, coverage, stryker, mutmut) preinstalled; the audited tree is mounted read-only and only the developer's test files plus the module under test are copied into the run dir. A project whose tests need its own dependencies is a recorded non-goal of v1.0.0 (the brief targets pure functions; the risk matrix already ranks those first) |
| Time and CPU | A test can spin forever or fork-bomb | Same `--cpus/--memory/--pids-limit`, a SHORTER timeout than analysis (default 120 s, `sandbox_timeout_seconds`), and the named-container kill already implemented |
| Results | The result files are attacker-controlled data | Only declared file names are read back (`coverage-final.json`, `junit.xml`, `mutation.json`), each size-capped and parsed as DATA with the same defensive parsing as SARIF; never `eval`, never a plugin that executes project config |
| Project config in the tree | `vitest.config.js`, `conftest.py`, `pytest.ini`, `package.json` can point the runner anywhere and run code at collection time | The runner is invoked with OUR config (`--config` / `-p no:cacheprovider -c <our ini>` / `--rootdir`), the audited config files are NOT copied into the run dir, and `conftest.py` from the tree is never copied (same discipline as the gitleaks `.gitleaksignore` strip in P1) |
| The image itself | A second image to ship air-gapped | One `docker/sandbox.Dockerfile`, pinned versions, checksum-verified downloads, non-root uid 10001, no network at build-time runtime check |

## §3 Design — E6 scaffolds (deterministic, no assertions)

```
scaffold(design) -> ScaffoldFile
    language from the path suffix (wave 1: js/ts -> vitest, py -> pytest)
    file name: <stem>.dioptra.test.<ext>  /  test_<stem>_dioptra.py
    imports: the module under test by RELATIVE path, nothing else
    one case per APPROVED case (title -> a slug + the title as the case name):
        it("C1 · <title>", () => { /* TODO(developer): … */ })
        def test_c1_<slug>(): ...  # TODO(developer)
    body: a single TODO comment naming the brief items the case declared
    never an assertion, never data, never a fixture
determinism: same design row -> byte-identical file (tested twice)
```
Endpoints: `GET …/scaffold?path&function&line` (developer, at E6, returns the
generated text + the stored one), `PUT …/tests` (developer, at E6, stores the
developer's file content as TEXT, size-capped, control chars stripped,
audit `tests.save`). Gate `leave_tests`: every approved case has a non-empty
body in the stored file — checked by our own parser over the stored text
(case name present AND at least one statement that is not the TODO comment),
never by executing it.

## §4 Design — E7 verification

```
verify(analysis) -> VerificationRun              (worker job, never in the request)
    run_dir = <data>/runs/<analysis>/<attempt>/  (writable, discarded after)
    copy: the module under test — read through `ast/source.py::load_source`
          (resolve() + is_relative_to(jail) + size cap), because the path
          comes from tool output and is hostile-influenced — plus the
          developer's stored test file and OUR runner config. Nothing else.
    docker run <sandbox image> --rm --name <killable> --network none --read-only
        --tmpfs /tmp:rw,size=256m  -v run_dir:/run:rw  -w /run
        --memory/--memory-swap (equal, no swap) --cpus --pids-limit
        --cap-drop ALL --security-opt no-new-privileges --user <non-root>
        -e HOME=/tmp   timeout sandbox_timeout_seconds  (the named container is killed)
    read back: coverage-final.json | junit.xml | mutation.json (capped, parsed as data)
    coverage vs the E4 criterion, branch by branch against the brief items
    assertion-less / trivial test rules (our own, over the AST of the test file)
    mutation: stryker (js/ts) / mutmut (py) over the covered lines only
    a surviving mutant or coverage below the criterion -> gate closed, back to E5
```
Gate `leave_verification`: the latest run meets the criterion AND has zero
surviving mutants AND no assertion-less test. The E7 → E5 loop is an explicit
action (`POST …/reopen-design`, developer, written reason, audited), NOT a
backwards stage move: it clears the approvals of the functions that failed so
E5 opens again for them — the stage machine stays monotonic (`stages.advance`
is still the only transition).

**The reopen needs its own flag, or it strands the analysis at E7.** Every E5
writer goes through `design._require_design_stage`, which raises
`StageLocked` for any stage past `DESIGN`; clearing an approval alone would
leave the developer unable to edit anything while `leave_verification` stays
closed — the exact shape fixed for E4/E5 today (scope-change log, 2026-09-22).
So the reopen sets `case_designs.reopened_at` on the failed functions, and
`_require_design_stage` accepts a write when the row is reopened AND the
stage is `VERIFICATION`; approving again clears the flag, and the gate needs
every planned function approved with no reopen outstanding. E6's writer takes
the same treatment (the developer must be able to fix the test that failed).
Tests: a reopened function is editable at E7 and no other one is; approval
clears the flag; the gate stays closed while any flag is set.

## §5 Open questions for `mmarin` — ANSWERED 2026-09-22

1. **Disk**: the sandbox image needs ~1.5–2 GB. Re-measured at sign-off time:
   **4.1 GB free** (the 1.2 GB figure above was taken before the analysis
   image build freed its intermediate layers), 11.38 GB of Docker images
   reclaimable, 227 MB of build cache. ANSWERED: build without cleaning
   anything — no `docker prune` of any kind, the named images, the volumes
   and the running containers stay untouched. If the build runs the disk
   down, the build stops and `mmarin` is asked before anything is removed.
   `sandbox_runs_size` stays at the 512m default (RAM, not disk).
2. **Dependency-less scope**: tests run against the module under test with no
   project dependencies installed. CONFIRMED as a v1.0.0 non-goal — a test
   that needs `axios` cannot run in the sandbox. `npm install` on a hostile
   tree executes lifecycle scripts: that is remote code execution by design,
   and no sandbox flag makes it acceptable. The brief targets pure functions
   and the risk matrix already ranks those first.
3. **Mutation tool per language**: CONFIRMED — Stryker (JS/TS) and mutmut
   (Python), both preinstalled in the image, both run offline, both already
   in CLAUDE.md → Analysis Tool Source Authority.

## Verdict

**SIGNED OFF by `mmarin`, 2026-09-22.** Proceed on §3 and §4 with the
controls of §2, reusing the P1 executor rather than writing a second one.
The three questions of §5 are answered above and are not re-opened without a
new survey section. Non-goal recorded for v1.0.0: a test that needs the
audited project's own dependencies cannot run in the sandbox.
