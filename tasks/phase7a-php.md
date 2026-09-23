# Task: Phase 7a — PHP / Laravel (language wave 2, first half)

> **Status: DONE — 2026-09-23. Deliverables 1–6 built and verified END TO END,
> and the phase was closed by a WALK rather than by assertion: a real Laravel
> application through E1–E6 and Dioptra's own PHP through E7, which found two
> defects that were fixed before closing (see the Definition of Done).** Second cycle, after the
> `v1.0.0` tag. Survey: `tasks/phase7-survey.md`, signed off by `mmarin`
> 2026-09-23 (§7.1 one sandbox image per language, §7.2 PHP first).
> Phase **7b (Java)** is covered by the same survey and MUST NOT start before
> this file is at DONE with a commit.

## Objective
Give the platform a second language that works END TO END: a PHP/Laravel
system is detected, analysed with our own PHP rules, briefed and diagrammed
from its AST, scaffolded as PHPUnit, and verified in a PHP sandbox with real
coverage and real mutation testing. This closes half the debt the P5
contingency created on 2026-09-22.

## Deliverables

1. `backend/app/workflow/ast/` — PHP profile
   - `source.py`: `LANGUAGE_BY_SUFFIX[".php"] = "php"`.
   - `extract.py`: a `PHP` `Profile` and a `_language("php")` branch importing
     `tree_sitter_php` (MIT). Node types confirmed AGAINST THE INSTALLED
     GRAMMAR, never from memory.
   - Known shape differences to handle explicitly: `throw` is an EXPRESSION in
     PHP 8 (`throw_expression`), not a statement; `else_if_clause` and the
     `elseif` keyword form; `match_expression` is a decision per arm;
     `foreach_statement`; `do_statement`; `??` and the `?:` short ternary.
   - `pyproject.toml`: `"tree-sitter-php"` with its licence + rationale
     comment, beside the wave-1 grammars.

2. `backend/tests/test_ast_php.py`, `backend/tests/fixtures/ast/real_*.php`
   - At least **three real PHP functions** whose basis paths, counted BY HAND,
     match our count — the plan's day-15 acceptance applied to wave 2.
   - The `tree-sitter<0.26` pin re-probed FOR THIS GRAMMAR: a large-function
     test mirroring `test_ast_python.py::test_large_functions_do_not_crash_the_process`.
   - Hostile source: deeply nested, oversized, syntactically broken → typed
     refusals within the existing limits (512 KiB, depth 40, 400 nodes).
   - Determinism: two runs, byte-identical Mermaid and brief.

3. `rules/semgrep/*.yml` — our own PHP rules, with `rules/semgrep/tests/` pairs
   - The existing families extended to `languages: [php]`: sql-injection,
     command-injection, code-injection, path-traversal, xss, open-redirect,
     insecure-deserialization, mass-assignment, hardcoded-secrets,
     weak-crypto, debug-info, dos-unbounded, no-cdn, crypto-inventory.
   - Laravel-specific where a factory rule earns its keep: `DB::raw` /
     `whereRaw` with interpolation, Eloquent `$fillable`/`$guarded = []` mass
     assignment, Blade `{!! !!}` unescaped echo, `env()` outside config.
   - Every SECURITY rule carries `metadata: {cwe, owasp}`; every
     crypto-inventory rule carries `metadata.category: inventory` and the
     fixed message shape `crypto-asset primitive=… algorithm=… weak=yes|no`
     the normalizer parses. NO public-registry rule (restrictive licence).

4. `backend/app/workflow/scaffold/` — PHPUnit generator
   - `_php_scaffold(design)`: `final class <Name>Test extends TestCase`,
     `require_once` of the flat-copied module, one `public function testC1_…()`
     per approved case. **The case id opens every method name**, which is how
     `gates.leave_tests` finds a case the developer reworded.
   - **Never an assertion, never data, never an oracle**: a `TODO(developer)`
     line and one English comment per declared brief item, exactly as the
     Python and JS generators do.
   - `scaffold/text.py`: a PHP literal escaper. Single-quoted target — PHP
     single quotes interpolate nothing, so `\\` and `\'` are the whole escape
     surface, which is the smallest boundary available.
   - `scaffold/inspect.py`: the PHPUnit assertion vocabulary
     (`$this->assert*`, `self::assert*`, `expectException`, `expectError`).
   - Byte-identical output for the same design row, checked ACROSS PROCESSES
     with different hash seeds.

5. `backend/app/sandbox/results.py` — PHP result shapes
   - Coverage: PHPUnit Clover XML (`<line num type="stmt|cond" count
     truecount falsecount>`) normalised to the existing `Coverage` shape,
     with a half-taken branch covering NEITHER side, as today.
   - Mutation: Infection's JSON log (`escaped` / `killed`, with the diff)
     normalised to the existing `Mutation` shape.
   - Defensive like the existing parsers: a half-shaped or non-UTF-8 document
     MEASURES NOTHING and becomes `ERRORED` upstream — never a pass.

6. `docker/sandbox-php.Dockerfile`, `docker/sandbox/run-php.sh`,
   `backend/app/sandbox/executor.py`, `backend/app/core/config.py`
   - Per-language images (survey §7.1): the existing image becomes
     `dioptra-sandbox-js-py`, this one is `dioptra-sandbox-php`, and
     `executor.command` selects on `attempt.language`. **Operator-visible
     rename** — the settings key gains a per-language default and the change
     is called out in the task's closing notes and `docs/threat-model.md`.
   - PHP 8.3 CLI + PCOV (coverage; smaller and faster than Xdebug and it does
     nothing else), PHPUnit phar, Infection phar — every one pinned by exact
     version and verified at build time, like `NODE_VERSION` is.
   - Same flags, no exceptions: `--network none --read-only --cap-drop ALL
     --security-opt no-new-privileges`, non-root, memory = memory-swap,
     `--cpus`, `--pids-limit`, one writable mount, no Docker socket, nothing
     of the audited project installed.
   - `run-php.sh` keeps the host's contract: the three declared files
     (`coverage.json`, `junit.xml`, `mutation.json`) produced on the
     container's OWN tmpfs and copied into the shared mount as the LAST
     action, once every runner has exited (P4's residual-bounding decision).
   - OUR config only: never the audited tree's `phpunit.xml`, `phpunit.xml.dist`,
     `composer.json`, `infection.json` or `.php` bootstrap — they run code at
     collection time, exactly like `conftest.py` and `vitest.config.js`.
   - `scripts/ci.sh`: the licence gate runs INSIDE this image too.

7. `backend/tests/test_sandbox_php.py`, `test_scaffold_php.py`, `test_verify_php.py`
   - The escape probes of `docs/threat-model.md` re-run against the PHP image
     with the shipped argv, each one ATTRIBUTABLE (fails under the shipped
     flags, succeeds when the flag it targets is removed).
   - A surviving Infection mutant demonstrably rejects the E7 gate.
   - A thorough suite reaches the E4 criterion; a one-assertion suite leaves
     mutants alive.

8. Docs — `docs/analysis-pipeline.md` (languages line), `docs/workflow-gates.md`
   (scaffolds + the E4 guard now accepting PHP), `docs/threat-model.md` (the
   per-language images and the PHP sandbox row), `docs/software-inventory.md`
   if the CBOM rules gain PHP, `CLAUDE.md` → Current phase status,
   `docs/development-phases.md` → Scope-change log (entry already written).

## Constraints
- Hard Rules (CLAUDE.md): the platform MUST NOT write tests — the PHPUnit
  scaffold carries no assertion; audited code executes ONLY in the sandbox;
  no CDN; free licences only (tree-sitter-php MIT, PHPUnit BSD-3, Infection
  BSD-3, PCOV MIT — each verified by the gate, each with a rationale comment);
  English everywhere in code; gates server-side.
- The plan-first gate is SATISFIED by `tasks/phase7-survey.md`; any departure
  from its §6 pseudocode is recorded there before it is coded.
- Forbidden: public Semgrep registry rules; installing the audited project's
  composer dependencies for analysis OR for the sandbox; relaxing a sandbox
  flag to make a PHP test pass; reading the audited tree's own runner config.

## Definition of Done
- [x] All deliverables implemented; ruff + mypy + oxlint clean, and the type
      check is now the REAL one: `npx tsc --noEmit` checks nothing in this
      repo (the root tsconfig is `files: []` with project references), so
      every earlier report of it was vacuous. `tsc -b` is the command, and
      running it found `Finding.third_party` missing from the frontend type
      with four call sites using it — already committed in `1b5795e`, fixed
      here. `scripts/ci.sh` has always run `tsc -b`, so CI was never blind:
      the hole was in the command I was verifying with, not in the gate
- [x] All specified tests passing (pytest / Vitest), hostile-input cases
      included; the live sandbox suite covers the PHP image behind the
      `sandbox` marker
- [x] Mutation pass on the touched surface (phase-close) — mutmut, 2026-09-23.
      **Scope stated honestly**: the full pass below ran BEFORE the two walk
      fixes, so it did not cover `verify.py`'s criterion span or `risk.py` at
      all (`risk.py` was not even a target — it is now, added to
      `pyproject.toml`). Those two surfaces carry HAND-RUN mutants instead,
      each verified to turn a test red: `_in_span` → identity, `criterion_span`
      → `None`, the ambiguity guard removed, the sort key without
      `is_third_party`, the filter after the cap, `total` counted post-cap, and
      the router dropping `q` — the last four run independently by the QA
      verifier. A full re-run over both modules is the next phase's first
      mutmut job, not a claim made here.
      The target list in `pyproject.toml` gained this phase's three decision
      surfaces (`scaffold/text.py`, `scaffold/inspect.py`, `analysis/normalizer.py`)
      beside the P3/P4/P5 ones: **5 301 mutants, 4 151 killed, 902 survived,
      247 with no covering test, 1 timeout.**

      **What this phase acted on.** `scaffold/text.py` — the boundary that turns
      audited text into generated PHP — has 12 survivors; eleven are the
      equivalent classes P3–P5 already recorded (codec-name case, the content
      of a replacement string whose invariant holds either way, an unreachable
      fallback) and **one was a real weakness**: the class-name test compared
      the generator against ITSELF (`php_class_name(...) == php_class_name(...)`),
      so any mutation of `studly`/`slug` changed both sides and passed. Pinned
      with a literal. `sandbox/results.py` — `_dioptra_coverage`, the PHP
      coverage parser added by this phase, had **no covering test at all**;
      three were written (the neutral shape, a forged document, half-shaped
      documents). `workflow/gates.py` shows five survivors, all in the
      `planned_keys` helper and all equivalent (the placeholder appended for a
      malformed entry, whose content the gate never reads — only the count);
      **no mutant of any gate function lives**, which is what
      `tasks/phase4-e6-e7.md` claims, though its narrower wording "gates.py has
      ZERO survivors" is no longer literally true for that helper.

      **Recorded rather than claimed**: `analysis/normalizer.py` (357 survived,
      127 uncovered) and `scaffold/inspect.py` (69 survived, 43 uncovered) were
      added to the target list by this phase, so those figures are a FIRST
      measurement of P1 and P4 code, not a regression from wave 2. Clearing
      them is its own piece of work and is not claimed here
- [x] Briefs for at least THREE real PHP functions with hand-counted, matching basis paths
      — `test_validar_cedula_hand_count`, `test_calcular_mora_hand_count`,
      `test_resolver_estado_hand_count` (3 passed). **Deviation recorded in the test file's
      own docstring**: wave 1's `real_*` fixtures are verbatim copies of this repository's
      functions and this repository contains no PHP, so these three were written for the
      purpose in Laravel-flavoured style. The hand count is still a hand count — every number
      was counted on the listing before it was asserted — but the "real project" half of the
      acceptance is met by the E1–E7 walk, not by these fixtures
- [x] `tree-sitter<0.26` pin re-probed with the PHP grammar (large-function test)
      — 2026-09-23, `backend/tests/test_ast_php.py::test_large_functions_do_not_crash_the_process`,
      three shapes (150 `while`, 150 `catch`, 120 `if`), each built three times in a CHILD
      interpreter so a binding regression fails an assertion instead of killing the test
      runner. 3 passed. The 0.26.0 fault was in the core binding, not in a grammar, which is
      exactly why a new grammar gets its own probe rather than inheriting Python's;
      `docs/threat-model.md` → Flow diagrams now names PHP in that residual
- [x] Every escape probe re-run against `dioptra-sandbox-php`, all negative and
      attributable — 2026-09-23, eleven probes, both columns recorded in
      `docs/threat-model.md` → Sandbox escape tests → PHP image. Each was
      re-expressed for what that image HAS (no `python3`, no `pcntl`, no
      `sockets`; `perl` forks, `php` with `posix` does the rest) and the memory
      balloon lifts PHP's own `memory_limit` first, or it would hit that instead
      of the container's. Ten of the eleven checked both ways; the balloon's
      negative control is not run because removing `--memory` would balloon the host
- [x] A surviving Infection mutant demonstrably rejects the E7 gate — 2026-09-23,
      `backend/tests/test_sandbox_live.py::test_a_surviving_infection_mutant_rejects_the_e7_gate`,
      run against `dioptra-sandbox-php:latest`. It drives `verify.verify_function`,
      which is the code the WORKER runs and the only thing
      `gates.leave_verification` ever reads — not `parse_mutation`, which would
      only prove the wiring. **Both directions**, because a gate that rejects
      everything proves nothing either: a one-assertion suite over `Edad::obtener`
      comes back `FAILED` with `mutant_survived` and the survivors named, and a
      three-case suite over the same class comes back `PASSED` with none and no
      reasons. `mutation_measured` is True on both — a class IS mutable, so a
      declared gap here would itself be a defect. This is the check the three
      earlier wiring bugs of this chain would each have failed while LOOKING
      like a pass
- [x] Licence gate green for the PHP image — 2026-09-23. The image WRITES a
      manifest of what it installed (`/opt/dioptra-php/licenses.json`, built from
      the same pinned `ARG`s its artefacts are verified against) and
      `license_gate.py --php-manifest` reads it; `scripts/ci.sh` pulls it out of
      the image and fails the build on it. **Deviation from the wave-1 shape,
      recorded**: the gate cannot run INSIDE this image — it is `php:8.3-cli` and
      has no python3 — so it runs on the host against the file the artefact
      carries. **Strengthened after the precommit panel**: the manifest is no
      longer hand-written. `docker/sandbox/php-licenses.php` runs at build time,
      walks the per-component LICENSE files inside `phpunit.phar` and
      `infection.phar` — neither ships a phar.io `manifest.xml` or a composer
      `installed.json`, checked inside the built image — and classifies each
      from its own text, failing the BUILD on anything it cannot recognise.
      **64 packages, against the 4 it named before** (33 BSD-3-Clause, 26 MIT,
      3 Apache-2.0, php, xdebug). The per-component version is the bundling
      artefact's, which the phars make the only honest answer. Verified both
      ways on the rebuilt image: the real manifest passes, the same manifest
      with one `Commercial` entry appended exits 1
- [x] No secrets in diff; locale parity check green — 2026-09-23. Gitleaks
      reports the same THREE pre-existing hits the P5 self-audit already
      discarded with a written justification (our own `hardcoded-secrets`
      rule fixtures, which exist to make the rule fire, and the sandbox
      test's exfiltration canary); none is introduced by this phase, and a
      scan of the staged patch alone reports none. `no_cdn_check.py` green
- [x] `/precommit` returned `READY TO COMMIT` — two full rounds. The first
      (the wave itself) is recorded below. The second, on the closing diff,
      earned its keep: the coverage adversary found that `_in_span` had
      BOTH endpoints unpinned — and since `function_span` is inclusive, a
      one-line function has `low == high`, so a `<` at the low end empties
      the span and the criterion passes unconditionally, a fail-OPEN in a
      gate; that `criterion_span`'s failure path had no test at all, where
      narrowing its `except` made the verification job RAISE instead of
      falling back; and that the plan-selection fix had no test, so
      reverting it left all 101 frontend tests green. The invariant checker
      found the defect the search box introduced (a ticked function dropped
      from the saved plan once a filter hid it), the security auditor found
      that an AMBIGUOUS span resolved to the first same-named declaration
      and that `criterion_lines` was stored with no surface reading it, and
      mockup fidelity found the search box was a bespoke control at 1.02:1
      contrast instead of the anchor's `.input`. All fixed and each pinned
      by a test verified to go red under the mutant
- [x] A real PHP project walks **E1–E6** on the dev instance, and **E7 on a
      self-contained module** — done 2026-09-23 against the dev database, every
      step through the service layer with the real roles and gates (the seed
      passwords are the operator's, so the HTTP login was not available to the
      agent; the gate-through-the-API proof is `tests/test_gates.py`, which
      skips every gate with no UI in the loop).
      **E1–E6 on `otroprevi`** (Laravel, 687 findings): E3 closed with 257
      written verdicts — 189 confirmed, 68 discarded — by rule family, because
      the judgement genuinely repeats (the `.env` with live credentials and the
      mass assignment in `RegisterController` confirmed; the 62 aciertos inside
      `public/Datatables/1.10.21` and the four in minified jQuery discarded as
      third-party code the team did not write; the 21 external `<script>`/`<link>`
      of the team's own Blade views confirmed under the no-CDN norm; the 164
      advisories confirmed as dependency debt). E4 planned three of the team's
      own PHP functions — `PoliciesController::uploadFile` (ccn 6),
      `RedirectIfAuthenticated::handle`, `Helper::best_seller_month` — and the
      AST briefed all three from real Laravel source, resolving `Class::method`
      names, giving a `switch` one item per case label and loops an enter/skip
      pair. E5 approved 13 cases; E6 stored three PHPUnit files written by hand
      over the scaffolds and `leave_tests` opened after PARSING them. The
      analysis stays at E6 by design: every one of these needs the framework,
      which the sandbox never installs.
      **E7 on `docker/sandbox/php-licenses.php`**, Dioptra's own shipped code —
      the generator whose verdict gates the PHP image's licences, the same
      precedent P5 set walking its own `scaffold/text.py::slug`. Three runs:
      two honest failures, the E7 → E5 loop reopening the design, and a PASS
      with the gate open. `mutation_measured` is False throughout and says so:
      `componentName` is a free function Infection cannot mutate, which is
      exactly the declared gap this phase exists to make visible
- [x] **Two defects the walk found, both fixed before this phase closed** — the
      point of walking rather than asserting. (1) The E4 risk matrix returned
      the top 200 of 5 000 measured functions and on this project all 200 were
      hand-vendored JavaScript, so the developer could reach none of their own
      code and nothing said so; it now ranks dependency directories last, takes
      a server-side `?q=` filter applied before the cap, and reports the total
      so the screen can say "Mostrando 200 de 5000". (2) The E7 coverage
      criterion was judged over the whole MODULE, so planning one function of a
      three-function file could never pass; it is now judged over the planned
      function's lines, falling back to the module when the span cannot be
      resolved. Both are in `docs/development-phases.md` → Scope-change log
- [x] Docs updated; CLAUDE.md phase status + `docs/development-phases.md`
      both say Phase 7a → DONE (2026-09-23), and `docs/analysis-pipeline.md`
      no longer says IN PROGRESS. `docs/workflow-gates.md` carries the
      function-scoped criterion, `docs/ui-model.md` the E4 search box and
      the count line, and the scope-change log both walk defects and the
      `GET …/risk-matrix` 1.x contract change. The closing commit hash is
      recorded in the follow-up commit, as P5 did in `df80ebe`

## Progress (2026-09-23)

Built and verified by execution:

- **AST profile** (deliverable 1–2): `PHP` profile in `workflow/ast/extract.py`
  against the installed `tree-sitter-php` 0.24.1, plus four generalisations
  the wave-1 walker needed and none of which changes wave-1 output —
  `unwrap_types` (PHP 8 `throw` is an EXPRESSION), `elif_types` (`elseif` is a
  chained clause), the `body` field where wave 1 says `consequence`, and the
  switch subject under `condition`. `tests/test_ast_php.py`: 17 tests,
  including the `tree-sitter<0.26` pin re-probed for THIS grammar.
  Three functions hand-counted and matching: `validarCedula` 7,
  `calcularMora` 8, `resolverEstado` 7.
- **Semgrep rules** (deliverable 3): **17 PHP/Laravel rules** across eleven
  families, each with positive and negative fixtures, run through Semgrep
  1.177 — zero rule errors, every rule fires on its positive, none fires on a
  negative. Two defects the fixtures caught: `laravel-model-unguarded` was an
  invalid PHP pattern (a class property is not a standalone pattern for
  semgrep-core — it is now a bounded regex over `*.php`), and
  `php-regex-from-input` fired on its own NEGATIVE fixture because
  `preg_quote()` still reads as a concatenation — flagging the recommended fix
  is how a rule gets disabled, so `preg_quote` is now excluded.
- **PHPUnit scaffold** (deliverable 4): `_php_scaffold`, `php_string()`
  (single-quoted — PHP double quotes INTERPOLATE, so a title holding `$var` or
  `{$x}` would become code), `studly()`, and the PHPUnit assertion vocabulary
  in `scaffold/inspect.py`. `tests/test_scaffold_php.py`: 12 tests, byte-identical
  across hash seeds, no assertion of ours anywhere.
- **Coverage** (deliverable 5, coverage half): **measured, not assumed.**
  pcov was the first choice and had to be abandoned — it measures LINES ONLY,
  and a build of this image with it produced `total_branches: 0`, which would
  make the default E4 criterion (100 % decisions) unreachable for PHP. Neither
  PHPUnit's Clover nor its Cobertura report carries branch sides either. What
  does carry them is Xdebug's own `xdebug_get_code_coverage()` with
  `XDEBUG_CC_BRANCH_CHECK`, so the wrapper drives PHPUnit through
  `PHPUnit\TextUI\Application` under that collector and reshapes the result.
  Verified end to end on a real module: a thorough five-case suite gives
  12/12 branches and no partial line; a one-case suite gives 6/12 and three
  partial branch lines — exactly the distinction E7 is built on.
- **Image** (deliverable 6): `docker/sandbox-php.Dockerfile` builds
  **754 MB** with PHP 8.3.33, PHPUnit 12.5.35, Infection 0.35.4 and Xdebug
  3.4.6, every artefact checksum-verified at build time, non-root, and the
  per-language selection wired through `executor.image_for`. The split
  decision (§7.1) proved right in practice: this host had 1.5 GB free when it
  built, which one fat image would not have survived.

## Mutation testing: what it took, and what it found (2026-09-23)

Infection reported **zero mutants** for a long time. Four causes, found by
bisection against a canonical Infection project that worked (4 mutants, 4
killed) — three of them OURS, one upstream:

1. **`testFrameworkOptions: "--configuration=phpunit.xml"`** in the config the
   host writes made Infection pass `--configuration` TWICE. PHPUnit refuses
   ("Option --configuration cannot be used more than once") and Infection
   reports it as "tests must be in a passing state". Removed.
2. **`pathCoverage="true"` as an ATTRIBUTE of `<phpunit>`** is not in the
   schema. PHPUnit then fails validation and runs NO tests. Removed — and it
   was never needed: the branch sides come from Xdebug directly through
   `docker/sandbox/php-harness.php`, not from a PHPUnit report.
3. **A missing bootstrap — and this one was a FAIL-OPEN, not just a failure.**
   Infection runs every mutant through an include-interceptor bootstrap that
   does `require_once <project>/vendor/autoload.php`. Nothing of the audited
   project is ever installed here (the v1.0.0 non-goal), so that file does not
   exist, **every mutant run died in the bootstrap, PHPUnit errored, and
   Infection counted all 26 as "killed by Test Framework"**. A suite that
   asserts nothing about the result scored **100 % MSI**. The attempt
   directory now carries a real (empty) `dioptra.bootstrap.php` and the config
   points at it; the same suite now scores 1 killed and 25 escaped. This is
   the same family of defect the P4 panel caught in E7 ("scored nothing was
   measured as everything passed") — reached by a different road, and caught
   before shipping rather than after.
4. **Upstream limitation: Infection only mutates code INSIDE A CLASS.** Proven
   minimally: one file holding the SAME logic twice, once as a free function
   (lines 2–8) and once as a class method (lines 10–18), yields 10 mutants,
   **all of them at lines 12–17**. A free PHP function therefore yields
   `total: 0` whatever the suite does — neither `--with-uncovered` nor a
   pre-built coverage report changes it.

   Consequence, and the guard it earned: zero mutants measured nothing, so
   "no survivor" would have read as a pass. `workflow/verify.py` now treats a
   run with `mutation.total == 0` as **ERRORED**, never a verdict — the same
   rule as a missing document. `None` is deliberately NOT zero: mutmut reports
   best-effort counts and an exact survivor list. Pinned by
   `tests/test_verify.py::test_a_run_that_generated_no_mutant_is_errored_not_passed`
   and `…::test_a_tool_that_reports_no_count_still_scores_on_its_survivor_list`.

**Measured end to end through the shipped wrapper**, with the production argv
(`--network none --read-only --cap-drop ALL --security-opt no-new-privileges`,
non-root, one writable mount), on the same module and the same 12 branches:

| Suite | Coverage | Mutation |
|---|---|---|
| four cases, real assertions | 12/12 branches | 24/26 killed, **2 survivors** (`ReturnRemoval` L8, `CastInt` L20, each with its diff) |
| covers everything, `assertIsBool` only | 12/12 branches | 1/26 killed, **25 survivors** |
| calls everything, asserts nothing | 12/12 branches | 1/26 killed, **25 survivors** |

That is the phase's acceptance criterion demonstrated: coverage alone cannot
tell a thorough suite from a trivial one (all three reach 12/12), and the
mutation run does. The survivors carry their diff, which is what the P5
equivalent-mutant verdict needs to be judgeable.

## The mutation gap, and how it is declared (`mmarin`, 2026-09-23: option b)

A free PHP function is planned, designed and tested like any other; what
changes is that E7 says out loud that it could not break it on purpose.

- `verify.mutation_is_measurable` answers from the SOURCE, through the AST
  (`ast.extract.declared_in_class`), BEFORE a run is scored — never inferred
  from an empty result. A source that cannot be read answers "measurable",
  the conservative side.
- The run row carries `mutation_measured` (migration `0012`, proven up and
  down against real PostgreSQL with a pre-existing row, which is backfilled
  `true` — every earlier run was JS/TS or Python, whose tools mutate free
  functions).
- The gate decides on the other three questions, which all still bind: a
  coverage shortfall still closes it
  (`test_the_gap_never_excuses_the_other_three_questions`).
- The E7 screen prints a plain-words line, and the report prints **"no
  medida"** instead of a zero in the survivors column plus a sentence under
  the totals — in HTML, Markdown and DOCX.
- A function the tool COULD have mutated and produced nothing for is still
  `ERRORED`: that is the tool breaking, not a limit.

The honest cost, recorded: an E7 pass on such a function attests three
questions, not four. That is why it is said on every surface rather than
implied.

Still not started: the E1–E7 walk on a real PHP project, and a surviving
Infection mutant shown to reject the E7 gate. The escape probes, the
workspace/verify tests, the tree-sitter probe and the docs of deliverable 8
all landed on 2026-09-23 — see the Definition of Done above, which is the
authority when this narrative and a box disagree.

## Precommit panel, 2026-09-23 — what it caught

Five agents; thirteen fixes applied and two decisions taken by `mmarin`. The
three findings that mattered were all in code written for this phase, and
none of them would have been caught by the tests written alongside it:

1. **`?>` leaves PHP mode from a `//` comment.** `scaffold/text.py::comment`
   neutralised `*/` and nothing else, and the values reaching it include brief
   item text lifted from the AUDITED source. The security auditor proved it by
   execution inside `dioptra-sandbox-php:latest`: the file passes `php -l` and
   the payload runs. Fixed symmetrically (`?>` → `? >`), pinned by two tests,
   one of which walks the whole path from a hostile brief item to the file.
2. **`declared_in_class` had its polarity inverted.** `False` means "excuse the
   mutation question", so an unresolvable function was being excused rather
   than scored. Now `True`, with the docstring corrected and two tests.
3. **The PHP wrapper wrote a mutation document with null counts** when
   Infection's log existed but could not be read — the host then scored an
   empty survivor list. Now it writes nothing, and the absent file is
   `ERRORED` by the rule the project already had.

Also fixed: the declared-gap sentence reached only HTML while the test was
named `…in_every_format`; `.caserow .sub.warn` did not exist, so the one line
saying "this was not measured" rendered exactly like the measurements above
it; Compose built no PHP image and the worker had no tag for it; `ci.sh` and
the Dockerfile both claimed a licence gate that does not run inside this image
(closed later the same day: the gate reads a manifest the image generates about
itself); and five docs were stale.

**Still open after the panel** (unchanged from the DoD above): no real PHP
project has walked E1–E7, and no surviving Infection mutant has been shown to
reject the gate.

Closed by the same panel round: the escape probes ran (eleven, all negative),
the tree-sitter pin was re-probed for this grammar, and the licence manifest
is no longer four hand-written lines — `docker/sandbox/php-licenses.php`
generates it from the artefacts, walking the per-component LICENSE files
inside both phars and classifying each from its own text. **64 packages**
instead of 4; an unrecognised licence text fails the BUILD. Proven both ways
on the rebuilt image: the real manifest passes the gate, and the same manifest
with one `Commercial` entry appended exits 1.

## Non-goals (explicit)
- **Java / Spring** — phase 7b, same survey, starts only when this is DONE.
- Go, C#/.NET, Tauri — out of scope by design since v1.0.0.
- Installing the audited project's composer dependencies in the sandbox: a
  `composer install` on a hostile tree runs `scripts` hooks, which is remote
  code execution by design. The v1.0.0 non-goal stands for PHP unchanged — a
  test needing the project's own classes cannot run.
- Blade template AST/briefs: `.blade.php` is detected and RULE-scanned, but a
  template is not a function and E4 does not plan one.
- PHPStan / Psalm: not in CLAUDE.md → Analysis Tool Source Authority, and
  adding a SAST engine is a change to that table, not a task decision.
- Any new dependency without a licence + rationale comment.

## References
- `tasks/phase7-survey.md` (the gate, §3–§7)
- `CLAUDE.md` → Hard Rules, Analysis Tool Source Authority, Agent Behavioral Rules
- `docs/workflow-gates.md` → Scaffolds, E7 re-audit rules; `docs/threat-model.md` → Test sandbox
- `docs/analysis-pipeline.md` → Rule authoring; `tasks/phase4-survey.md` §5 (the dependency non-goal)
- OWASP ASVS 4.0.3 V1.14; CWE-89 / 78 / 94 / 22 / 79 / 601 / 502 / 915; McCabe basis paths
