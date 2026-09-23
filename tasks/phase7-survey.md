# Phase 7 survey — PHP/Laravel + Java/Spring (language wave 2)

> **Status: SIGNED OFF 2026-09-23 by `mmarin`** — the two blocking decisions
> of §7 were taken (§7.1 one image per language; §7.2 PHP first as phase 7a,
> Java after as phase 7b). Written read-only before any edit, as the gate
> requires; the decisions are recorded in §7 and in
> `docs/development-phases.md` → Scope-change log.
> Plan-first investigation gate (CLAUDE.md → Agent Behavioral Rules): this
> slice touches the SANDBOX and exceeds 200 LOC by a wide margin, so no edit
> to `backend/`, `docker/`, `rules/` or `frontend/` may happen before
> `mmarin` signs the `## Verdict` at the end of this file.
>
> Scope: the wave cut from P5 on 2026-09-22 under the contingency "two
> consecutive weekly milestones missed" (`docs/development-phases.md` →
> Scope-change log). The second cycle's other known item,
> `tasks/phase6-user-administration.md`, is untouched by this and stays at
> DESIGN. The numbers are file identifiers, not an order.

## 1. What the plan actually owes

`tasks/phase5-closure.md` deliverable 2 and the day-19 row of the day table:

> PHP/Laravel and Java/Spring: detector, AST + brief, PHPUnit / JUnit
> scaffolds, own Semgrep rules, Infection + Pitest in the sandbox.

Read literally that is six things. The survey below finds that **one of them
is already built, three are mechanical, and two are where the whole cost
sits** — and that the second of those two collides with a non-goal v1.0.0
already recorded.

## 2. Already built — nothing to do (verified by reading)

| Piece | Where | State |
|---|---|---|
| Language detection | `ingest/detection.py::EXTENSION_LANGUAGES` | `.php` → PHP, `.java` → Java, present since P1 |
| Framework detection | same file, `PHP_FRAMEWORKS` / `JAVA_MARKERS` | Laravel, Symfony, Slim, CodeIgniter; Spring Boot, Spring, Quarkus, Micronaut |
| Lockfile detection | same file, `LOCKFILE_NAMES` | `composer.lock`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile` |
| SBOM | Syft, `analysis/runners/tools.py` | reads composer and maven trees natively, no change |
| SCA correlation | `inventory/correlation.py` | Packagist and Maven are already mapped OSV ecosystems |
| Stage machine, gates, risk matrix, report, inventory, audit | everywhere | language-agnostic by construction |

So "the detector" of the plan's day-19 row **is a no-op**: it was built in P1
and never removed by the cut. What the cut actually removed was the AST, the
rules, the scaffolds and the sandbox runtimes.

## 3. Mechanical work — cost is real but the design is settled

### 3.1 AST layer (`workflow/ast/`)

The architecture already anticipated this: `extract.py` is ONE builder driven
by a `Profile` dataclass naming node types, plus a `PROFILES` dict and a
`LANGUAGE_BY_SUFFIX` map in `source.py`. Adding a language is a `Profile`, a
grammar import and two dict entries — not a new walker.

Grammars, checked on PyPI today, both **MIT** (Hard Rule: free licences only):

| Package | Version | Licence |
|---|---|---|
| `tree-sitter-php` | 0.24.1 | MIT (`license_expression`) |
| `tree-sitter-java` | 0.23.5 | MIT (classifier) |

`tree-sitter-php` declares `tree-sitter~=0.24`, compatible with our
`tree-sitter<0.26` pin (pinned because 0.26.0 corrupts the heap on ordinary
functions — `docs/threat-model.md`, regression test in `test_ast_python.py`).
**The pin must be re-probed with the two new grammars**: the crash was in the
core binding, but the large-function test only covers Python today.

Node types to map (from the grammars' own `node-types.json`, to be confirmed
against the installed grammar, not from memory):

- **PHP**: `function_definition` + `method_declaration`; `if_statement` with
  `else_if_clause` / `else_clause`; `for_statement`, `foreach_statement`,
  `while_statement`, `do_statement`; `switch_statement` / `case_statement` /
  `default_statement`; `match_expression` (a decision per arm);
  `try_statement` / `catch_clause` / `finally_clause`; `return_statement`;
  `throw_expression` (PHP 8 made `throw` an expression — it is NOT a
  statement type, which the profile's `throw_types` assumes);
  `binary_expression` for `&&`/`||`/`and`/`or`/`??`;
  `conditional_expression` including the `?:` short form.
- **Java**: `method_declaration` + `constructor_declaration`; no free
  functions at all, so **`function_types` must accept a method nested in a
  class**, which the JS profile already does via `method_definition`;
  `if_statement` / `else`; `for_statement`, `enhanced_for_statement`,
  `while_statement`, `do_statement`; `switch_expression` with both
  `switch_block_statement_group` (colon form) and `switch_rule` (arrow form,
  Java 14+) — **two case shapes, unlike every wave-1 language**;
  `try_statement` / `catch_clause` / `finally_clause` /
  `try_with_resources_statement`; `return_statement`; `throw_statement`;
  `binary_expression` for `&&`/`||`; `ternary_expression`.

Boundary extraction (`F<n>` items) needs `number_types` and `string_types`
per grammar: PHP `integer`/`float`/`string`/`encapsed_string`, Java
`decimal_integer_literal`/`decimal_floating_point_literal`/`string_literal`.

**Acceptance the plan itself demands** (day 15's rule, applied to wave 2):
briefs for at least three real PHP functions and three real Java methods
whose basis paths, counted BY HAND, match our count. Fixtures verbatim, as
`backend/tests/fixtures/ast/real_*` already does for wave 1.

### 3.2 Our own Semgrep rules (`rules/semgrep/`)

Today: 25 rule bodies for `[javascript, typescript]`, 20 for `[python]`, 3
`regex`, 1 `generic`. Nothing for PHP or Java. Public registry rules stay
FORBIDDEN (restrictive licence) — ours only.

The twelve families that exist for wave 1 (`sql-injection`,
`command-injection`, `code-injection`, `path-traversal`, `xss`,
`open-redirect`, `insecure-deserialization`, `mass-assignment`,
`hardcoded-secrets`, `weak-crypto`, `debug-info`, `dos-unbounded`) plus
`no-cdn` and `crypto-inventory` all have PHP and Java analogues, and the
framework-specific ones are where a factory rule earns its keep (Laravel
`DB::raw`, Eloquent `$fillable` mass assignment, Blade `{!! !!}`; Spring
`@RequestMapping` + string-concatenated JPQL, `JdbcTemplate` concatenation,
Jackson polymorphic deserialization, `Runtime.exec`).

Each rule carries `metadata: {cwe, owasp}` and a positive/negative test pair
(`rules/semgrep/tests/`), and the crypto-inventory ones carry
`metadata.category: inventory` with the fixed message shape the normalizer
parses. **Estimate: 24–30 new rule bodies**, which is the single largest
mechanical block of the phase and is pure YAML plus fixtures.

### 3.3 Scaffolds (`workflow/scaffold/`)

`generate()` dispatches on `language_for(design.path)` into
`_python_scaffold` / `_javascript_scaffold`. Two more functions, same shape:
name, imports, one case per approved case, a `TODO(developer)` line, one
comment per declared brief item, **never an assertion**.

- **PHPUnit**: `final class <Name>Test extends TestCase` with
  `public function testC1…()`; the case id must still OPEN the method name
  so `gates.leave_tests` finds a reworded case — `testC1_…`.
- **JUnit 5**: `class <Name>Test` with `@Test void c1_…()`. `@DisplayName`
  carries the developer's title, which is the escaping boundary.

`scaffold/text.py` gains a PHP string literal escaper (single-quoted with
`\\` and `\'` only — PHP's single quotes interpolate nothing, the safest
target) and a Java one (double-quoted, `\uXXXX` for everything outside
printable ASCII, and the same U+2028/U+2029 care is unnecessary but harmless).
`scaffold/inspect.py::assertion_free_cases` needs the assertion vocabulary
per language: PHPUnit `$this->assert*` / `self::assert*` / `expectException`;
JUnit `assert*` / `assertThrows` / `verify` (Mockito).

### 3.4 Result parsing (`sandbox/results.py`)

`parse_coverage` dispatches `python` → coverage.py JSON, everything else →
Istanbul JSON. Two new shapes:

- **PHP**: PHPUnit writes Clover XML (`--coverage-clover`), which gives
  `<line num= type="stmt|cond" count= truecount= falsecount=>` — enough for
  our `statements` and `decisions`, and the branch sides the brief items
  need. PHPUnit can also emit `--coverage-php` / Cobertura; Clover is the
  richest for branches.
- **Java**: JaCoCo XML gives `<counter type="LINE|BRANCH" missed= covered=>`
  per method and `<line nr= mi= ci= mb= cb=>` per line — `mb`/`cb` are
  missed/covered branches, which maps onto "a half-taken branch covers
  neither side" exactly.

`parse_mutation`: Infection writes a JSON log (`--logger-json`) with
`escaped` / `killed` arrays carrying the diff; Pitest writes
`mutations.xml`/`.csv` with `<mutation status="SURVIVED">` and a description.
Both fit the existing `Mutation` shape — **and both are adapted INSIDE the
image by a wrapper** (`docker/sandbox/run-php.sh`, `run-java.sh`), per P4's
recorded decision that the host never learns a tool's output format.

## 4. Wall 1 — Java is compiled, and the sandbox model assumes it is not

This is the finding that matters, and it is not a detail.

`sandbox/workspace.py::build_attempt` copies the module under test **FLAT**
into the attempt directory root, writes the developer's test beside it and
runs the tool. It works because Python and JavaScript load a file by path.

Java does not:

1. **A `package com.example.util;` declaration binds the class to a directory
   path.** `javac` will compile a flat file, but the resulting class must sit
   at `com/example/util/X.class` for the test's `import` to resolve. So the
   attempt directory must RECREATE the package path from the declaration —
   or the generator must strip the declaration, which means **mutating the
   code under test before measuring it**, and that is not acceptable: the
   verdict would describe a file the project does not have.
2. **Compilation is a step with its own failure mode.** Today a test file
   that does not parse is "unwritten" (E6 gate) and a run that produces no
   document is `ERRORED` (P4's fail-open fix). A Java attempt adds a THIRD
   state: compiles-or-not, for the module AND for the test. That must map to
   an existing verdict rather than invent one — `ERRORED` with the compiler's
   message is the honest mapping.
3. **JUnit, JaCoCo and Pitest are jars**, pinned in the image at fixed paths
   (`/opt/dioptra-java/`), never resolved from the audited tree — the same
   rule that keeps `/opt/dioptra-js` out of the run directory. No Maven, no
   Gradle: a build tool would read the audited `pom.xml`, which is
   attacker-controlled and downloads code. **`javac` + `java -jar` with a
   fixed classpath only.**
4. **The v1.0.0 non-goal bites harder here than anywhere.** The sandbox
   installs nothing of the audited project. A Python function importing only
   the stdlib is common; a Java method in a Spring codebase that imports
   nothing but `java.*` is **rare** — it will usually reference an entity, a
   repository or a DTO from the same project. Those classes are not copied,
   so compilation fails, so the run is `ERRORED`.

**Honest consequence to state up front**: Java support will parse, brief,
diagram and scaffold for real Spring code, and will reach a *measured* E7
verdict only for self-contained classes. That is the same limit the MINCYT
frontend already hit (`tasks/phase5-closure.md`: it cannot reach E8 in
v1.0.0), but it will be the NORMAL case for Java rather than the exception.

Two ways to widen it, both out of this phase's scope and both needing their
own survey: copy the module's whole compilation unit set (a dependency
closure computed from imports, still without third-party jars), or allow an
operator-provided, offline, pre-vetted jar directory. Neither may be improvised.

PHP has none of this: it is interpreted, `require` by path works like
Python's flat copy, and a namespace declaration does not bind to a directory
the way a Java package does. **PHP is close to the Python path; Java is not.**

## 5. Wall 2 — the image, and the disk it has to be built on

Measured on this host today:

```
/dev/nvme0n1p5   92G   85G  2.1G  98% /
dioptra-sandbox:latest   701MB
dioptra-analysis:latest  974MB
docker system df: images 16.66GB total, 10.69GB reclaimable; build cache 8.82GB (3.29GB reclaimable)
```

**2.1 GB free.** The P4 survey signed off on "the image is built WITHOUT
pruning anything — 4.1 GB free measured at sign-off, and a build that runs
the disk down stops rather than removing an image". Free space has since
halved, and this phase wants to add to the sandbox image:

| Addition | Rough size |
|---|---|
| JDK (temurin 21 headless, needed for `javac` — a JRE is not enough) | 300–400 MB |
| JUnit console standalone + JaCoCo + Pitest jars | 15–25 MB |
| PHP 8.3 CLI + common extensions | 80–120 MB |
| PCOV or Xdebug (compiled extension — Xdebug needs build deps at image build) | 5–15 MB + transient |
| PHPUnit phar + Infection phar | 5–10 MB |

So the sandbox image roughly **doubles, to ~1.2–1.3 GB**, and the build needs
transient space on top. With 2.1 GB free that is tight enough that a failed
build could fill the disk — the exact situation the P4 rule was written to
prevent.

**This is `mmarin`'s call and I will not take it**: the 10.69 GB reclaimable
belongs to unrelated images on this machine (`ejbca`, `mariadb`, a CTF
portal, stopped two weeks to two months ago). Removing them is destructive
and outside this repository.

A real alternative exists and should be weighed rather than dismissed:
**split the sandbox image per language** (`dioptra-sandbox-js-py`,
`dioptra-sandbox-php`, `dioptra-sandbox-java`), selected by
`executor.command` from `attempt.language`. It keeps every existing
deployment's image the size it is today, lets an air-gapped factory ship only
the languages it audits, and turns "the JDK broke the image" into a
per-language problem. Cost: three images to build and version instead of one,
and `scripts/ci.sh` runs the licence gate inside each.

## 6. Design pseudocode

Only the parts where the design is a decision, not a transcription.

### 6.1 Attempt layout, per language

```
build_attempt(analysis, scaffold, source_path, test_content):
    root = runs_root / analysis.id / random12
    if scaffold.language in ("python", "javascript", "typescript", "tsx", "php"):
        module_file = basename(source_path)             # today's flat copy
        write(root / module_file, load_source(...))
    elif scaffold.language == "java":
        pkg = package_declaration_of(load_source(...))  # parsed, NOT regexed:
                                                        # the AST layer already
                                                        # has the tree
        rel = pkg.replace(".", "/") if pkg else ""
        module_file = rel / basename(source_path)
        mkdir_p(root / rel)                             # inside root; the path
                                                        # comes from the audited
                                                        # file, so it is checked
                                                        # against traversal the
                                                        # same way ingest does
        write(root / module_file, load_source(...))
    write(root / scaffold.filename, test_content)
    write_config(root, scaffold, module_file)
```

The Java branch writes a path derived from hostile input. It MUST go through
the same normalisation `ingest/archive.py` applies to zip entries — reject
`..`, absolute and backslash segments — or a crafted `package` declaration
walks out of the attempt directory. That is the one new hostile-input surface
this phase adds, and it is the reason this file exists.

### 6.2 `docker/sandbox/run-java.sh` (contract identical to the other two)

```
WORK=/tmp/dioptra                       # artefacts on the container's OWN tmpfs
javac -d $WORK/classes $MODULE $TEST_FILE  2> $WORK/compile.log  || {
    emit_errored("compile_failed", head(compile.log))   # a REFUSAL, never a pass
    exit 0 }                                            # the host reads documents
java -javaagent:/opt/dioptra-java/jacocoagent.jar=destfile=$WORK/jacoco.exec \
     -jar /opt/dioptra-java/junit-console.jar \
     --class-path $WORK/classes --select-class <TestClass> \
     --reports-dir=$WORK                                 # JUnit writes TEST-*.xml
java -jar /opt/dioptra-java/jacococli.jar report $WORK/jacoco.exec \
     --classfiles $WORK/classes --sourcefiles . --xml $WORK/jacoco.xml
java -cp /opt/dioptra-java/pitest.jar:... org.pitest.mutationtest.commandline.MutationCoverageReport \
     --targetClasses <Class> --targetTests <TestClass> --outputFormats XML ...
normalise $WORK/jacoco.xml   -> $WORK/coverage.json     # OUR shape, in here
normalise $WORK/TEST-*.xml   -> $WORK/junit.xml
normalise $WORK/mutations.xml-> $WORK/mutation.json
cp $WORK/{coverage.json,junit.xml,mutation.json} "$OUT"  # LAST action, as today
```

### 6.3 `E4` guard

`test_plan.check_briefable` already refuses any function the AST layer cannot
parse, naming it. Once the PHP/Java profiles land, PHP and Java functions
stop being refused there **automatically** — which means the E4 guard is the
switch that turns wave 2 on. It must not be flipped before §4's Java
compilation path can produce an honest `ERRORED`, or a developer will plan a
Java method, design its cases, write its tests and only discover at E7 that
nothing can run.

## 7. Decisions — taken by `mmarin` 2026-09-23

1. **Disk / image strategy → ONE IMAGE PER LANGUAGE.** `dioptra-sandbox-js-py`,
   `dioptra-sandbox-php`, `dioptra-sandbox-java`, selected by
   `sandbox/executor.py` from `attempt.language`. Every existing deployment
   keeps the image size it has today, an air-gapped factory ships only the
   languages it audits, and a JDK that breaks does not break Python. Nothing
   on this host is pruned to make room — the 10.69 GB reclaimable belongs to
   unrelated projects and stays untouched. `scripts/ci.sh` runs the licence
   gate inside EACH image. Consequence to build: the current
   `dioptra-sandbox:latest` is renamed, so the operator's existing image tag
   stops being the one the worker asks for — the settings key must carry a
   per-language default and the rename must be said in the task file.
2. **Java scope → SPLIT, PHP FIRST.** Phase **7a** is PHP whole and lands
   first: a language that works end to end. Phase **7b** is Java, with the
   package-path attempt layout of §6.1, the compile-failure → `ERRORED`
   mapping, and the "E7 measured only for self-contained classes" limit
   written into `docs/workflow-gates.md` as a recorded non-goal — not
   discovered by a developer at E7. 7b does not start until 7a is DONE.
3. **Release number.** `v1.0.0` is tagged. Adding two languages is additive
   (1.1.0), but the `systems.installed_at` contract change of 2026-09-23 is
   already sitting unreleased on `main` and CLAUDE.md → Release rules says a
   breaking change is documented as 1.x → 2.0, never as "unfinished". These
   two want to be ONE decision, not two.
4. **Order against Phase 6.** `tasks/phase6-user-administration.md` is DESIGN
   and blocked behind its own survey, and it carries a **blocking condition**
   — its "no justification when creating an account" exception must be
   written into CLAUDE.md before any code. Nothing here depends on it, and it
   does not depend on this. Sequential is fine; they must not interleave in
   one diff.

## 8. Estimate, honestly

| Block | Size |
|---|---|
| AST profiles PHP + Java + grammar pins + fixtures + hand-counted brief tests | ~500 LOC + fixtures |
| Semgrep rules (24–30 bodies + positive/negative pairs) | ~1 200 lines YAML |
| Scaffolds PHPUnit + JUnit + escapers + assertion vocabulary | ~350 LOC |
| Result parsers (Clover, JaCoCo, Infection, Pitest) + wrappers | ~400 LOC + 2 shell wrappers |
| Image(s), pinned tools, licence gate inside each | Dockerfile work, build time dominated by the JDK |
| Docs (7 files) + task file + scope-change entry | — |

It is **not** a one-sitting job, and PHP alone is roughly 45 % of it with
none of §4's wall.

## Verdict

**PROCEED, with the phase split and two of §7's decisions taken first.**

The design holds: the `Profile` architecture, the per-language scaffold
dispatch, the in-image output normalisation and the pure-row-predicate gates
were all built to take a second language wave, and they do. Detection, SBOM
and SCA are already done. Nothing in the existing invariants has to bend.

Two things must be settled before any edit:

- **§7.1 (image strategy)** — because 2.1 GB free on this host cannot build a
  fat image, and the alternative changes `executor.py`'s image selection,
  which is sandbox code and therefore inside this gate.
- **§7.2 (Java scope)** — because §4 is a real limit, not a risk. Shipping
  Java without saying it in `docs/workflow-gates.md` as a recorded non-goal
  would be claiming a capability the sandbox does not have, which is exactly
  what P4's fail-open finding was about.

**Recommended split**, if `mmarin` wants the work to land in working pieces
rather than one large diff:

- **7a — PHP**, whole vertical: profile, rules, PHPUnit scaffold, Clover +
  Infection, image. Ships a language that works end to end.
- **7b — Java**, same vertical plus the package-path attempt layout, the
  compile-failure → `ERRORED` mapping, and the recorded non-goal.

**Signed off by `mmarin`, 2026-09-23** — §7.1 one image per language,
§7.2 PHP first (7a) and Java after (7b). Phase 7a may now be written;
phase 7b needs no new survey (this one covers it) but MUST NOT start
before 7a is at DONE with a commit.
