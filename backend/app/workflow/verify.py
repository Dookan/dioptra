"""Stage E7 (day 17): run the developer's tests and re-audit them.

Four questions, in this order, per planned function:

1. did the tests pass at all (JUnit)?
2. does every case assert something (our own rule, over the AST)?
3. does the coverage meet the E4 criterion, and did every brief item's line
   actually run with its branch complete?
4. did any mutant survive?

Any "no" closes the gate. The developer is shown WHICH — the exact mutant,
the uncovered brief items, the cases that assert nothing — because "rompimos
el código a propósito; un buen test debe fallar" is a lesson only if you can
see what survived.

This runs in the WORKER, never in a request: it starts containers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, Stage
from app.audit import service as audit
from app.auth.models import User
from app.core.clock import utc_now
from app.core.config import Settings
from app.sandbox import executor, results, workspace
from app.sandbox.errors import SandboxError
from app.workflow import authoring
from app.workflow.ast.errors import AstError
from app.workflow.ast.extract import declared_in_class
from app.workflow.ast.source import load_source
from app.workflow.design import FunctionRef, get_design
from app.workflow.errors import (
    MutantUnknown,
    StageLocked,
    StageNotReached,
    TestPlanEmpty,
    UnparsableTests,
    WorkflowError,
)
from app.workflow.models import (
    REASON_ASSERTION_FREE,
    REASON_BRIEF_UNCOVERED,
    REASON_COVERAGE_SHORT,
    REASON_MUTANT_SURVIVED,
    REASON_SANDBOX_ERROR,
    REASON_TESTS_FAILED,
    CoverageCriterion,
    EquivalentMutant,
    VerificationRun,
    VerificationStatus,
)
from app.workflow.scaffold import ScaffoldFile
from app.workflow.scaffold.inspect import assertion_free_cases
from app.workflow.triage import clean_justification
from app.workflow.triage import strip_control_chars as results_strip

MAX_DETAIL_CHARS = 4000


@dataclass(frozen=True)
class Outcome:
    """The verdict on one function, before it becomes a row."""

    status: VerificationStatus
    reasons: list[str]
    coverage: results.Coverage
    uncovered_items: list[str]
    surviving_mutants: list[dict[str, str]]
    assertion_free: list[str]
    failed_cases: list[str]
    detail: str | None
    duration_ms: int
    #: Survivors excused as equivalent BEFORE this run (shown, never counted).
    equivalent_mutants: list[dict[str, str]] = field(default_factory=list)
    #: False when the mutation tool could never have produced a mutant for this
    #: function (a free PHP function under Infection). The gate then decides on
    #: the other three questions and every surface SAYS SO — a declared gap,
    #: never a silent pass.
    mutation_measured: bool = True


#: Shown to the developer when the mutation tool produced no mutant at all AND
#: the code was mutable, i.e. the tool broke. English like every other
#: code-side string; the screen shows it as the ERRORED run's detail.
NO_MUTANTS_DETAIL = "mutation produced no mutants: nothing about the tests was measured"

#: Languages whose mutation tool only mutates code declared inside a class, so
#: a free function yields no mutant however good or bad the tests are. Measured
#: for Infection 0.35.4 on 2026-09-23 (tasks/phase7a-php.md); mutmut and
#: Stryker mutate free functions, which is why this is a set and not a flag.
CLASS_ONLY_MUTATION_LANGUAGES = frozenset({"php"})


def mutation_is_measurable(analysis: Analysis, *, language: str, ref: FunctionRef) -> bool:
    """Could the mutation tool have produced ANY mutant for this function?

    Answered from the SOURCE before the run is scored, never inferred from an
    empty result — "no mutants" must not be allowed to read as "nothing
    survived" (docs/workflow-gates.md → E7 re-audit rules, question 4).
    A source that cannot be read answers True, the conservative side: the run
    is then scored on mutation like any other.
    """
    if language not in CLASS_ONLY_MUTATION_LANGUAGES:
        return True
    try:
        source = load_source(analysis, ref.path)
    except (AstError, OSError):
        return True
    return declared_in_class(source, language, ref.function, ref.line)


def _errored(detail: str | None, *, duration_ms: int = 0) -> Outcome:
    """The attempt could not be carried out, or produced nothing to score."""
    return Outcome(
        status=VerificationStatus.ERRORED,
        reasons=[REASON_SANDBOX_ERROR],
        coverage=results.EMPTY_COVERAGE,
        uncovered_items=[],
        surviving_mutants=[],
        assertion_free=[],
        failed_cases=[],
        detail=detail,
        duration_ms=duration_ms,
    )


def _require_verification_stage(analysis: Analysis) -> None:
    if analysis.stage is Stage.VERIFICATION:
        return
    if analysis.stage is Stage.REPORT:
        raise StageLocked(f"analysis {analysis.id} is at {analysis.stage.value}")
    raise StageNotReached(f"analysis {analysis.id} is at {analysis.stage.value}")


def check_can_verify(analysis: Analysis) -> None:
    """The request-side guard: E7 only, and there has to be a plan to verify."""
    _require_verification_stage(analysis)
    plan = analysis.test_plan
    if plan is None or not plan.functions:
        raise TestPlanEmpty(f"analysis {analysis.id} has no planned function")


def _brief_lines(scaffold_brief: dict[str, Any]) -> list[tuple[str, int | None]]:
    items = scaffold_brief.get("items")
    if not isinstance(items, list):
        return []
    out: list[tuple[str, int | None]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        line = item.get("line")
        out.append((str(item.get("id", "")), line if isinstance(line, int) else None))
    return out


def _criterion_met(criterion: CoverageCriterion, coverage: results.Coverage) -> bool:
    """The E4 exigency, applied to the module under test.

    ``statements`` ⊂ ``decisions`` ⊂ ``paths``: each level keeps the previous
    one's requirement and adds its own. Brief items are checked regardless —
    that check is the plan's "each brief branch verified by line", not the
    criterion.
    """
    if coverage.missing_lines:
        return False
    if criterion is CoverageCriterion.STATEMENTS:
        return True
    return not coverage.partial_branch_lines


def verify_function(
    settings: Settings,
    *,
    analysis: Analysis,
    ref: FunctionRef,
    scaffold: ScaffoldFile,
    content: str,
    criterion: CoverageCriterion,
    equivalent: dict[str, str] | None = None,
) -> Outcome:
    """One sandbox attempt. Never raises for a test's behaviour — only records it.

    ``equivalent`` maps mutant ids the developer already excused (with a
    written reason, audited) to their text: those survivors are reported
    beside the verdict but never close the gate.
    """
    attempt = None
    try:
        attempt = workspace.build_attempt(
            settings,
            analysis=analysis,
            scaffold=scaffold,
            source_path=ref.path,
            test_content=content,
        )
        result = executor.run(settings, attempt)
        # A container that produced no document measured NOTHING, and every
        # question below would answer "yes" on the empty values: 100 % of no
        # lines, no failing test, no surviving mutant. That is a fail-OPEN in
        # a gate, so it is an error, not a verdict. Same for an exit code the
        # runners never return (the wrappers swallow test failures on purpose;
        # anything else is the entrypoint itself breaking).
        if result.missing or result.exit_code != 0:
            why = "; ".join(
                filter(
                    None,
                    [
                        f"no {', '.join(result.missing)}" if result.missing else "",
                        f"exit {result.exit_code}" if result.exit_code != 0 else "",
                        results_strip(result.stderr)[-MAX_DETAIL_CHARS:],
                    ],
                )
            )
            return _errored(why, duration_ms=result.duration_ms)
        coverage = results.parse_coverage(
            result.coverage, language=scaffold.language, module_file=attempt.module_file
        )
        mutation = results.parse_mutation(result.mutation)
        # A run that generated ZERO mutants measured nothing about the tests,
        # and "no survivor" would then read as a pass — the same fail-OPEN the
        # missing-document check above exists for. Known cause in PHP:
        # Infection only mutates code INSIDE A CLASS, so a free function yields
        # total = 0 no matter how good or bad the suite is (measured
        # 2026-09-23, tasks/phase7a-php.md → Open defects).
        # ``None`` is NOT zero and must not trip this: mutmut's counts are best
        # effort while its survivor list is the exact one
        # (docker/sandbox/run-python.sh).
        mutation_measured = True
        if mutation.total == 0:
            # `mmarin`, 2026-09-23: a function the tool CANNOT mutate is not a
            # dead end — the gate decides on the other three questions and the
            # gap is declared everywhere (run row, screen, report). A function
            # it COULD have mutated and did not is still the tool breaking.
            if mutation_is_measurable(analysis, language=scaffold.language, ref=ref):
                return _errored(NO_MUTANTS_DETAIL, duration_ms=result.duration_ms)
            mutation_measured = False
        failed = results.parse_failed_cases(result.junit)
        detail = results_strip(result.stderr)[-MAX_DETAIL_CHARS:] or None
        duration = result.duration_ms
    except (SandboxError, WorkflowError, AstError, OSError) as error:
        # Anything that stops the attempt is a RECORDED reason, never a job
        # that dies and takes the rows already written for this batch with
        # it. `WorkflowError` is defensive here — the scaffold lookup that
        # used to raise it has its own guard in `run_verification` now — and
        # stays because this is the only place a failure becomes visible.
        return _errored(str(error)[:MAX_DETAIL_CHARS])
    finally:
        if attempt is not None:
            workspace.discard(attempt)

    try:
        assertion_free = assertion_free_cases(content, ref.path, scaffold.cases)
    except (UnparsableTests, AstError):
        assertion_free = [case.id for case in scaffold.cases]

    uncovered = [
        item_id
        for item_id, line in _brief_lines(scaffold_brief_of(analysis, ref))
        if not coverage.covers_line(line)
    ]

    # An excusal names a mutant by id AND by the text it had when the
    # developer judged it: mutant ids are index-based, so a tool bump can
    # renumber them and a mark would otherwise excuse a DIFFERENT survivor.
    # A changed text is a real survivor again, shown to the developer.
    excused = equivalent or {}

    def _is_excused(m: dict[str, str]) -> bool:
        stored = excused.get(m.get("id", ""))
        return stored is not None and stored == m.get("mutant", "")

    survivors = [m for m in mutation.survived if not _is_excused(m)]
    excused_now = [
        {"id": m.get("id", ""), "line": m.get("line", ""), "mutant": m.get("mutant", "")}
        for m in mutation.survived
        if _is_excused(m)
    ]

    reasons: list[str] = []
    if failed:
        reasons.append(REASON_TESTS_FAILED)
    if assertion_free:
        reasons.append(REASON_ASSERTION_FREE)
    if not _criterion_met(criterion, coverage):
        reasons.append(REASON_COVERAGE_SHORT)
    if uncovered:
        reasons.append(REASON_BRIEF_UNCOVERED)
    if survivors:
        reasons.append(REASON_MUTANT_SURVIVED)

    return Outcome(
        status=VerificationStatus.PASSED if not reasons else VerificationStatus.FAILED,
        reasons=reasons,
        coverage=coverage,
        uncovered_items=uncovered,
        surviving_mutants=survivors,
        assertion_free=assertion_free,
        failed_cases=failed,
        mutation_measured=mutation_measured,
        detail=detail,
        duration_ms=duration,
        equivalent_mutants=excused_now,
    )


def scaffold_brief_of(analysis: Analysis, ref: FunctionRef) -> dict[str, Any]:
    """The brief snapshot taken when the cases were approved."""
    for design in analysis.case_designs:
        if (design.path, design.function, design.line) == (ref.path, ref.function, ref.line):
            return design.brief if isinstance(design.brief, dict) else {}
    return {}


def run_verification(
    db: Session,
    settings: Settings,
    *,
    analysis: Analysis,
    actor: User,
    source_ip: str | None,
) -> list[VerificationRun]:
    """Verify every planned function and record one run each."""
    _require_verification_stage(analysis)
    plan = analysis.test_plan
    rows = plan.functions if plan is not None else []
    criterion = plan.criterion if plan is not None else CoverageCriterion.DECISIONS

    runs: list[VerificationRun] = []
    for row in rows:
        ref = FunctionRef(
            path=str(row.get("path")), function=str(row.get("function")), line=row.get("line")
        )
        design = get_design(db, analysis, ref)
        stored = authoring.get_test_file(db, analysis, ref)
        if design is None or stored is None or not stored.content.strip():
            outcome = Outcome(
                status=VerificationStatus.FAILED,
                reasons=[REASON_TESTS_FAILED],
                coverage=results.EMPTY_COVERAGE,
                uncovered_items=[],
                surviving_mutants=[],
                assertion_free=[],
                failed_cases=[],
                detail=None,
                duration_ms=0,
            )
        else:
            try:
                scaffold = authoring.scaffold_of(db, analysis, ref)
            except (WorkflowError, AstError) as error:
                outcome = _errored(str(error)[:MAX_DETAIL_CHARS])
            else:
                outcome = verify_function(
                    settings,
                    analysis=analysis,
                    ref=ref,
                    scaffold=scaffold,
                    content=stored.content,
                    criterion=criterion,
                    equivalent=equivalent_mutants_of(db, analysis, ref),
                )
        runs.append(_record(db, analysis=analysis, actor=actor, ref=ref, outcome=outcome))

    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="verification.run",
        target=f"analysis:{analysis.id}:{len(runs)}"[:255],
        source_ip=source_ip,
    )
    db.flush()
    return runs


def _record(
    db: Session, *, analysis: Analysis, actor: User, ref: FunctionRef, outcome: Outcome
) -> VerificationRun:
    if outcome.status is VerificationStatus.PASSED:
        # A pass closes the E7 → E5 loop for this function: its design and
        # tests are locked again (approval alone must NOT clear the flag —
        # the developer still has to rewrite the tests after re-approving).
        for design in analysis.case_designs:
            if (design.path, design.function, design.line) == (ref.path, ref.function, ref.line):
                design.reopened_at = None
    run = VerificationRun(
        analysis_id=analysis.id,
        path=ref.path,
        function=ref.function,
        line=ref.line,
        status=outcome.status,
        reasons=list(outcome.reasons),
        coverage=outcome.coverage.as_dict(),
        uncovered_items=list(outcome.uncovered_items),
        surviving_mutants=list(outcome.surviving_mutants),
        equivalent_mutants=list(outcome.equivalent_mutants),
        assertion_free_cases=list(outcome.assertion_free),
        failed_cases=list(outcome.failed_cases),
        mutation_measured=outcome.mutation_measured,
        detail=outcome.detail,
        duration_ms=outcome.duration_ms,
        created_by_username=actor.username,
    )
    db.add(run)
    return run


def latest_runs(analysis: Analysis) -> dict[tuple[str, str, int | None], VerificationRun]:
    """The most recent run per planned function — what the gate reads."""
    latest: dict[tuple[str, str, int | None], VerificationRun] = {}
    for run in analysis.verification_runs:
        latest[(run.path, run.function, run.line)] = run
    return latest


def reopen_design(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    justification: str,
    source_ip: str | None,
) -> list[str]:
    """The E7 → E5 loop, as an explicit action rather than a backwards stage move.

    The stage machine stays monotonic (``stages.advance`` is still the only
    transition). What this does is clear the approval of the functions whose
    latest run failed and mark them reopened, so E5's writers — and E6's —
    accept them again while the analysis sits at E7.

    Going back to the design is a sensitive action, so the written reason is
    checked HERE, with the same helper ``stages.advance`` and the triage
    verdicts use. The screen disables its button below ten characters, but the
    screen is never the enforcement (CLAUDE.md → Gates are server-side).
    """
    reason = clean_justification(justification)
    _require_verification_stage(analysis)
    reopened: list[str] = []
    latest = latest_runs(analysis)
    for design in analysis.case_designs:
        run = latest.get((design.path, design.function, design.line))
        if run is None or run.status is VerificationStatus.PASSED:
            continue
        design.approved_at = None
        design.approved_by_username = None
        design.reopened_at = utc_now()
        reopened.append(f"{design.path}:{design.function}")
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="verification.reopen",
        target=f"analysis:{analysis.id}:{len(reopened)}"[:255],
        justification=reason,
        source_ip=source_ip,
    )
    db.flush()
    return reopened


def equivalent_mutants_of(db: Session, analysis: Analysis, ref: FunctionRef) -> dict[str, str]:
    """``{mutant id: text}`` the developer excused for this function."""
    rows = db.scalars(
        select(EquivalentMutant).where(
            EquivalentMutant.analysis_id == analysis.id,
            EquivalentMutant.path == ref.path,
            EquivalentMutant.function == ref.function,
            EquivalentMutant.line == ref.line,
        )
    )
    return {row.mutant_id: row.mutant for row in rows}


def mark_equivalent(
    db: Session,
    *,
    analysis: Analysis,
    actor: User,
    ref: FunctionRef,
    mutant_id: str,
    justification: str,
    source_ip: str | None,
) -> EquivalentMutant:
    """Excuse one surviving mutant of the function's LATEST run, with a written reason.

    Some mutants no test can kill (a codec name's case, ``None`` for
    ``False``). Like a triage verdict, the judgement is a person's, it is
    justified in writing and it is audited (``verification.mutant.equivalent``).
    It takes effect on the NEXT run — the run rows stay immutable and the
    gate stays a row predicate — so the developer re-runs to prove it.
    """
    reason = clean_justification(justification)
    _require_verification_stage(analysis)
    latest = latest_runs(analysis).get((ref.path, ref.function, ref.line))
    if latest is None:
        raise MutantUnknown(f"{ref.function}: never verified"[:200])
    survivor = next((m for m in latest.surviving_mutants if m.get("id") == mutant_id), None)
    if survivor is None:
        raise MutantUnknown(f"{ref.function}: {mutant_id}"[:200])
    existing = db.scalars(
        select(EquivalentMutant).where(
            EquivalentMutant.analysis_id == analysis.id,
            EquivalentMutant.path == ref.path,
            EquivalentMutant.function == ref.function,
            EquivalentMutant.line == ref.line,
            EquivalentMutant.mutant_id == mutant_id,
        )
    ).first()
    if existing is not None:
        return existing
    row = EquivalentMutant(
        analysis_id=analysis.id,
        path=ref.path,
        function=ref.function,
        line=ref.line,
        mutant_id=mutant_id[:200],
        mutant=str(survivor.get("mutant", ""))[:400],
        justification=reason,
        created_by_username=actor.username,
    )
    db.add(row)
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="verification.mutant.equivalent",
        target=f"analysis:{analysis.id}:{ref.path}:{ref.line}:{ref.function}:{mutant_id}"[:255],
        justification=reason,
        source_ip=source_ip,
    )
    db.flush()
    return row
