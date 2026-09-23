"""Workflow endpoints.

Phase 2: ``POST /api/v1/findings/{id}/verdict`` (E3 triage).
Phase 3: ``POST /api/v1/analyses/{id}/stage/advance`` (the one transition),
``GET …/risk-matrix`` and ``GET|PUT …/test-plan`` (E4), ``GET|PUT …/diagram``,
``GET …/brief``, ``GET …/case-designs``, ``PUT …/cases`` and ``POST …/cases/approve`` (E5).
Phase 4: ``GET …/scaffold`` and ``PUT …/tests`` (E6), ``GET …/test-files``;
``POST …/verify``, ``GET …/verification`` and ``POST …/reopen-design`` (E7).
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.auth.deps import ActiveUser, AnalystUser, DeveloperUser, client_ip
from app.core.queue import enqueue_verification
from app.db.session import get_db
from app.ingest import service
from app.projects.router import analysis_out
from app.projects.schemas import (
    AnalysisOut,
    BriefOut,
    CasesIn,
    DesignStateOut,
    DiagramOut,
    DiagramTextIn,
    EquivalentMutantIn,
    FindingOut,
    JustificationIn,
    PlannedFunctionIn,
    RiskMatrixOut,
    RiskRowOut,
    ScaffoldOut,
    TestPlanIn,
    TestPlanOut,
    TestsIn,
    VerdictIn,
    VerificationRunOut,
    WritingStateOut,
    finding_out,
)
from app.workflow import authoring, design, stages, test_plan, triage, verify
from app.workflow.risk import risk_matrix

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])
workflow_router = APIRouter(prefix="/api/v1/analyses/{analysis_id}", tags=["workflow"])

DbSession = Annotated[Session, Depends(get_db)]


@router.post("/{finding_id}/verdict", response_model=FindingOut)
def post_verdict(
    finding_id: uuid.UUID,
    payload: VerdictIn,
    request: Request,
    user: AnalystUser,
    db: DbSession,
) -> FindingOut:
    """Stage E3: confirm a finding or discard it as a false positive, with a written reason.

    Analyst only (docs/roles-and-permissions.md): the admin and the developer
    receive 403 and an ``authz.denied`` audit row from the role dependency.
    """
    finding = triage.get_finding(db, finding_id)
    triage.record_verdict(
        db,
        finding=finding,
        actor=user,
        verdict=payload.verdict,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    return finding_out(finding)


@workflow_router.post("/stage/advance", response_model=AnalysisOut)
def advance_stage(
    analysis_id: uuid.UUID,
    payload: JustificationIn,
    request: Request,
    user: ActiveUser,
    db: DbSession,
) -> AnalysisOut:
    """Leave the current stage: the role AND the gate are checked here, never in the UI."""
    analysis = service.get_analysis(db, analysis_id)
    stages.advance(
        db,
        analysis=analysis,
        actor=user,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    return analysis_out(analysis)


@workflow_router.get("/risk-matrix", response_model=RiskMatrixOut)
def get_risk_matrix(
    analysis_id: uuid.UUID,
    _user: ActiveUser,
    db: DbSession,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> RiskMatrixOut:
    analysis = service.get_analysis(db, analysis_id)
    matrix = risk_matrix(analysis, q=q)
    return RiskMatrixOut(
        rows=[RiskRowOut(**asdict(row)) for row in matrix.rows],
        total=matrix.total,
        query=matrix.query,
    )


@workflow_router.get("/diagram", response_model=DiagramOut)
def get_diagram(
    analysis_id: uuid.UUID,
    path: str,
    function: str,
    _user: ActiveUser,
    db: DbSession,
    line: int | None = None,
) -> DiagramOut:
    """Stage E5: the flow graph of one planned function, computed from the source now."""
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=path[:1024], function=function[:200], line=line)
    return DiagramOut(**design.diagram_payload(db, analysis, ref))


@workflow_router.put("/diagram", response_model=DiagramOut)
def put_diagram_text(
    analysis_id: uuid.UUID,
    payload: DiagramTextIn,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> DiagramOut:
    """Stage E5 (developer only): the edited Mermaid text, stored as text."""
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=payload.path, function=payload.function, line=payload.line)
    design.save_diagram_text(
        db,
        analysis=analysis,
        actor=user,
        ref=ref,
        text=payload.text,
        source_ip=client_ip(request),
    )
    return DiagramOut(**design.diagram_payload(db, analysis, ref))


@workflow_router.get("/brief", response_model=BriefOut)
def get_brief(
    analysis_id: uuid.UUID,
    path: str,
    function: str,
    _user: ActiveUser,
    db: DbSession,
    line: int | None = None,
) -> BriefOut:
    """Stage E5: the brief computed from the source and the findings now, with the cases."""
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=path[:1024], function=function[:200], line=line)
    return BriefOut(**design.brief_payload(db, analysis, ref))


@workflow_router.get("/case-designs", response_model=list[DesignStateOut])
def get_case_designs(
    analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession
) -> list[DesignStateOut]:
    """Stage E5: cases count and approval per planned function (the gate's state, no parsing)."""
    analysis = service.get_analysis(db, analysis_id)
    return [DesignStateOut(**state) for state in design.design_states(analysis)]


@workflow_router.put("/cases", response_model=BriefOut)
def put_cases(
    analysis_id: uuid.UUID,
    payload: CasesIn,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> BriefOut:
    """Stage E5 (developer only): the cases in the developer's words; clears any approval."""
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=payload.path, function=payload.function, line=payload.line)
    design.save_cases(
        db,
        analysis=analysis,
        actor=user,
        ref=ref,
        cases=[case.model_dump() for case in payload.cases],
        source_ip=client_ip(request),
    )
    return BriefOut(**design.brief_payload(db, analysis, ref))


@workflow_router.post("/cases/approve", response_model=BriefOut)
def approve_cases(
    analysis_id: uuid.UUID,
    payload: PlannedFunctionIn,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> BriefOut:
    """Stage E5 (developer only): approval — every brief item covered, enough cases; audited."""
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=payload.path, function=payload.function, line=payload.line)
    design.approve_cases(db, analysis=analysis, actor=user, ref=ref, source_ip=client_ip(request))
    return BriefOut(**design.brief_payload(db, analysis, ref))


@workflow_router.get("/scaffold", response_model=ScaffoldOut)
def get_scaffold(
    analysis_id: uuid.UUID,
    path: str,
    function: str,
    _user: ActiveUser,
    db: DbSession,
    line: int | None = None,
) -> ScaffoldOut:
    """Stage E6: the deterministic scaffold and whatever the developer has stored."""
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=path[:1024], function=function[:200], line=line)
    return ScaffoldOut(**authoring.scaffold_payload(db, analysis, ref))


@workflow_router.put("/tests", response_model=ScaffoldOut)
def put_tests(
    analysis_id: uuid.UUID,
    payload: TestsIn,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> ScaffoldOut:
    """Stage E6 (developer only): store the test file the developer wrote."""
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=payload.path, function=payload.function, line=payload.line)
    authoring.save_tests(
        db,
        analysis=analysis,
        actor=user,
        ref=ref,
        content=payload.content,
        source_ip=client_ip(request),
    )
    return ScaffoldOut(**authoring.scaffold_payload(db, analysis, ref))


@workflow_router.get("/test-files", response_model=list[WritingStateOut])
def get_test_files(
    analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession
) -> list[WritingStateOut]:
    """Stage E6: cases written per planned function — the gate's state, for the banner."""
    analysis = service.get_analysis(db, analysis_id)
    return [WritingStateOut(**state) for state in authoring.writing_states(db, analysis)]


@workflow_router.get("/verification", response_model=list[VerificationRunOut])
def get_verification(
    analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession
) -> list[VerificationRunOut]:
    """Stage E7: the latest run per planned function — what the gate reads."""
    analysis = service.get_analysis(db, analysis_id)
    latest = verify.latest_runs(analysis)
    return [VerificationRunOut.model_validate(run) for run in latest.values()]


@workflow_router.post("/verify", response_model=AnalysisOut)
def post_verify(
    analysis_id: uuid.UUID,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> AnalysisOut:
    """Stage E7 (developer only): run the tests in the sandbox and re-audit them.

    The handler only ENQUEUES: running the tests starts containers, and the
    API process never holds the Docker socket (docs/threat-model.md → Test
    sandbox).
    """
    analysis = service.get_analysis(db, analysis_id)
    verify.check_can_verify(analysis)
    audit_username = user.username
    db.commit()
    enqueue_verification(analysis.id, audit_username)
    del request
    db.refresh(analysis)
    return analysis_out(analysis)


@workflow_router.post("/reopen-design", response_model=list[VerificationRunOut])
def post_reopen_design(
    analysis_id: uuid.UUID,
    payload: JustificationIn,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> list[VerificationRunOut]:
    """Stage E7 → E5 (developer only): reopen the functions whose run failed.

    Not a backwards stage move — the machine stays monotonic. It clears the
    approval of the failed functions and marks them reopened, so their design
    and their tests become editable again while the analysis sits at E7.
    """
    analysis = service.get_analysis(db, analysis_id)
    verify.reopen_design(
        db,
        analysis=analysis,
        actor=user,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    latest = verify.latest_runs(analysis)
    return [VerificationRunOut.model_validate(run) for run in latest.values()]


@workflow_router.post("/mutants/equivalent", response_model=list[VerificationRunOut])
def post_equivalent_mutant(
    analysis_id: uuid.UUID,
    payload: EquivalentMutantIn,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> list[VerificationRunOut]:
    """Stage E7 (developer only): excuse a surviving mutant as equivalent, with a reason.

    Takes effect on the next run — the developer re-runs to prove the
    verdict, and the run row records what was excused.
    """
    analysis = service.get_analysis(db, analysis_id)
    ref = design.FunctionRef(path=payload.path, function=payload.function, line=payload.line)
    verify.mark_equivalent(
        db,
        analysis=analysis,
        actor=user,
        ref=ref,
        mutant_id=payload.mutant_id,
        justification=payload.justification,
        source_ip=client_ip(request),
    )
    latest = verify.latest_runs(analysis)
    return [VerificationRunOut.model_validate(run) for run in latest.values()]


@workflow_router.get("/test-plan", response_model=TestPlanOut)
def get_test_plan(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> TestPlanOut:
    analysis = service.get_analysis(db, analysis_id)
    return TestPlanOut.model_validate(test_plan.get_test_plan(analysis))


@workflow_router.put("/test-plan", response_model=TestPlanOut)
def put_test_plan(
    analysis_id: uuid.UUID,
    payload: TestPlanIn,
    request: Request,
    user: DeveloperUser,
    db: DbSession,
) -> TestPlanOut:
    """Stage E4 (developer only): the plan is the gate's evidence, audit-logged."""
    analysis = service.get_analysis(db, analysis_id)
    plan = test_plan.save_test_plan(
        db,
        analysis=analysis,
        actor=user,
        criterion=payload.criterion,
        rationale=payload.rationale,
        functions=[item.model_dump() for item in payload.functions],
        source_ip=client_ip(request),
    )
    return TestPlanOut.model_validate(plan)
