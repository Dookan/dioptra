"""Workflow endpoints.

Phase 2: ``POST /api/v1/findings/{id}/verdict`` (E3 triage).
Phase 3: ``POST /api/v1/analyses/{id}/stage/advance`` (the one transition),
``GET …/risk-matrix`` and ``GET|PUT …/test-plan`` (E4), ``GET|PUT …/diagram``,
``GET …/brief``, ``GET …/case-designs``, ``PUT …/cases`` and ``POST …/cases/approve`` (E5).
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth.deps import ActiveUser, AnalystUser, DeveloperUser, client_ip
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
    FindingOut,
    JustificationIn,
    PlannedFunctionIn,
    RiskRowOut,
    TestPlanIn,
    TestPlanOut,
    VerdictIn,
    finding_out,
)
from app.workflow import design, stages, test_plan, triage
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


@workflow_router.get("/risk-matrix", response_model=list[RiskRowOut])
def get_risk_matrix(analysis_id: uuid.UUID, _user: ActiveUser, db: DbSession) -> list[RiskRowOut]:
    analysis = service.get_analysis(db, analysis_id)
    return [RiskRowOut(**asdict(row)) for row in risk_matrix(analysis)]


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
