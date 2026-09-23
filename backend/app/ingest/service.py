"""Ingest use cases: create projects, accept a ZIP or a git URL, queue the pipeline."""

from __future__ import annotations

import shutil
import uuid
from datetime import date
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.models import Analysis, AnalysisStatus, SourceKind
from app.audit import service as audit
from app.auth.models import User
from app.core.config import get_settings
from app.core.queue import enqueue_pipeline
from app.ingest.archive import ExtractionLimits, extract_zip
from app.ingest.detection import detect
from app.ingest.errors import AnalysisNotFound, ProjectNotFound, ZipTooLarge
from app.ingest.git_source import validate_repository_url
from app.projects.models import Project, System


def get_project(db: Session, project_id: uuid.UUID) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise ProjectNotFound(str(project_id))
    return project


def list_projects(db: Session) -> list[Project]:
    return list(db.scalars(select(Project).order_by(Project.created_at.desc())))


def get_analysis(db: Session, analysis_id: uuid.UUID) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise AnalysisNotFound(str(analysis_id))
    return analysis


def list_analyses(db: Session, project_id: uuid.UUID) -> list[Analysis]:
    statement = (
        select(Analysis)
        .where(Analysis.project_id == project_id)
        .order_by(Analysis.created_at.desc())
    )
    return list(db.scalars(statement))


def create_project(
    db: Session,
    *,
    actor: User,
    name: str,
    description: str | None,
    system_name: str,
    framework: str | None,
    database: str | None,
    developer: str | None,
    installed_at: date | None,
    source_ip: str | None,
) -> Project:
    """Stage E1: register the project and its system profile."""
    project = Project(name=name, description=description, created_by_id=actor.id)
    project.system = System(
        name=system_name,
        framework=framework,
        database=database,
        developer=developer,
        installed_at=installed_at,
    )
    db.add(project)
    db.flush()
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="project.create",
        target=str(project.id),
        source_ip=source_ip,
    )
    return project


def _jail_for(project_id: uuid.UUID, analysis_id: uuid.UUID) -> str:
    root = get_settings().workspace_root
    return str(root / str(project_id) / str(analysis_id) / "src")


def ingest_zip(
    db: Session,
    *,
    project: Project,
    actor: User,
    upload: BinaryIO,
    upload_size: int | None,
    filename: str,
    source_ip: str | None,
) -> Analysis:
    """Stage E2 from an archive: extract into the jail, detect, queue the pipeline."""
    settings = get_settings()
    if upload_size is not None and upload_size > settings.max_zip_bytes:
        raise ZipTooLarge(f"{upload_size} bytes")

    analysis = Analysis(
        project_id=project.id,
        source_kind=SourceKind.ZIP,
        source_ref=filename[:512],
        status=AnalysisStatus.QUEUED,
        created_by_id=actor.id,
    )
    db.add(analysis)
    db.flush()
    jail = _jail_for(project.id, analysis.id)
    analysis.workspace_path = jail

    try:
        extract_zip(
            upload,
            Path(jail),
            ExtractionLimits(
                max_entries=settings.max_zip_entries,
                max_unpacked_bytes=settings.max_unpacked_bytes,
                max_ratio=settings.max_zip_ratio,
            ),
        )
    except Exception:
        # The archive removes the jail itself; the analysis directory around
        # it belongs to a row that is about to be rolled back.
        shutil.rmtree(Path(jail).parent, ignore_errors=True)
        raise
    detection = detect(Path(jail))
    analysis.languages = detection.languages
    analysis.frameworks = detection.frameworks
    analysis.lockfiles = detection.lockfiles

    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="analysis.ingest.zip",
        target=str(analysis.id),
        source_ip=source_ip,
    )
    # The worker (or the inline runner) opens its own session: the row must be
    # visible before the job exists.
    db.commit()
    enqueue_pipeline(analysis.id)
    return analysis


def ingest_git(
    db: Session,
    *,
    project: Project,
    actor: User,
    url: str,
    source_ip: str | None,
) -> Analysis:
    """Stage E2 from a repository URL: validate now, clone in the worker."""
    normalized = validate_repository_url(url)
    analysis = Analysis(
        project_id=project.id,
        source_kind=SourceKind.GIT,
        source_ref=normalized,
        status=AnalysisStatus.QUEUED,
        created_by_id=actor.id,
    )
    db.add(analysis)
    db.flush()
    analysis.workspace_path = _jail_for(project.id, analysis.id)
    audit.record(
        db,
        actor_username=actor.username,
        actor_id=actor.id,
        actor_role=actor.role.value,
        action="analysis.ingest.git",
        target=str(analysis.id),
        source_ip=source_ip,
    )
    db.commit()
    enqueue_pipeline(analysis.id)
    return analysis
