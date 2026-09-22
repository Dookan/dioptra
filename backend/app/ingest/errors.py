"""Typed ingest errors (docs/threat-model.md → rows ZIP ingest, git URL ingest)."""

from __future__ import annotations

from app.core.errors import AppError


class IngestError(AppError):
    """Base class for everything the ingest surface rejects."""

    status_code = 422
    code = "ingest_failed"
    message_key = "errors.ingest.failed"


class ZipSlipDetected(IngestError):
    code = "zip_slip_detected"
    message_key = "errors.ingest.zipSlip"


class ZipTooLarge(IngestError):
    status_code = 413
    code = "zip_too_large"
    message_key = "errors.ingest.zipTooLarge"


class TooManyEntries(IngestError):
    status_code = 413
    code = "zip_too_many_entries"
    message_key = "errors.ingest.tooManyEntries"


class ZipBomb(IngestError):
    status_code = 413
    code = "zip_bomb"
    message_key = "errors.ingest.zipBomb"


class InvalidArchive(IngestError):
    code = "invalid_archive"
    message_key = "errors.ingest.invalidArchive"


class ForbiddenHost(IngestError):
    code = "forbidden_host"
    message_key = "errors.ingest.forbiddenHost"


class InvalidRepositoryUrl(IngestError):
    code = "invalid_repository_url"
    message_key = "errors.ingest.invalidUrl"


class RepoUnreachable(IngestError):
    status_code = 502
    code = "repo_unreachable"
    message_key = "errors.ingest.repoUnreachable"


class ProjectNotFound(IngestError):
    status_code = 404
    code = "project_not_found"
    message_key = "errors.projects.notFound"


class AnalysisNotFound(IngestError):
    status_code = 404
    code = "analysis_not_found"
    message_key = "errors.analysis.notFound"


class AnalysisNotReady(IngestError):
    """The report was requested before the pipeline finished."""

    status_code = 409
    code = "analysis_not_ready"
    message_key = "errors.analysis.notReady"
