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


class UploadTooLarge(ZipTooLarge):
    """The UPLOAD passed the compressed cap (phase 10), declared or streamed.

    Same ``code`` as its parent, so the contract a client matches on does not
    move; its own key, because this refusal happens in the request and can say
    the limit (``context["limit_mib"]``), while the parent is also raised by
    the worker over the UNPACKED size, where no number is carried.
    """

    message_key = "errors.ingest.uploadTooLarge"


class UploadMediaTypeUnsupported(IngestError):
    """Phase 10 (1.x contract change): the ZIP is the raw body, never multipart."""

    status_code = 415
    code = "upload_media_type_unsupported"
    message_key = "errors.ingest.uploadMediaType"


class UploadInterrupted(IngestError):
    """The client stopped sending before the body ended."""

    status_code = 400
    code = "upload_interrupted"
    message_key = "errors.ingest.uploadInterrupted"


class UploadMissing(IngestError):
    """The worker found no spooled upload for a ZIP analysis it must extract."""

    status_code = 500
    code = "upload_missing"
    message_key = "errors.ingest.uploadMissing"


class AnalysisEnqueueFailed(IngestError):
    """The broker refused the job: the analysis is closed as FAILED, not left QUEUED."""

    status_code = 503
    code = "analysis_enqueue_failed"
    message_key = "errors.ingest.enqueueFailed"


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
