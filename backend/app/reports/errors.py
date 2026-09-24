"""Report engine errors."""

from __future__ import annotations

from app.core.errors import AppError


class ReportError(AppError):
    """Base class for everything the report engine rejects."""


class ReportRenderError(ReportError):
    """WeasyPrint (or python-docx) could not produce the document."""

    status_code = 500
    code = "report_render_failed"
    message_key = "errors.report.renderFailed"


class ForbiddenAssetFetch(ReportError):
    """The renderer was asked to fetch something outside the template's own assets.

    A hostile snippet must never turn the PDF renderer into an HTTP client
    (docs/threat-model.md → Finding snippets). Raised inside WeasyPrint's
    ``url_fetcher``; WeasyPrint logs it and leaves the reference unresolved.
    """

    status_code = 500
    code = "report_asset_forbidden"
    message_key = "errors.report.renderFailed"


class ReportVersionNotFound(ReportError):
    status_code = 404
    code = "report_version_not_found"
    message_key = "errors.report.versionNotFound"


class VersionNotCurrent(ReportError):
    """Only the latest version can be signed; an older number is stale."""

    status_code = 409
    code = "report_version_not_current"
    message_key = "errors.report.versionNotCurrent"


class VersionAlreadySigned(ReportError):
    status_code = 409
    code = "report_version_already_signed"
    message_key = "errors.report.versionAlreadySigned"


class UnknownSection(ReportError):
    status_code = 422
    code = "report_unknown_section"
    message_key = "errors.report.unknownSection"


class SectionTooLong(ReportError):
    status_code = 422
    code = "report_section_too_long"
    message_key = "errors.report.sectionTooLong"


# --- Asynchronous PDF export (phase 8) ---------------------------------------


class ReportJobInFlight(ReportError):
    """The person already has a PDF queued or running (survey §7.1)."""

    status_code = 409
    code = "report_job_in_flight"
    message_key = "errors.report.jobInFlight"


class ReportJobNotFound(ReportError):
    """Unknown job — or someone else's: 404 either way, never an oracle."""

    status_code = 404
    code = "report_job_not_found"
    message_key = "errors.report.jobNotFound"


class ReportJobNotReady(ReportError):
    """The PDF is not there to download: still rendering, failed, or taken."""

    status_code = 409
    code = "report_job_not_ready"
    message_key = "errors.report.jobNotReady"


class ReportEnqueueFailed(ReportError):
    status_code = 503
    code = "report_enqueue_failed"
    message_key = "errors.report.enqueueFailed"


class ReportPdfIsQueued(ReportError):
    """The synchronous endpoint no longer renders PDFs: ask for a job instead.

    Rendering one in a request is what froze the screen, and leaving the path
    open would make the one-per-person rule the screen's rather than the
    server's.
    """

    status_code = 409
    code = "report_pdf_is_queued"
    message_key = "errors.report.pdfIsQueued"
