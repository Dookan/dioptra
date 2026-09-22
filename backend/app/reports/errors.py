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
