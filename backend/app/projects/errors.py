"""Typed refusals of the project surface (E1 registration)."""

from __future__ import annotations

from app.core.errors import AppError


class ProjectError(AppError):
    status_code = 422
    code = "project_invalid"
    message_key = "errors.validation"


class InstalledAtInFuture(ProjectError):
    """The system's installation date is after today: a typo, not a fact."""

    code = "installed_at_in_future"
    message_key = "errors.projects.installedAtInFuture"
