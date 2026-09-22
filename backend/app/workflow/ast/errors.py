"""Typed AST errors. The audited source is hostile input: every limit is a typed refusal."""

from __future__ import annotations

from app.workflow.errors import WorkflowError


class AstError(WorkflowError):
    code = "ast_failed"
    message_key = "errors.ast.failed"


class UnsupportedLanguage(AstError):
    code = "ast_unsupported_language"
    message_key = "errors.ast.unsupportedLanguage"


class SourceTooLarge(AstError):
    status_code = 413
    code = "ast_source_too_large"
    message_key = "errors.ast.sourceTooLarge"


class FunctionNotFound(AstError):
    status_code = 404
    code = "ast_function_not_found"
    message_key = "errors.ast.functionNotFound"


class ParseFailed(AstError):
    """The function's source has syntax errors; a graph would be a guess."""

    code = "ast_parse_failed"
    message_key = "errors.ast.parseFailed"


class TooDeep(AstError):
    code = "ast_too_deep"
    message_key = "errors.ast.tooDeep"


class FunctionNotInPlan(AstError):
    """Diagrams exist for what E4 chose; anything else is refused."""

    code = "ast_function_not_in_plan"
    message_key = "errors.ast.functionNotInPlan"
