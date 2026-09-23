"""The analysis job: runners → raw outputs → normalization → persistence.

Runs in the worker (or inline in tests). Invariants (docs/analysis-pipeline.md):
every tool's raw output is persisted BEFORE normalization; a tool that cannot
run is a recorded coverage gap; the SBOM is generated exactly once here; the
API process never executes a tool.
"""

from __future__ import annotations

import json
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.analysis.metrics import parse_cloc_json, parse_lizard_csv, scan_commented_code
from app.analysis.models import (
    Analysis,
    AnalysisStatus,
    CodeMetrics,
    Finding,
    RawToolOutput,
    Sbom,
    SourceKind,
    ToolCategory,
    ToolRun,
    ToolStatus,
)
from app.analysis.normalizer import (
    NormalizationError,
    ToolReport,
    normalize,
    normalize_crypto,
    parse_sarif,
)
from app.analysis.runners import default_runners
from app.analysis.runners.base import WORK_DIR, ExecutionResult, Runner, RunnerSpec
from app.analysis.runners.executor import build_executor
from app.analysis.sbom import SbomInvalid, component_count, validate_cyclonedx
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.db.session import get_session_factory
from app.ingest.detection import detect
from app.ingest.git_source import shallow_clone
from app.inventory.models import CryptoAsset

logger = logging.getLogger("dioptra.pipeline")

SECURITY_CATEGORIES = frozenset({ToolCategory.SAST, ToolCategory.SECRET, ToolCategory.SCA})


class NoToolRan(AppError):
    """Every security tool was missing or failed: the analysis is FAILED, not empty."""

    status_code = 500
    code = "no_tool_ran"
    message_key = "errors.analysis.noToolRan"


class _Collected:
    """What the tool loop hands to the normalization step."""

    def __init__(self, roots: tuple[str, ...] = (WORK_DIR,)) -> None:
        #: Prefixes under which the tools saw the tree: /work (docker) or the jail (local).
        self.roots = roots
        self.reports: list[ToolReport] = []
        self.sbom: dict[str, Any] | None = None
        self.sbom_generator: str | None = None
        self.lizard: list[dict[str, Any]] = []
        self.cloc: dict[str, Any] = {}


def run_pipeline(analysis_id: uuid.UUID | str) -> None:
    """RQ entry point. Never raises: the outcome is written to the row."""
    identifier = uuid.UUID(str(analysis_id))
    settings = get_settings()
    with get_session_factory()() as db:
        analysis = db.get(Analysis, identifier)
        if analysis is None:
            logger.error("analysis %s vanished before the job ran", identifier)
            return
        analysis.status = AnalysisStatus.RUNNING
        analysis.started_at = utc_now()
        db.commit()
        try:
            _execute(db, analysis, settings)
            analysis.status = AnalysisStatus.DONE
        except AppError as exc:
            logger.warning("analysis %s failed: %s (%s)", identifier, exc.code, exc.detail)
            analysis.status = AnalysisStatus.FAILED
            analysis.failure_code = exc.code
        except Exception:
            logger.exception("analysis %s crashed", identifier)
            analysis.status = AnalysisStatus.FAILED
            analysis.failure_code = "pipeline_error"
        analysis.finished_at = utc_now()
        db.commit()


def _execute(db: Session, analysis: Analysis, settings: Settings) -> None:
    if analysis.workspace_path is None:
        message = "analysis has no workspace"
        raise AppError(message)
    workspace = Path(analysis.workspace_path)
    if analysis.source_kind is SourceKind.GIT:
        shallow_clone(
            analysis.source_ref, workspace, timeout_seconds=settings.git_clone_timeout_seconds
        )
        detection = detect(workspace)
        analysis.languages = detection.languages
        analysis.frameworks = detection.frameworks
        analysis.lockfiles = detection.lockfiles
        db.commit()

    _strip_scanner_overrides(workspace)
    out_dir = workspace.parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    settings = _stage_rules(settings, workspace.parent)
    executor = build_executor(settings)
    # Both spellings of the jail: a tool may print the path as given or resolved.
    collected = _Collected((WORK_DIR, str(workspace), str(workspace.resolve())))

    for runner in default_runners():
        reason = runner.unavailable_reason(settings)
        if reason is not None:
            db.add(
                ToolRun(
                    analysis_id=analysis.id,
                    tool=runner.name,
                    category=runner.category,
                    status=ToolStatus.MISSING,
                    detail=reason[:500],
                )
            )
            continue
        spec = runner.spec(settings, workspace=workspace, out_dir=out_dir)
        result = executor.run(spec, workspace=workspace, out_dir=out_dir)
        _record(db, analysis, runner, runner.name, spec, result, collected)
        history_spec = _history_spec(runner, settings, workspace, out_dir)
        if history_spec is not None:
            history = executor.run(history_spec, workspace=workspace, out_dir=out_dir)
            _record(
                db, analysis, runner, f"{runner.name}-history", history_spec, history, collected
            )

    # Raw outputs and coverage rows are durable before anything is normalized:
    # a normalizer bug must never lose a tool's result.
    db.commit()

    # Fail closed: an analysis in which NO security tool ran is a broken
    # deployment (no docker CLI, no image, no rules), not a clean system. It
    # must never become a DONE row that exports an empty report.
    ran_security = any(
        run.category in SECURITY_CATEGORIES and run.status is ToolStatus.RAN
        for run in analysis.tool_runs
    )
    if not ran_security:
        raise NoToolRan("no SAST/SCA/secret tool produced a report")

    findings = normalize(collected.reports, collected.roots)
    if len(findings) > settings.max_findings_per_analysis:
        # Worst first is already the normalizer's order; what falls off the end
        # is a recorded coverage gap, never a silent drop.
        db.add(
            ToolRun(
                analysis_id=analysis.id,
                tool="normalizer",
                category=ToolCategory.SAST,
                status=ToolStatus.RAN,
                detail=(
                    f"findings capped at {settings.max_findings_per_analysis} of "
                    f"{len(findings)} (worst first); the rest are not in this report"
                ),
            )
        )
        findings = findings[: settings.max_findings_per_analysis]
    for ordinal, item in enumerate(findings):
        db.add(
            Finding(
                analysis_id=analysis.id,
                ordinal=ordinal,
                category=item.category,
                tools=list(item.tools),
                rule_id=item.rule_id,
                cwe=item.cwe,
                owasp=item.owasp,
                title=item.title,
                severity=item.severity,
                cvss_score=item.cvss_score,
                cvss_vector=item.cvss_vector,
                path=item.path,
                line=item.line,
                snippet=item.snippet,
                message=item.message,
                advisory=item.advisory,
                references=list(item.references),
                fingerprint=item.fingerprint,
            )
        )
    # The CBOM rows (P5): the crypto-inventory results the normalizer set aside.
    for asset in normalize_crypto(collected.reports, collected.roots):
        db.add(
            CryptoAsset(
                analysis_id=analysis.id,
                primitive=asset.primitive,
                algorithm=asset.algorithm,
                path=asset.path,
                line=asset.line,
                weak=asset.weak,
                rule_id=asset.rule_id,
            )
        )
    if collected.sbom is not None:
        db.add(
            Sbom(
                analysis_id=analysis.id,
                generator=collected.sbom_generator or "syft",
                component_count=component_count(collected.sbom),
                document=collected.sbom,
            )
        )
    db.add(
        CodeMetrics(
            analysis_id=analysis.id,
            functions=collected.lizard,
            lines=collected.cloc,
            commented_code_files=scan_commented_code(workspace),
        )
    )
    db.commit()


#: Files a scanned tree can ship to reconfigure a scanner from the inside.
#: ``--config`` covers the rule files; these are loaded from the source
#: directory regardless of flags (proven for gitleaks 8.28), so they are
#: removed from the jail before the first container starts.
SCANNER_OVERRIDE_FILES = (".gitleaksignore",)


def _strip_scanner_overrides(workspace: Path) -> None:
    for name in SCANNER_OVERRIDE_FILES:
        candidate = workspace / name
        if candidate.is_symlink() or candidate.is_file():
            candidate.unlink()


def _stage_rules(settings: Settings, analysis_dir: Path) -> Settings:
    """Copy our Semgrep rules beside the jail.

    ``docker run -v`` is resolved by the HOST daemon, so a path that only exists
    inside the worker image (``/srv/app/rules``) cannot be mounted into the
    tool container. The data directory is shared with the host at the same
    path (docker-compose.yml → DIOPTRA_DATA_DIR), so a copy placed next to the
    workspace is mountable everywhere. Cheap: a few KiB per analysis.
    """
    source = settings.rules_dir
    if not source.is_dir():
        return settings
    staged = analysis_dir / "rules"
    shutil.rmtree(staged, ignore_errors=True)
    shutil.copytree(
        source, staged, symlinks=False, ignore=shutil.ignore_patterns("tests", "__pycache__")
    )
    return settings.model_copy(update={"rules_dir": staged})


def _history_spec(
    runner: Runner, settings: Settings, workspace: Path, out_dir: Path
) -> RunnerSpec | None:
    """Gitleaks also scans the history when the tree carries one."""
    spec_git_history = getattr(runner, "spec_git_history", None)
    if spec_git_history is None or not (workspace / ".git").is_dir():
        return None
    spec: RunnerSpec = spec_git_history(settings, workspace=workspace, out_dir=out_dir)
    return spec


def _record(
    db: Session,
    analysis: Analysis,
    runner: Runner,
    tool_name: str,
    spec: RunnerSpec,
    result: ExecutionResult,
    collected: _Collected,
) -> None:
    db.add(
        RawToolOutput(
            analysis_id=analysis.id,
            tool=tool_name[:40],
            exit_code=result.exit_code,
            stderr=result.stderr[: 64 * 1024] if result.stderr else None,
            output=result.output,
            truncated=result.truncated,
        )
    )
    status = result.status
    detail = result.detail
    if status is ToolStatus.RAN and result.output is not None:
        try:
            _collect(runner, spec, result.output, collected)
        except (NormalizationError, SbomInvalid, ValueError) as exc:
            status = ToolStatus.FAILED
            detail = f"output rejected: {exc.__class__.__name__}"
    db.add(
        ToolRun(
            analysis_id=analysis.id,
            tool=tool_name[:40],
            category=runner.category,
            status=status,
            detail=detail[:500] if detail else None,
            duration_ms=result.duration_ms,
        )
    )


def _collect(runner: Runner, spec: RunnerSpec, output: bytes, collected: _Collected) -> None:
    if runner.category in SECURITY_CATEGORIES:
        collected.reports.append(
            ToolReport(tool=runner.name, category=runner.category, sarif=parse_sarif(output))
        )
    elif runner.category is ToolCategory.SBOM:
        collected.sbom = validate_cyclonedx(output)
        collected.sbom_generator = runner.name
    elif runner.category is ToolCategory.METRICS:
        text = output.decode("utf-8", errors="replace")
        if spec.output_file.endswith(".csv"):
            collected.lizard = parse_lizard_csv(text, collected.roots)
        else:
            try:
                json.loads(text)
            except ValueError as exc:
                raise NormalizationError("cloc output is not JSON") from exc
            collected.cloc = parse_cloc_json(text)
