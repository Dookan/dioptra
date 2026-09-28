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

from app.analysis import artefacts
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
    NormalizedFinding,
    ToolReport,
    normalize,
    normalize_crypto,
    parse_sarif,
    report_order,
)
from app.analysis.progress import ACQUIRE, NORMALIZE
from app.analysis.runners import default_runners
from app.analysis.runners.base import WORK_DIR, ExecutionResult, Runner, RunnerSpec
from app.analysis.runners.executor import build_executor
from app.analysis.sbom import SbomInvalid, component_count, validate_cyclonedx
from app.analysis.third_party import finding_is_third_party, is_third_party
from app.core.clock import utc_now
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.db.session import get_session_factory
from app.ingest.detection import detect
from app.ingest.git_source import shallow_clone
from app.ingest.upload import extract_upload
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
        analysis.current_step = None
        analysis.finished_at = utc_now()
        db.commit()


def _enter(db: Session, analysis: Analysis, step: str) -> None:
    """Record the step the worker is entering, visible to a poll at once."""
    analysis.current_step = step
    db.commit()


def _execute(db: Session, analysis: Analysis, settings: Settings) -> None:
    if analysis.workspace_path is None:
        message = "analysis has no workspace"
        raise AppError(message)
    workspace = Path(analysis.workspace_path)
    _enter(db, analysis, ACQUIRE)
    # Acquisition happens HERE, in the worker, for both sources: the git clone
    # since P1, the ZIP's extraction since phase 10 (`tasks/phase10-survey.md`
    # §3 option C). The request only spooled the archive; `archive.py`'s
    # guards run unchanged, just in this process instead of the API's.
    acquired = False
    if analysis.source_kind is SourceKind.GIT:
        shallow_clone(
            analysis.source_ref, workspace, timeout_seconds=settings.git_clone_timeout_seconds
        )
        acquired = True
    elif analysis.source_kind is SourceKind.ZIP:
        try:
            extract_upload(workspace, settings)
        except Exception:
            # Nothing of a refused archive stays on disk; the row keeps the
            # typed failure code (`run_pipeline`).
            shutil.rmtree(workspace.parent, ignore_errors=True)
            raise
        acquired = True
    if acquired:
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
        _enter(db, analysis, runner.name)
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
            db.commit()
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
        # Each tool's coverage row and raw output are durable as soon as the
        # tool ends. The next `_enter` would commit them too; this makes the
        # per-tool durability explicit instead of a side effect of the next step.
        db.commit()

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

    _enter(db, analysis, NORMALIZE)
    # Phase 11: our own walk for dumps, uploads, `.env`, keys and logs. Its
    # hits are merged BEFORE the ordering below, so a dump competes for the
    # cap on its severity like any other finding, never last in line.
    findings = sorted(
        [*normalize(collected.reports, collected.roots), *_scan_artefacts(db, analysis, workspace)],
        key=report_order,
    )
    # The audited project's OWN findings rank before dependency ones, and the
    # normalizer's worst-first order is preserved inside each group because
    # Python's sort is stable.
    #
    # This is load-bearing for the cap below, not cosmetic. Severity used to
    # collapse to INFO for every SAST finding (the SARIF `defaultConfiguration`
    # defect fixed the same day), so the order inside the cap was effectively
    # arbitrary and nothing was systematically evicted. Now that a dependency
    # tree can contribute hundreds of genuine HIGHs, a fat or hostile `vendor/`
    # would fill every slot and push the team's own findings out of the stored
    # set entirely — out of the report, the executive summary, the E3 queue AND
    # the E4 risk matrix — leaving only what nobody on that team can fix. The
    # audited tree chooses how many files it ships, so that is its decision to
    # make, which is exactly why it must not be able to make it.
    # Found by the precommit security auditor, 2026-09-23.
    # TWO levels, not one. Using the triage predicate alone reopened the very
    # defect this sort closes: it exempts the whole SCA category whatever the
    # path, so a vendored `composer.lock` landed in the privileged half and a
    # tree shipping many nested lockfiles could still evict its own developers'
    # findings. The first key is the PATH rule, so dependency code is
    # de-prioritised however it was found; the second keeps a vendored CVE
    # above vendored SAST, because it is the only one of the two an analyst
    # can still act on. Own code < vendored SCA < vendored everything else.
    # Found by the precommit security auditor re-auditing its own remedy.
    findings = sorted(
        findings,
        key=lambda item: (
            is_third_party(item.path),
            finding_is_third_party(item.category, item.path),
        ),
    )
    if len(findings) > settings.max_findings_per_analysis:
        # What falls off the end is a recorded coverage gap, never a silent
        # drop — and it is dependency code before it is ever the team's own.
        db.add(
            ToolRun(
                analysis_id=analysis.id,
                tool="normalizer",
                category=ToolCategory.SAST,
                status=ToolStatus.RAN,
                detail=(
                    f"findings capped at {settings.max_findings_per_analysis} of "
                    f"{len(findings)} (the audited project's own code first, then "
                    f"dependency code, worst first within each); the rest are not "
                    f"in this report"
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
                # Decided once, here, from the category and the report-relative
                # path — not at read time, so the E3 gate can be a plain row
                # predicate. Same predicate as the sort key above, deliberately:
                # two copies of this rule would drift.
                third_party=finding_is_third_party(item.category, item.path),
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


def _scan_artefacts(db: Session, analysis: Analysis, workspace: Path) -> list[NormalizedFinding]:
    """Run the artefact scan, persist what it saw, and return it as findings.

    The raw hits are durable before they become findings, like every tool's
    output; a scan that could not run, or stopped at its cap, is a recorded
    coverage gap, never a silent pass (`tasks/phase11-survey.md` §7).
    """
    try:
        scan = artefacts.scan_artefacts(workspace)
    except OSError as exc:
        db.add(
            ToolRun(
                analysis_id=analysis.id,
                tool=artefacts.TOOL,
                category=ToolCategory.ARTEFACT,
                status=ToolStatus.FAILED,
                detail=f"scan failed: {exc.__class__.__name__}",
            )
        )
        db.commit()
        return []
    raw = [
        {"rule_id": h.rule_id, "path": h.path, "size": h.size, "detail": h.detail, "files": h.files}
        for h in scan.hits
    ]
    db.add(
        RawToolOutput(
            analysis_id=analysis.id,
            tool=artefacts.TOOL,
            exit_code=0,
            stderr=None,
            output=json.dumps({"files_seen": scan.files_seen, "hits": raw}).encode("utf-8"),
            truncated=scan.truncated,
        )
    )
    detail = (
        f"stopped after {scan.files_seen} files or {artefacts.MAX_HITS} hits; "
        "the rest of the tree was not checked for artefacts"
        if scan.truncated
        else None
    )
    db.add(
        ToolRun(
            analysis_id=analysis.id,
            tool=artefacts.TOOL,
            category=ToolCategory.ARTEFACT,
            status=ToolStatus.RAN,
            detail=detail,
        )
    )
    db.commit()
    return [artefacts.to_finding(hit) for hit in scan.hits]


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
