"""Self-audit: run the platform's own repository through its own pipeline.

The plan's last day (docs/development-phases.md, day 20): "the platform is
run through its own analysis, like any other system, and must come out with
no high finding open without justification". This script does the mechanical
part — it archives the committed tree (``git archive HEAD``, so nothing
uncommitted or ignored leaks in), registers it as a project and ingests it
through the SAME service the API uses, with the queue inline so the pipeline
runs here — and prints the findings for the analyst to triage in the UI.

    DIOPTRA_DATABASE_URL=… DIOPTRA_RUNNER_MODE=docker DIOPTRA_QUEUE_INLINE=true \\
      uv run --project backend python scripts/self_audit.py [--actor mmarin]

It never triages anything: the verdicts and their justifications are the
analyst's, written in the Hallazgos screen, and end up in the audit log.
"""

from __future__ import annotations

import argparse
import io
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actor", default="mmarin", help="analyst username that registers the run")
    parser.add_argument("--name", default=None, help="project name (default: dioptra-self-audit-<date>)")
    args = parser.parse_args()

    from sqlalchemy import select

    import app.db.registry  # noqa: F401 — maps every model before the first query
    from app.analysis.models import SEVERITY_ORDER, Analysis, AnalysisStatus, Severity
    from app.auth.models import Role, User
    from app.db.session import get_session_factory
    from app.ingest import service
    from app.projects.models import Project, System

    head = subprocess.run(  # noqa: S603, S607 — fixed argv
        ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    archive = subprocess.run(  # noqa: S603, S607 — fixed argv
        ["git", "-C", str(REPO), "archive", "--format=zip", "HEAD"], capture_output=True, check=True
    ).stdout
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    name = args.name or f"dioptra-self-audit-{stamp}-{head}"

    with get_session_factory()() as db:
        actor = db.scalars(select(User).where(User.username == args.actor)).first()
        if actor is None:
            print(f"no such user: {args.actor} (seed the accounts first)", file=sys.stderr)
            return 2
        if actor.role not in {Role.ANALYST, Role.ADMIN}:
            # The same rule the API enforces: only an analyst or the admin starts an analysis.
            print(f"{args.actor} is a {actor.role.value}; only an analyst or the admin may", file=sys.stderr)
            return 2
        project = db.scalars(select(Project).where(Project.name == name)).first()
        if project is None:
            project = Project(name=name, description=f"Self-audit of Dioptra at {head}")
            project.system = System(name="Dioptra", framework="FastAPI + React", database="PostgreSQL")
            db.add(project)
            db.commit()
        analysis = service.ingest_zip(
            db,
            project=project,
            actor=actor,
            upload=io.BytesIO(archive),
            upload_size=len(archive),
            filename=f"dioptra-{head}.zip",
            source_ip=None,
        )
        db.refresh(analysis)
        row = db.get(Analysis, analysis.id)
        assert row is not None
        print(f"project {project.name} — analysis {row.id}: {row.status.value}")
        if row.status is not AnalysisStatus.DONE:
            print(f"pipeline did not finish: {row.failure_code}", file=sys.stderr)
            return 1
        for run in row.tool_runs:
            print(f"  {run.tool:<16} {run.status.value:<8} {run.detail or ''}")
        counts = Counter(f.severity for f in row.findings)
        print("findings:", ", ".join(f"{level.value}={counts.get(level, 0)}" for level in Severity))
        high = [f for f in row.findings if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[Severity.HIGH]]
        for finding in high:
            print(f"  [{finding.severity.value}] {finding.rule_id} {finding.path}:{finding.line} — {finding.title}")
        print(f"sbom: {row.sbom.component_count if row.sbom else 'none'} components")
        print("triage the high findings in the Hallazgos screen; every verdict needs a written reason.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
