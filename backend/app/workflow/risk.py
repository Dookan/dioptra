"""E4 risk matrix: complexity × findings × criticality, computed on demand.

Deterministic and never stored — the same metrics and verdicts always give
the same ranking, so the developer and the report agree by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.models import SEVERITY_ORDER, Analysis, Severity
from app.analysis.third_party import is_third_party

#: Weight of the worst finding in the function's file; 1 when there is none.
CRITICALITY: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 1,
}
LEVEL_HIGH = 20
LEVEL_MEDIUM = 8
MAX_ROWS = 200


@dataclass(frozen=True)
class RiskRow:
    path: str
    function: str
    line: int | None
    ccn: int
    nloc: int
    findings: int
    max_severity: Severity | None
    score: int
    level: str


def _level(score: int) -> str:
    if score >= LEVEL_HIGH:
        return "high"
    if score >= LEVEL_MEDIUM:
        return "medium"
    return "low"


@dataclass(frozen=True)
class RiskMatrix:
    """What the screen shows, and what it is NOT showing.

    ``total`` is how many functions matched before the cap. The screen has to
    be able to say "200 de 5000": found by the phase-7a walk on a real Laravel
    application, where 5 000 functions were measured and the 200 highest-scoring
    were ALL hand-vendored JavaScript libraries — the developer could not reach
    a single function of their own team's code through the UI, and the cap said
    nothing about it.
    """

    rows: list[RiskRow]
    total: int
    query: str


def risk_matrix(analysis: Analysis, *, q: str | None = None) -> RiskMatrix:
    """Every measured function, the team's own code first, worst first within.

    ``q`` filters on the path and the function name (case-insensitive
    substring) BEFORE the cap, which is what lets a developer reach their own
    code on a tree whose top 200 by score is all dependency noise.

    The first sort key is `is_third_party`, for the same reason the findings
    cap has it: the audited tree chooses how many files it ships and where, so
    a fat dependency directory must not be able to push the team's own work off
    the end of a truncated list. It does NOT catch a library copied in by hand
    (`public/Datatables/…` on the anchor application) — nothing can, from a
    path alone, which is exactly why the count and the filter exist.
    """
    needle = (q or "").strip().lower()
    metrics = analysis.metrics
    if metrics is None:
        return RiskMatrix(rows=[], total=0, query=needle)
    by_path: dict[str, list[Severity]] = {}
    for finding in analysis.findings:
        if finding.in_report:
            by_path.setdefault(finding.path, []).append(finding.severity)
    rows: list[RiskRow] = []
    for entry in metrics.functions:
        path = str(entry.get("path", ""))
        function = str(entry.get("function", ""))
        if needle and needle not in path.lower() and needle not in function.lower():
            continue
        ccn = int(entry.get("ccn", 1) or 1)
        severities = by_path.get(path, [])
        worst = min(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else None
        criticality = CRITICALITY[worst] if worst is not None else 1
        score = ccn * (1 + len(severities)) * criticality
        rows.append(
            RiskRow(
                path=path,
                function=function,
                line=entry.get("line"),
                ccn=ccn,
                nloc=int(entry.get("nloc", 0) or 0),
                findings=len(severities),
                max_severity=worst,
                score=score,
                level=_level(score),
            )
        )
    rows.sort(
        key=lambda r: (
            is_third_party(r.path),
            -r.score,
            r.path,
            r.line if r.line is not None else -1,
            r.function,
        )
    )
    return RiskMatrix(rows=rows[:MAX_ROWS], total=len(rows), query=needle)
