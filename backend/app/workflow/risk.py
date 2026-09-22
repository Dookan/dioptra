"""E4 risk matrix: complexity × findings × criticality, computed on demand.

Deterministic and never stored — the same metrics and verdicts always give
the same ranking, so the developer and the report agree by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.models import SEVERITY_ORDER, Analysis, Severity

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


def risk_matrix(analysis: Analysis) -> list[RiskRow]:
    """Every measured function, worst first. False positives do not count."""
    metrics = analysis.metrics
    if metrics is None:
        return []
    by_path: dict[str, list[Severity]] = {}
    for finding in analysis.findings:
        if finding.in_report:
            by_path.setdefault(finding.path, []).append(finding.severity)
    rows: list[RiskRow] = []
    for entry in metrics.functions:
        path = str(entry.get("path", ""))
        ccn = int(entry.get("ccn", 1) or 1)
        severities = by_path.get(path, [])
        worst = min(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else None
        criticality = CRITICALITY[worst] if worst is not None else 1
        score = ccn * (1 + len(severities)) * criticality
        rows.append(
            RiskRow(
                path=path,
                function=str(entry.get("function", "")),
                line=entry.get("line"),
                ccn=ccn,
                nloc=int(entry.get("nloc", 0) or 0),
                findings=len(severities),
                max_severity=worst,
                score=score,
                level=_level(score),
            )
        )
    rows.sort(key=lambda r: (-r.score, r.path, r.line if r.line is not None else -1, r.function))
    return rows[:MAX_ROWS]
