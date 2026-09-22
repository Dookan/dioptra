"""Real function copied verbatim from app/workflow/risk.py (2026-09-22).

Hand-counted in tests/test_brief.py; do not edit — the numbers there depend on these lines.
"""


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
