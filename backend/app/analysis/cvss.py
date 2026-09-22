"""CVSS 3.1 base score, computed from the vector string.

Own implementation (no dependency): the formula is fixed by the specification
and a score must be reproducible from the vector alone, so the report can be
explained finding by finding.
"""

from __future__ import annotations

import math
import re

from app.analysis.models import Severity

_PREFIX = re.compile(r"^CVSS:3\.[01]/")

_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}
_SCOPE = {"U", "C"}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _round_up(value: float) -> float:
    """Round up to one decimal exactly as CVSS 3.1 Appendix A prescribes."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (math.floor(scaled / 10_000) + 1) / 10


def parse_vector(vector: str) -> dict[str, str]:
    """Split a base vector into its metrics. Raises ``ValueError`` when malformed."""
    text = vector.strip()
    if not _PREFIX.match(text):
        message = "not a CVSS 3.x vector"
        raise ValueError(message)
    metrics: dict[str, str] = {}
    for part in _PREFIX.sub("", text).split("/"):
        if ":" not in part:
            message = f"malformed metric {part!r}"
            raise ValueError(message)
        key, _, value = part.partition(":")
        if key in metrics:
            message = f"duplicate metric {key}"
            raise ValueError(message)
        metrics[key] = value
    missing = [key for key in _REQUIRED if key not in metrics]
    if missing:
        message = f"missing base metrics: {', '.join(missing)}"
        raise ValueError(message)
    return metrics


def base_score(vector: str) -> float:
    """CVSS 3.1 base score (0.0–10.0) for a ``CVSS:3.1/...`` vector."""
    metrics = parse_vector(vector)
    try:
        changed = metrics["S"] == "C"
        if metrics["S"] not in _SCOPE:
            raise KeyError(metrics["S"])
        privileges = (_PRIVILEGES_CHANGED if changed else _PRIVILEGES_UNCHANGED)[metrics["PR"]]
        exploitability = (
            8.22
            * _ATTACK_VECTOR[metrics["AV"]]
            * _ATTACK_COMPLEXITY[metrics["AC"]]
            * privileges
            * _USER_INTERACTION[metrics["UI"]]
        )
        iss = 1 - (1 - _IMPACT[metrics["C"]]) * (1 - _IMPACT[metrics["I"]]) * (
            1 - _IMPACT[metrics["A"]]
        )
    except KeyError as error:
        message = f"invalid metric value: {error}"
        raise ValueError(message) from error

    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    if changed:
        return _round_up(min(1.08 * (impact + exploitability), 10))
    return _round_up(min(impact + exploitability, 10))


def severity_for_score(score: float) -> Severity:
    """CVSS 3.1 qualitative rating."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


def severity_for_level(level: str | None) -> Severity:
    """Severity from a SARIF ``level`` when the tool gives no vector."""
    match (level or "").strip().lower():
        case "error":
            return Severity.HIGH
        case "warning":
            return Severity.MEDIUM
        case "note":
            return Severity.LOW
        case _:
            return Severity.INFO
