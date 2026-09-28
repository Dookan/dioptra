"""Where a running analysis is, in steps the screen can name (phase 10).

The pipeline is a fixed sequence: acquire the tree (extract the ZIP or clone),
run each tool in ``default_runners()`` order, then normalise and store. The
worker writes the step it is ENTERING to ``Analysis.current_step`` and commits,
so a poll sees it. Steps are not of equal length — Semgrep was 368 of the 499 s
on the phase-10 walk — so the screen names the step and shows the elapsed
time; the bar counts steps done, never claims a percentage of time.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analysis.models import Analysis, AnalysisStatus
from app.analysis.runners import default_runners

ACQUIRE = "acquire"
NORMALIZE = "normalize"


def pipeline_steps() -> tuple[str, ...]:
    return (ACQUIRE, *(runner.name for runner in default_runners()), NORMALIZE)


@dataclass(frozen=True)
class Progress:
    step: str
    #: 1-based position of ``step``.
    index: int
    total: int


def progress_of(analysis: Analysis) -> Progress | None:
    """The step of a RUNNING analysis, or None (queued, finished, or unknown step)."""
    if analysis.status is not AnalysisStatus.RUNNING or analysis.current_step is None:
        return None
    steps = pipeline_steps()
    if analysis.current_step not in steps:
        return None
    return Progress(
        step=analysis.current_step,
        index=steps.index(analysis.current_step) + 1,
        total=len(steps),
    )
