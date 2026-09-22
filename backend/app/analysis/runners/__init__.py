"""Tool runners: one spec per tool, executed offline in an ephemeral container.

Public surface used by the pipeline:

- :mod:`app.analysis.runners.base` — ``RunnerSpec``, ``ExecutionResult``,
  the ``Executor`` and ``Runner`` protocols;
- :mod:`app.analysis.runners.executor` — ``DockerExecutor`` (production),
  ``LocalExecutor`` (development, tests) and ``build_executor``;
- :mod:`app.analysis.runners.tools` — the concrete runners and
  ``default_runners()``.
"""

from app.analysis.runners.base import ExecutionResult, Executor, Runner, RunnerSpec
from app.analysis.runners.executor import DockerExecutor, LocalExecutor, build_executor
from app.analysis.runners.tools import default_runners

__all__ = [
    "DockerExecutor",
    "ExecutionResult",
    "Executor",
    "LocalExecutor",
    "Runner",
    "RunnerSpec",
    "build_executor",
    "default_runners",
]
