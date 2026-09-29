"""The socket-holding worker has a memory cap sized to what it parses (1.6.1).

It reads each tool's report in memory and a parsed SARIF takes about six
times its size (26 MiB peaked at 158 MiB, `tasks/hardening-1.5.1.md`), so at
the default parse cap it can reach ~1.5 GiB. Without a cap a hostile tree
could take the host's memory; with one set too low, a legitimate large tree
would kill the worker. Both edges are pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import Settings

REPO = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
#: Measured parse overhead (×6) plus the Python process and RQ.
PARSE_FACTOR = 6
BASELINE = 512 * MIB


def _service(name: str) -> str:
    """The text of one top-level service block (two-space indent) of the Compose file."""
    text = (REPO / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    pattern = rf"^  {re.escape(name)}:\n(.*?)(?=^  [a-z-]+:\n|^[a-z]|\Z)"
    match = re.search(pattern, text, re.M | re.S)
    assert match is not None, f"no service {name}"
    return match.group(1)


def _setting(block: str, key: str) -> str | None:
    match = re.search(rf"^    {key}: (.+)$", block, re.M)
    return match.group(1).strip() if match else None


def _default_bytes(value: object) -> int:
    match = re.fullmatch(r"\$\{DIOPTRA_WORKER_MEMORY:-(\d+)([mg])\}", str(value))
    assert match is not None, f"not an overridable default: {value!r}"
    number, unit = int(match.group(1)), match.group(2)
    return number * (1024 if unit == "g" else 1) * MIB


def test_the_worker_has_a_memory_cap_and_no_swap_beyond_it() -> None:
    worker = _service("worker")
    assert _setting(worker, "mem_limit") is not None
    assert _setting(worker, "mem_limit") == _setting(worker, "memswap_limit")
    _default_bytes(_setting(worker, "mem_limit"))


def test_the_cap_covers_a_whole_parse_at_the_default_parse_cap() -> None:
    parse_cap = Settings.model_fields["max_tool_parse_bytes"].default
    assert isinstance(parse_cap, int)
    limit = _setting(_service("worker"), "mem_limit")
    assert _default_bytes(limit) >= parse_cap * PARSE_FACTOR + BASELINE


def test_only_the_worker_is_capped_here() -> None:
    """Every other service keeps its own sizing: a cap there needs its own measurement."""
    text = (REPO / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    services = re.findall(r"^  ([a-z-]+):\n", text.split("\nvolumes:")[0], re.M)
    assert "worker" in services
    assert "report-worker" in services
    capped = [name for name in services if _setting(_service(name), "mem_limit") is not None]
    assert capped == ["worker"]
