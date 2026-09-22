#!/bin/sh
# One verification attempt for Python, inside the sandbox container.
#
# The contract with the host is three files in the attempt directory:
# coverage.json, junit.xml and mutation.json. The host reads ONLY those, each
# size-capped, and parses them as data. Keeping the adaptation to every tool's
# own output shape in here means the host never learns a tool's format — and
# mutmut's changes between versions stay a one-file problem.
#
# Nothing is installed and there is no network. $1 is the test file, $2 the
# module under test, both at the root of the attempt directory.
set -eu

TEST_FILE="$1"
MODULE="$2"
OUT="${DIOPTRA_OUT:-/run/attempt}"
# Every artefact is produced on the container's OWN tmpfs and copied into the
# shared mount as the last action, once the runner has exited. The audited
# code executes in here as this same user with $OUT as its working directory,
# so anything written there while it runs is code it can rewrite — an atexit
# hook after pytest has flushed junit.xml, or deleting the coverage data so a
# forged document survives. It can still forge what it writes on its way out
# (docs/threat-model.md → Accepted residual risks), but not silently, and
# never by simply removing a file: an absent document is a REFUSAL upstream,
# never a pass.
WORK=/tmp/dioptra
mkdir -p "$WORK"

export PYTHONDONTWRITEBYTECODE=1
export COVERAGE_FILE="$WORK/.coverage"

# OUR config, never the audited tree's: -c names the ini we wrote and
# -p no:cacheprovider keeps pytest from writing a cache next to the sources.
# A failing test is a RESULT, not an error of the attempt, so failures do not
# abort the script.
coverage run --branch --include="$MODULE" -m pytest \
    -c "$OUT/dioptra.pytest.ini" \
    -p no:cacheprovider \
    --rootdir="$OUT" \
    --junit-xml="$WORK/junit.xml" \
    "$TEST_FILE" >"$WORK/pytest.log" 2>&1 || true

coverage json -o "$WORK/coverage.json" >>"$WORK/pytest.log" 2>&1 || true

# mutmut reads [tool.mutmut] from the pyproject.toml the host wrote; from 3.8
# there is no --paths-to-mutate flag at all. `mutmut results` lists ONLY the
# mutants that were not killed, which is exactly what the gate needs.
mutmut run >"$WORK/mutmut.log" 2>&1 || true
python3 - "$WORK" <<'PY' || true
import json
import pathlib
import re
import subprocess
import sys

out = pathlib.Path(sys.argv[1])
survived: list[dict[str, str]] = []
try:
    listing = subprocess.run(
        ["mutmut", "results"], capture_output=True, text=True, timeout=120, check=False
    ).stdout
except Exception:
    listing = ""
for line in listing.splitlines():
    match = re.match(r"^(?P<name>\S+?):\s*(?P<verdict>[a-z_ ]+)$", line.strip())
    if match is None or match.group("verdict").strip() == "killed":
        continue
    survived.append(
        {"id": match.group("name")[:200], "line": "", "mutant": line.strip()[:400]}
    )

# Best effort only: mutmut prints its totals on a progress line. The gate uses
# the survivor list, which is exact; the counts are for the report.
killed: int | None = None
total: int | None = None
log = (out / "mutmut.log").read_text(encoding="utf-8", errors="replace")
for done, count, wins in re.findall(r"(\d+)/(\d+)\s+\S*\s*(\d+)", log):
    if done == count:
        total, killed = int(count), int(wins)
(out / "mutation.json").write_text(
    json.dumps({"tool": "mutmut", "killed": killed, "total": total, "survived": survived}),
    encoding="utf-8",
)
PY

# Last action, with every runner process finished: hand the three declared
# files over. `cp` never creates what the tools did not produce, and the host
# treats an absent file as a refusal.
for name in coverage.json junit.xml mutation.json; do
    [ -f "$WORK/$name" ] && cp "$WORK/$name" "$OUT/$name"
done
exit 0
