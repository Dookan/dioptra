#!/bin/sh
# One verification attempt for JavaScript / TypeScript, inside the sandbox.
#
# Same contract as run-python.sh: coverage.json, junit.xml and mutation.json in
# the attempt directory, and nothing else read back. The runners live in
# /opt/dioptra-js so the audited tree cannot shadow them with its own
# node_modules, and both are invoked with OUR config file.
set -eu

TEST_FILE="$1"
MODULE="$2"
OUT="${DIOPTRA_OUT:-/run/attempt}"
VITEST="/opt/dioptra-js/node_modules/vitest/vitest.mjs"
STRYKER="/opt/dioptra-js/node_modules/@stryker-mutator/core/bin/stryker.js"
export NODE_PATH=/opt/dioptra-js/node_modules
# See run-python.sh: the artefacts are produced on the container's own tmpfs
# and copied into the shared mount only once the runners have exited.
WORK=/tmp/dioptra
mkdir -p "$WORK"

node "$VITEST" run \
    --root "$OUT" \
    --config "$OUT/dioptra.vitest.config.mjs" \
    --coverage.enabled \
    --coverage.provider=v8 \
    --coverage.reporter=json \
    --coverage.reportsDirectory="$WORK/coverage" \
    --reporter=junit \
    --outputFile="$WORK/junit.xml" \
    >"$WORK/vitest.log" 2>&1 || true

if [ -f "$WORK/coverage/coverage-final.json" ]; then
    cp "$WORK/coverage/coverage-final.json" "$WORK/coverage.json"
fi

node "$STRYKER" run "$OUT/dioptra.stryker.json" >"$WORK/stryker.log" 2>&1 || true
node -e '
const fs = require("node:fs");
const work = process.argv[2];
let killed = 0;
let total = 0;
const survived = [];
try {
  const report = JSON.parse(fs.readFileSync(work + "/reports/mutation.json", "utf8"));
  for (const file of Object.values(report.files ?? {})) {
    for (const mutant of file.mutants ?? []) {
      total += 1;
      if (mutant.status === "Killed" || mutant.status === "CompileError") {
        killed += 1;
      } else if (mutant.status !== "Ignored") {
        survived.push({
          id: String(mutant.id ?? ""),
          line: String(mutant.location?.start?.line ?? ""),
          mutant: `${String(mutant.mutatorName ?? "")}: ${String(mutant.replacement ?? "")}`.slice(0, 400),
        });
      }
    }
  }
} catch { /* no report: the host sees zero killed and an empty survivor list */ }
fs.writeFileSync(process.argv[2] + "/mutation.json", JSON.stringify({ tool: "stryker", killed, total, survived }));
' "$OUT" "$WORK" || true

# Last action, with every runner process finished (see run-python.sh).
for name in coverage.json junit.xml mutation.json; do
    [ -f "$WORK/$name" ] && cp "$WORK/$name" "$OUT/$name"
done
exit 0
