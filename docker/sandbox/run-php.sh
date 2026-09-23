#!/bin/sh
# One verification attempt for PHP, inside the sandbox container.
#
# The contract with the host is three files in the attempt directory:
# coverage.json, junit.xml and mutation.json. The host reads ONLY those, each
# size-capped, and parses them as data. Keeping the adaptation to every tool's
# own output shape in here means the host never learns a tool's format — so a
# PHPUnit or Infection version change stays a one-file problem, exactly as
# mutmut's 3.3 → 3.8 change did for Python (tasks/phase4-e6-e7.md, day 17c).
#
# PHPUnit's native coverage is Clover XML. It is converted HERE, by PHP
# itself, into the neutral shape `app/sandbox/results.py::_dioptra_coverage`
# reads — which also keeps an XML parser out of the API process.
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
# so anything written there while it runs is code it can rewrite (see
# run-python.sh, and docs/threat-model.md → Accepted residual risks).
WORK=/tmp/dioptra
mkdir -p "$WORK"

INFECTION="php /opt/dioptra-php/infection.phar"

# OUR config, never the audited tree's: -c names the XML the host wrote, and
# the tree's own phpunit.xml / phpunit.xml.dist / composer.json are never
# copied into the attempt directory in the first place (workspace.py).
#
# The run goes through OUR harness rather than the phar's CLI, because the
# coverage PHPUnit reports does not carry branch sides and the E4 criterion
# needs them — see docker/sandbox/php-harness.php for the measurement that
# settled it. A failing test is a RESULT, not an error of the attempt, so
# failures do not abort the script.
php /opt/dioptra-php/harness.php \
    "$MODULE" \
    "$OUT/phpunit.xml" \
    "$WORK/coverage.json" \
    "$WORK/junit.xml" \
    >"$WORK/phpunit.log" 2>&1 || true

# Infection mutates ONLY the module under test; the host wrote the config and
# the test file is excluded there, so a mutant is never planted in the
# developer's own test. `--no-progress` keeps the log a log.
$INFECTION \
    --configuration="$OUT/dioptra.infection.json" \
    --no-progress \
    --no-interaction \
    --show-mutations \
    --threads=1 \
    >"$WORK/infection.log" 2>&1 || true

# Infection's JSON log → the neutral mutation shape the host has read since
# P4. Every survivor carries its diff, which is what lets the developer JUDGE
# it (kill it, or excuse it as equivalent with a written reason).
php -r '
$work = $argv[1];
$killed = null; $total = null; $survived = [];
$log = $work . "/infection.json";
// No log at all means Infection did not finish — the audited class could not
// be loaded, the initial suite refused to run, the tool crashed. Writing a
// document with null counts would let the host score "no survivor", so we
// write NOTHING and let the host treat the absent file as a refusal
// (app/sandbox/executor.py → SandboxResult.missing).
if (!is_file($log)) { exit(0); }
if (is_file($log)) {
    $report = json_decode((string) file_get_contents($log), true);
    if (is_array($report)) {
        $stats = $report["stats"] ?? [];
        $killedCount = $stats["killedCount"] ?? null;
        $totalCount = $stats["totalMutantsCount"] ?? null;
        $killed = is_int($killedCount) ? $killedCount : null;
        $total = is_int($totalCount) ? $totalCount : null;
        // Everything that is not killed is a survivor for the gate: escaped,
        // and the ones the tooling could not decide. Ignored mutants are the
        // ones Infection was told to skip, so they are not survivors.
        // Infection names the bucket "uncovered", not "notCovered" — reading
        // the wrong key silently drops every survivor no test reached, which
        // is exactly the kind of "measured nothing, reported a pass" the E7
        // rules refuse (docs/workflow-gates.md). A timed-out mutant is NOT a
        // survivor: Infection counts it as killed, and so do we.
        foreach (["escaped", "uncovered"] as $bucket) {
            foreach (($report[$bucket] ?? []) as $index => $mutant) {
                if (count($survived) >= 200) { break 2; }
                $mutator = $mutant["mutator"] ?? [];
                $diff = (string) ($mutant["diff"] ?? "");
                $lines = [];
                foreach (explode("\n", $diff) as $row) {
                    $head = substr($row, 0, 1);
                    if (($head === "+" || $head === "-")
                        && substr($row, 0, 3) !== "+++" && substr($row, 0, 3) !== "---") {
                        $lines[] = trim(preg_replace("/\s+/", " ", $row));
                    }
                }
                $survived[] = [
                    "id" => substr((string) ($mutator["mutatorName"] ?? $bucket) . "#" . $index, 0, 200),
                    "line" => (string) ($mutator["originalStartLine"] ?? ""),
                    "mutant" => substr(implode(" ", $lines), 0, 400),
                ];
            }
        }
    }
}
// A log we could not READ is not a measurement either. Infection puts the
// counts and the survivor buckets in the SAME document, so `total === null`
// means the whole thing was unread — unlike mutmut, whose counts are best
// effort while its survivor list is exact. Writing a document here would let
// the host score an empty survivor list as "nothing survived"; writing
// nothing routes through SandboxResult.missing to ERRORED, which is the rule.
if (!is_int($total)) { exit(0); }
file_put_contents($work . "/mutation.json", json_encode([
    "tool" => "infection",
    "killed" => $killed,
    "total" => $total,
    "survived" => $survived,
]));
' "$WORK" || true

# Last action, with every runner process finished: hand the three declared
# files over. `cp` never creates what the tools did not produce, and the host
# treats an absent file as a refusal, never as a pass.
for name in coverage.json junit.xml mutation.json; do
    [ -f "$WORK/$name" ] && cp "$WORK/$name" "$OUT/$name"
done
exit 0
