<?php
/**
 * One PHPUnit run under Xdebug's own branch collector.
 *
 * WHY THIS EXISTS, and why it is not `phpunit --coverage-clover`: PHPUnit's
 * Clover and Cobertura reports carry LINE counts only — measured on this image
 * on 2026-09-23, both produced zero branch data for a module with three `if`s.
 * pcov cannot help either: it is a line profiler by design. The E4 coverage
 * criterion defaults to 100 % DECISIONS and every brief branch item is checked
 * side by side ("a half-taken branch covers neither side"), so line counts are
 * not enough. Xdebug's raw `xdebug_get_code_coverage()` with
 * XDEBUG_CC_BRANCH_CHECK does carry every branch with its `out` / `out_hit`
 * arrays, so the collector is started here, around PHPUnit's own run.
 *
 * It lives in the IMAGE (/opt/dioptra-php), never in the attempt directory:
 * the audited code can write to that directory and must not be able to
 * replace the thing that measures it.
 *
 * argv: 1 module under test, 2 PHPUnit config, 3 coverage out, 4 junit out.
 */
$module = realpath($argv[1]);
$config = $argv[2];
$coverageOut = $argv[3];
$junitOut = $argv[4];

// Registered BEFORE PHPUnit runs, because PHPUnit ends the process itself.
register_shutdown_function(static function () use ($module, $coverageOut): void {
    $raw = @xdebug_get_code_coverage();
    $info = (is_array($raw) && $module !== false) ? ($raw[$module] ?? null) : null;
    $executed = [];
    $missing = [];
    $partial = [];
    $total = 0;
    $covered = 0;
    if (is_array($info)) {
        foreach (($info['lines'] ?? []) as $line => $state) {
            // 1 executed, -1 not executed, -2 dead code (not executable).
            if ($state === 1) {
                $executed[(int) $line] = true;
            } elseif ($state === -1) {
                $missing[(int) $line] = true;
            }
        }
        foreach (($info['functions'] ?? []) as $name => $function) {
            if ($name === '{main}' || !is_array($function)) {
                continue;
            }
            foreach (($function['branches'] ?? []) as $branch) {
                $outs = array_values($branch['out'] ?? []);
                $hits = array_values($branch['out_hit'] ?? []);
                // One exit is a straight line, not a decision.
                if (count($outs) < 2) {
                    continue;
                }
                $line = (int) ($branch['line_end'] ?? 0);
                $taken = 0;
                foreach ($outs as $index => $_) {
                    if ((int) ($hits[$index] ?? 0) > 0) {
                        $taken++;
                    }
                }
                $total += count($outs);
                $covered += $taken;
                if ($taken < count($outs) && $line > 0) {
                    $partial[$line] = true;
                }
            }
        }
    }
    $executedLines = array_keys($executed);
    sort($executedLines);
    $missingLines = array_values(array_diff(array_keys($missing), $executedLines));
    sort($missingLines);
    $partialLines = array_keys($partial);
    sort($partialLines);
    @file_put_contents($coverageOut, json_encode([
        'executed_lines' => $executedLines,
        'missing_lines' => $missingLines,
        'partial_branch_lines' => $partialLines,
        'total_branches' => $total,
        'covered_branches' => $covered,
    ]));
});

xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK);

require 'phar:///opt/dioptra-php/phpunit.phar';

// Through the Application class, not the phar's CLI stub: requiring the phar
// only loads its classes, it does not run the suite (measured, same day).
(new PHPUnit\TextUI\Application())->run([
    'phpunit',
    '-c',
    $config,
    '--do-not-cache-result',
    '--log-junit',
    $junitOut,
]);
