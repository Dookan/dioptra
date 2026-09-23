<?php
/**
 * Build /opt/dioptra-php/licenses.json from what the image ACTUALLY ships.
 *
 * The wave-1 sandbox image is licence-gated by walking the 230 real packages
 * installed inside it. This image installs phars, which appear in no lockfile
 * of the repository, and the first version of this manifest was four lines
 * written by hand — so `phpunit.phar` and `infection.phar` each embedded
 * dozens of components (`sebastian/*`, `nikic/php-parser`, `symfony/*`,
 * `composer/*`) that the gate never saw, and bumping a version changed no
 * licence claim. Named by the precommit security auditor, 2026-09-23.
 *
 * Neither phar carries a phar.io `manifest.xml` or a composer `installed.json`
 * (checked inside the built image), so the component list is taken from the
 * per-component LICENSE files the phars DO carry, and each one is classified
 * from its own text. A text this script cannot classify is a BUILD FAILURE,
 * never an assumed licence: fail closed is the whole point of a gate.
 */
declare(strict_types=1);

/**
 * Every family whose signature the text carries — ALL of them, not the first.
 *
 * Returning on the first match would mislabel a text that quotes a permissive
 * licence inside a non-free one, which is the shape a gate must not be fooled
 * by. Measured on the built image at the time this was written: 60 licence
 * files, none matching more than one family. So ambiguity costs nothing today
 * and fails closed the day it appears.
 *
 * @return list<string>
 */
function classify(string $text): array
{
    $flat = preg_replace('/\s+/', ' ', $text) ?? '';
    $families = [];
    if (
        stripos($flat, 'BSD 3-Clause License') !== false
        || (
            stripos($flat, 'Redistribution and use in source and binary forms') !== false
            && stripos($flat, 'Neither the name of') !== false
        )
    ) {
        $families[] = 'BSD-3-Clause';
    }
    if (stripos($flat, 'Apache License') !== false && stripos($flat, 'Version 2.0') !== false) {
        $families[] = 'Apache-2.0';
    }
    if (
        stripos($flat, 'Permission is hereby granted, free of charge') !== false
        && stripos($flat, 'THE SOFTWARE IS PROVIDED') !== false
    ) {
        $families[] = 'MIT';
    }
    if (stripos($flat, 'GNU LESSER GENERAL PUBLIC LICENSE') !== false) {
        $families[] = 'LGPL-3.0';
    } elseif (stripos($flat, 'GNU GENERAL PUBLIC LICENSE') !== false) {
        $families[] = 'GPL-3.0';
    }
    return $families;
}

/** Component name from the path of its LICENSE file, e.g. `vendor/psr/clock/LICENSE`. */
function componentName(string $phar, string $relative): string
{
    $parts = array_values(array_filter(explode('/', dirname($relative)), static function (string $p): bool {
        return $p !== '' && $p !== '.' && $p !== 'vendor' && $p !== '.box';
    }));
    return $phar . '/' . (count($parts) === 0 ? 'bundle' : implode('/', $parts));
}

/**
 * Everything above is pure and importable; everything below RUNS.
 *
 * The split is not decoration: a script whose work happens at include time
 * cannot be tested without doing that work, and `classify` is the function
 * the licence gate's verdict actually rests on. Guarding the entry point is
 * the PHP equivalent of Python's `if __name__ == "__main__"`, and it is what
 * lets Dioptra's E6/E7 run against this file at all (phase 7a walk).
 */
function main(): int
{
    $packages = [];
    $unclassified = [];

    foreach (['phpunit', 'infection'] as $tool) {
        $path = "/opt/dioptra-php/{$tool}.phar";
        $prefix = "phar://{$path}/";
        foreach (new RecursiveIteratorIterator(new Phar($path)) as $file) {
            $relative = str_replace($prefix, '', $file->getPathname());
            // An unknown licence TEXT failed the build while an unknown licence
            // FILE NAME was silently skipped — two ways of not knowing, one of
            // them invisible. `COPYING` and `LICENSE.rst` now come in too, so both
            // fail the same way.
            if (preg_match('#(^|/)(LICEN[SC]E|COPYING)(\.(md|txt|rst))?$#i', $relative) !== 1) {
                continue;
            }
            $text = file_get_contents($file->getPathname());
            if ($text === false) {
                $unclassified[] = "{$tool}:{$relative} (unreadable)";
                continue;
            }
            $families = classify($text);
            if (count($families) !== 1) {
                $unclassified[] = sprintf(
                    '%s:%s (%s)',
                    $tool,
                    $relative,
                    $families === [] ? 'unrecognised' : 'ambiguous: ' . implode(', ', $families),
                );
                continue;
            }
            $packages[] = [
                'name' => componentName($tool, $relative),
                // The phars do not carry a per-component version, so the version of
                // the artefact that bundles it is the honest answer.
                'version' => getenv(strtoupper($tool) . '_VERSION') ?: 'bundled',
                'license' => $families[0],
            ];
        }
    }

    if ($unclassified !== []) {
        fwrite(STDERR, "licence text not recognised, refusing to write a manifest:\n");
        foreach ($unclassified as $item) {
            fwrite(STDERR, "  - {$item}\n");
        }
        exit(1);
    }

    // The four top-level artefacts stay named explicitly: php and xdebug ship no
    // LICENSE file inside a phar, and phpunit/infection are the bundles themselves.
    array_unshift(
        $packages,
        ['name' => 'php', 'version' => getenv('PHP_VERSION') ?: '8.3', 'license' => 'PHP-3.01'],
        ['name' => 'phpunit', 'version' => getenv('PHPUNIT_VERSION') ?: 'unknown', 'license' => 'BSD-3-Clause'],
        ['name' => 'infection', 'version' => getenv('INFECTION_VERSION') ?: 'unknown', 'license' => 'BSD-3-Clause'],
        ['name' => 'xdebug', 'version' => getenv('XDEBUG_VERSION') ?: 'unknown', 'license' => 'Xdebug-1.03'],
    );

    usort($packages, static fn(array $a, array $b): int => strcmp($a['name'], $b['name']));

    $document = ['runtime' => 'php', 'packages' => $packages];
    $json = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        fwrite(STDERR, "could not encode the manifest\n");
        exit(1);
    }
    file_put_contents('/opt/dioptra-php/licenses.json', $json . "\n");
    fwrite(STDERR, sprintf("wrote %d packages\n", count($packages)));
    return 0;
}

// Only when this file is the program, never when a test requires it.
if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    exit(main());
}
