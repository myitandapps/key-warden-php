<?php

declare(strict_types=1);

/**
 * Runs every keywarden PHP suite and aggregates the exit codes.
 *
 *   composer test          (or)      php tests/run-all.php
 *
 * Suites:
 *   run-tests.php           legacy surface - validate, verifyToken, trials, seal/unseal
 *   test-grant.php          grant conformance against grant-vectors.json (platform-signed)
 *   test-client-contract.php  what validate() actually puts on the wire, and what it returns
 *   test-no-composer.php    the install that includes the files by hand, with no autoloader
 *
 * grant-vectors.json is minted by the platform's own signGrantToken, not a
 * lookalike, so a drift between SDK and platform fails here rather than in a
 * customer's install. Pass an alternative path as argv[1].
 */

$php = PHP_BINARY;
$dir = __DIR__;
$vectors = $argv[1] ?? ($dir . '/grant-vectors.json');

$suites = [
    ['legacy surface',   $dir . '/run-tests.php',            []],
    ['grant conformance', $dir . '/test-grant.php',           [$vectors]],
    ['client contract',  $dir . '/test-client-contract.php', [$vectors]],
    ['no-composer install', $dir . '/test-no-composer.php',  [$vectors]],
];

$failed = 0;
foreach ($suites as [$label, $script, $args]) {
    if (!is_file($script)) {
        echo "\n== $label == MISSING: $script\n";
        $failed++;
        continue;
    }
    echo "\n== $label ==\n";
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($script);
    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }
    passthru($cmd, $code);
    if ($code !== 0) {
        $failed++;
    }
}

echo "\n" . ($failed === 0 ? "ALL SUITES PASSED\n" : "$failed SUITE(S) FAILED\n");
exit($failed === 0 ? 0 : 1);
