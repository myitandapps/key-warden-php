<?php
/**
 * v1.4.0 conformance - the activation-key + grant model.
 *
 * Driven by grant-vectors.json, minted by the PLATFORM'S own signGrantToken. The
 * Node, Python and .NET SDKs run the same file and must reach the same verdict
 * on every vector, so the four cannot quietly drift apart.
 *
 *   php tests/test-grant.php [path/to/grant-vectors.json]
 */
declare(strict_types=1);
require __DIR__ . '/../src/Grant.php';

$file = $argv[1] ?? __DIR__ . '/grant-vectors.json';
$V = json_decode((string) file_get_contents($file), true);
$pass = 0; $fail = 0;
function ok(bool $c, string $what, $got = null): void {
    global $pass, $fail;
    $c ? $pass++ : $fail++;
    echo '  ' . ($c ? 'ok  ' : 'FAIL') . " $what" . ($got !== null ? " -- $got" : '') . "\n";
}

echo "sdk: grant vectors (signed by the platform)\n";
foreach ($V['vectors'] as $v) {
    $r = KeyWarden\Grant::verify($v['token'], $V['keys'], [
        'activationKey' => $V['activationKey'],
        'machineId'     => $V['machineId'],
        'nonce'         => $v['name'] === 'wrong_nonce' ? $V['nonce'] : '',
    ]);
    ok($r['verdict'] === $v['verdict'], "{$v['name']} -> {$v['verdict']}",
       $r['verdict'] === $v['verdict'] ? $r['reason'] : "got {$r['verdict']}/{$r['reason']}");
}

echo "\nsdk: the claim that is always misread\n";
$good = null;
foreach ($V['vectors'] as $v) { if ($v['name'] === 'valid') { $good = $v; break; } }
$c = KeyWarden\Grant::verify($good['token'], $V['keys'],
    ['activationKey' => $V['activationKey'], 'machineId' => $V['machineId']])['claims'];
$end = KeyWarden\Grant::expiresAt($c);
ok($end !== null && $end - time() > 50 * 86400, 'expires_at is the licence term, ~60 days out');
ok($end > (int) $c['exp'], 'and outlives the grant - reading exp as the term would nag on every rollover');
ok(KeyWarden\Grant::needsRefresh($c) === false, 'a fresh grant does not need refreshing');
ok(KeyWarden\Grant::needsRefresh($c, time() + 20 * 86400) === true, 'but does once exp has passed');

$pv = null;
foreach ($V['vectors'] as $v) { if ($v['name'] === 'perpetual') { $pv = $v; break; } }
$perp = KeyWarden\Grant::verify($pv['token'], $V['keys'],
    ['activationKey' => $V['activationKey'], 'machineId' => $V['machineId']])['claims'];
ok(KeyWarden\Grant::expiresAt($perp) === null, 'a perpetual licence has no end, not an end of zero');
ok(KeyWarden\Grant::inGrace($perp) === false, 'and is never in grace');

$gv = null;
foreach ($V['vectors'] as $v) { if ($v['name'] === 'expired_in_grace') { $gv = $v; break; } }
$gr = KeyWarden\Grant::verify($gv['token'], $V['keys'],
    ['activationKey' => $V['activationKey'], 'machineId' => $V['machineId']])['claims'];
ok(KeyWarden\Grant::inGrace($gr) === true, 'an expired-but-graced licence reports in-grace so the UI can warn');

echo "\nsdk: the 1.3.0 hole\n";
$wrong = KeyWarden\Grant::verify($good['token'], $V['keys'],
    ['activationKey' => 'KW-0000-0000-0000-0000', 'machineId' => $V['machineId']]);
ok($wrong['verdict'] === 'deny' && $wrong['reason'] === 'wrong_key',
   'a grant for a DIFFERENT licence key is refused', $wrong['reason']);

echo "\nsdk: a rotation does not brick the field\n";
$fv = null;
foreach ($V['vectors'] as $v) { if ($v['name'] === 'foreign_signer') { $fv = $v; break; } }
$f = KeyWarden\Grant::verify($fv['token'], $V['keys'],
    ['activationKey' => $V['activationKey'], 'machineId' => $V['machineId']]);
ok($f['verdict'] === 'fallback', 'an unknown kid is fallback, never deny', $f['reason']);
ok(KeyWarden\Grant::verify($good['token'], [],
    ['activationKey' => $V['activationKey'], 'machineId' => $V['machineId']])['reason'] === 'no_keys',
   'a build with no keys baked falls back rather than denying');

echo "\n  $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
