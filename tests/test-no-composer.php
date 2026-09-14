<?php

declare(strict_types=1);

/**
 * The install that does NOT use Composer.
 *
 * Composer's PSR-4 autoloader resolves KeyWarden\Grant on its own, so every other
 * suite here loads it without noticing. A WordPress plugin that just includes the
 * two files it knows about gets no autoloader - and before v1.5.0, passing a key
 * set to validate() fatalled on a missing class instead of verifying anything.
 *
 * This runs in its own process and requires ONLY the client, deliberately.
 *
 *   php tests/test-no-composer.php [path/to/grant-vectors.json]
 */

require __DIR__ . '/../src/KeyWardenError.php';
require __DIR__ . '/../src/KeyWardenClient.php';

$PASS = 0;
$FAIL = 0;
function ok(bool $c, string $what, ?string $got = null): void
{
    global $PASS, $FAIL;
    if ($c) { $PASS++; } else { $FAIL++; }
    echo '  ' . ($c ? 'ok  ' : 'FAIL') . " $what" . ($got !== null ? " -- $got" : '') . "\n";
}

$path = $argv[1] ?? (__DIR__ . '/grant-vectors.json');
$V = json_decode(file_get_contents($path), true);
$token = null;
foreach ($V['vectors'] as $v) {
    if ($v['name'] === 'valid') { $token = $v['token']; }
}

echo "php client: an install with no Composer autoloader\n";
ok(!class_exists('KeyWarden\Grant', false), 'Grant is NOT loaded by requiring the client alone');

$res = KeyWarden\KeyWardenClient::validate($V['activationKey'], [
    'apimKey' => 'AK', 'clientKey' => 'CK', 'machineId' => $V['machineId'],
    'keys' => $V['keys'],
    'transport' => function (array $req) use ($token): array {
        return ['status' => 200, 'body' => json_encode(['valid' => true, 'token' => $token])];
    },
]);

ok(class_exists('KeyWarden\Grant', false), 'validate() pulls it in on demand rather than fatalling');
ok(isset($res['grantVerdict']), 'and a verdict is actually produced', $res['grantVerdict'] ?? '(none)');
ok(($res['valid'] ?? null) === true, 'the licence verdict is untouched by grant verification');

echo "\n  $PASS passed, $FAIL failed\n";
exit($FAIL === 0 ? 0 : 1);
