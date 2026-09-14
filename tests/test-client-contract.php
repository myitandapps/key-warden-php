<?php
declare(strict_types=1);
/**
 * v1.5.0 - what the PHP client DECLARES and what it TRUSTS.
 *
 * Until v1.5.0 the PHP client sent no nonce, no env type, and never verified the
 * grant it received: Grant.php shipped in 1.4.0 as a standalone verifier that
 * nothing called. The practical consequences were a captured answer being
 * replayable, and every PHP install - staging included - counted against the
 * PRODUCTION seat pool. These tests pin all three so it cannot regress.
 */
require __DIR__ . '/../src/KeyWardenError.php';
require __DIR__ . '/../src/Grant.php';
require __DIR__ . '/../src/KeyWardenClient.php';

use KeyWarden\KeyWardenClient;

$pass = 0; $fail = 0;
function ok(bool $c, string $what, $got = null) {
    global $pass, $fail;
    $c ? $pass++ : $fail++;
    echo '  ', $c ? 'ok  ' : 'FAIL', ' ', $what, $got !== null ? ' -- ' . $got : '', PHP_EOL;
}

$V = json_decode(file_get_contents(__DIR__ . '/grant-vectors.json'), true);
$good = null; $foreign = null;
foreach ($V['vectors'] as $v) {
    if ($v['name'] === 'valid') $good = $v['token'];
    if ($v['name'] === 'foreign_signer') $foreign = $v['token'];
}

echo "php client: validate() declares what the platform needs", PHP_EOL;
$sent = null;
$transport = function (array $req) use (&$sent) {
    $sent = $req;
    return ['status' => 200, 'body' => json_encode(['valid' => true, 'plan' => 'acme-pro', 'seats' => 5])];
};
$res = KeyWardenClient::validate($V['activationKey'], [
    'apimKey' => 'AK', 'clientKey' => 'CK', 'machineId' => $V['machineId'],
    'product' => 'acme-maps', 'userCount' => 40, 'transport' => $transport,
]);
ok(!empty($sent['headers']['X-Kw-Nonce']), 'a fresh nonce per call');
ok(in_array($sent['headers']['X-Kw-Env-Type'] ?? '', ['production', 'non-production'], true),
   'the env type - undeclared, a staging box burns a production seat', $sent['headers']['X-Kw-Env-Type'] ?? '(none)');
ok(($sent['headers']['X-Machine-Id'] ?? '') === $V['machineId'], 'the machine id');
$body = json_decode($sent['body'], true);
ok(($body['product'] ?? '') === 'acme-maps', 'the product code');
ok(($body['userCount'] ?? 0) === 40, 'the declared user count, for banded plans');
ok(($res['valid'] ?? null) === true, 'and the verdict comes back');

echo PHP_EOL, "php client: two nonces are never the same", PHP_EOL;
$n1 = $sent['headers']['X-Kw-Nonce'];
KeyWardenClient::validate($V['activationKey'], ['apimKey'=>'AK','clientKey'=>'CK','transport'=>$transport]);
ok($sent['headers']['X-Kw-Nonce'] !== $n1, 'a second call carries a different nonce');
ok(strlen($n1) >= 32, 'and it is long enough to be unguessable', (string) strlen($n1));

echo PHP_EOL, "php client: env type is conservative", PHP_EOL;
putenv('KW_ENV_TYPE=staging');
KeyWardenClient::validate($V['activationKey'], ['apimKey'=>'AK','clientKey'=>'CK','transport'=>$transport]);
ok($sent['headers']['X-Kw-Env-Type'] === 'non-production', 'KW_ENV_TYPE=staging -> non-production');
putenv('KW_ENV_TYPE=banana');
KeyWardenClient::validate($V['activationKey'], ['apimKey'=>'AK','clientKey'=>'CK','transport'=>$transport]);
ok($sent['headers']['X-Kw-Env-Type'] === 'production',
   'an unrecognised label reads as PRODUCTION - a site can never talk itself into the cheaper pool');
putenv('KW_ENV_TYPE');
KeyWardenClient::validate($V['activationKey'], ['apimKey'=>'AK','clientKey'=>'CK','envType'=>'non-production','transport'=>$transport]);
ok($sent['headers']['X-Kw-Env-Type'] === 'non-production', 'an explicit option wins');

echo PHP_EOL, "php client: the grant is verified BEFORE the caller sees it", PHP_EOL;
$replay = function (array $req) use ($good) {
    // Answer with a grant minted for a DIFFERENT nonce - i.e. a replay.
    return ['status' => 200, 'body' => json_encode(['valid' => true, 'token' => $good])];
};
$r2 = KeyWardenClient::validate($V['activationKey'], [
    'apimKey' => 'AK', 'clientKey' => 'CK', 'machineId' => $V['machineId'],
    'keys' => $V['keys'], 'transport' => $replay,
]);
ok(($r2['grantVerdict'] ?? '') === 'deny' && ($r2['grantReason'] ?? '') === 'replayed',
   'a grant echoing somebody else\'s nonce is denied', ($r2['grantVerdict'] ?? '?') . '/' . ($r2['grantReason'] ?? '?'));
ok(($r2['trustworthy'] ?? null) === false, 'and is flagged untrustworthy rather than silently accepted');
ok(($r2['valid'] ?? null) === true,
   'while the online verdict is left alone - a verification fault must not downgrade a paying licence');

echo PHP_EOL, "php client: a rotation does not brick the field", PHP_EOL;
$rot = function (array $req) use ($foreign) {
    return ['status' => 200, 'body' => json_encode(['valid' => true, 'token' => $foreign])];
};
$r3 = KeyWardenClient::validate($V['activationKey'], [
    'apimKey' => 'AK', 'clientKey' => 'CK', 'machineId' => $V['machineId'],
    'keys' => $V['keys'], 'transport' => $rot,
]);
ok(($r3['grantVerdict'] ?? '') === 'fallback', 'an unknown kid is fallback, never deny', $r3['grantReason'] ?? '?');
ok(!isset($r3['trustworthy']), 'and is NOT flagged untrustworthy - we simply cannot judge it');

echo PHP_EOL, "php client: no keys supplied -> no grant fields invented", PHP_EOL;
$plain = function (array $req) use ($good) {
    return ['status' => 200, 'body' => json_encode(['valid' => true, 'token' => $good])];
};
$r4 = KeyWardenClient::validate($V['activationKey'], ['apimKey'=>'AK','clientKey'=>'CK','transport'=>$plain]);
ok(!isset($r4['grantVerdict']), 'grantVerdict is absent when the caller baked no keys');
ok(($r4['token'] ?? '') !== '', 'but the token is still handed back for later verification');

echo PHP_EOL, ($fail === 0 ? "  $pass passed, 0 failed" : "  $pass passed, $fail FAILED"), PHP_EOL;
exit($fail === 0 ? 0 : 1);
