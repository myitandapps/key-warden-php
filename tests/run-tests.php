<?php

declare(strict_types=1);

/**
 * keywarden PHP tests. Zero network: online calls use an injected transport, and
 * the offline tests mint tokens with a throwaway key EXACTLY the way the platform
 * signs them (header.body over Ed25519, via sodium), so a drift in the token
 * format breaks a test here rather than a customer's install.
 *
 * Run:  php tests/run-tests.php   ->  "16 passed, 0 failed"
 */

require __DIR__ . '/../src/KeyWardenError.php';
require __DIR__ . '/../src/KeyWardenClient.php';

use KeyWarden\KeyWardenClient;
use KeyWarden\KeyWardenError;

function b64url(string $b): string
{
    return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
}

/** Sign a token the way the platform does: over "header.body". */
function mint(array $payload): array
{
    $kp = sodium_crypto_sign_keypair();
    $sk = sodium_crypto_sign_secretkey($kp);
    $pk = sodium_crypto_sign_publickey($kp);
    $header = b64url(json_encode(['alg' => 'EdDSA', 'typ' => 'KWT']));
    $body = b64url(json_encode($payload));
    $sig = b64url(sodium_crypto_sign_detached("$header.$body", $sk));
    return ["$header.$body.$sig", base64_encode($pk), $sk, $pk];
}

/** A deterministic fake transport: returns a preset status+body, captures the request. */
function transportReturning(int $status, ?array $body, ?array &$capture = null): callable
{
    return function (array $req) use ($status, $body, &$capture): array {
        if ($capture !== null) {
            $capture['url'] = $req['url'];
            $capture['headers'] = $req['headers'];
            $capture['body'] = json_decode($req['body'], true);
        }
        return ['status' => $status, 'body' => $body === null ? null : json_encode($body)];
    };
}

$PASS = 0;
$FAIL = 0;
function check(string $name, callable $fn): void
{
    global $PASS, $FAIL;
    try {
        $fn();
        $PASS++;
        echo "  ok   $name\n";
    } catch (\Throwable $e) {
        $FAIL++;
        echo "  FAIL $name\n       " . $e->getMessage() . "\n";
    }
}

function assertTrue($cond, string $msg): void
{
    if (!$cond) {
        throw new \Exception($msg);
    }
}

$now = time();

echo "\nkeywarden(php): offline verifyToken\n";

check('a valid, correctly signed token verifies', function () use ($now) {
    [$token, $pub] = mint(['valid' => true, 'plan' => 'pro', 'exp' => $now + 3600]);
    $r = KeyWardenClient::verifyToken($token, $pub);
    assertTrue($r['valid'] === true && $r['claims']['plan'] === 'pro', 'expected valid pro token');
});

check('the signature covers header.body, not the payload alone', function () use ($now) {
    // The docs bug: signing the payload alone must FAIL here.
    $kp = sodium_crypto_sign_keypair();
    $sk = sodium_crypto_sign_secretkey($kp);
    $pk = sodium_crypto_sign_publickey($kp);
    $header = b64url(json_encode(['alg' => 'EdDSA', 'typ' => 'KWT']));
    $body = b64url(json_encode(['valid' => true, 'exp' => $now + 3600]));
    $wrong = b64url(sodium_crypto_sign_detached($body, $sk)); // payload only - WRONG
    $r = KeyWardenClient::verifyToken("$header.$body.$wrong", base64_encode($pk));
    assertTrue($r['valid'] === false, 'payload-only signature must NOT verify');
});

check('a tampered payload is rejected as bad_signature', function () use ($now) {
    [$token, $pub] = mint(['valid' => true, 'seats' => 5, 'exp' => $now + 3600]);
    [$h, $b, $s] = explode('.', $token);
    $b2 = b64url(json_encode(['valid' => true, 'seats' => 9999, 'exp' => $now + 3600]));
    $r = KeyWardenClient::verifyToken("$h.$b2.$s", $pub);
    assertTrue($r['reason'] === 'bad_signature', 'tamper must be bad_signature');
});

check('a token signed by a DIFFERENT key is rejected', function () use ($now) {
    [$ta] = mint(['valid' => true, 'exp' => $now + 3600]);
    [, $pb] = mint(['valid' => true, 'exp' => $now + 3600]);
    assertTrue(KeyWardenClient::verifyToken($ta, $pb)['valid'] === false, 'wrong key must fail');
});

check('expiry honoured, with the offline grace window', function () use ($now) {
    [$t1, $p1] = mint(['valid' => true, 'exp' => $now - 100, 'grace_seconds' => 0]);
    assertTrue(KeyWardenClient::verifyToken($t1, $p1)['reason'] === 'expired', 'expired without grace');
    [$t2, $p2] = mint(['valid' => true, 'exp' => $now - 100, 'grace_seconds' => 86400]);
    assertTrue(KeyWardenClient::verifyToken($t2, $p2)['valid'] === true, 'within grace must be valid');
});

check('a signed NEGATIVE (valid:false) is honoured', function () use ($now) {
    [$token, $pub] = mint(['valid' => false, 'reason' => 'revoked', 'exp' => $now + 3600]);
    $r = KeyWardenClient::verifyToken($token, $pub);
    assertTrue($r['valid'] === false && $r['reason'] === 'revoked', 'signed revoke must be honoured');
});

check('a malformed token and a bad public key fail cleanly', function () use ($now) {
    assertTrue(KeyWardenClient::verifyToken('nope', 'AAAA')['reason'] === 'malformed_token', 'malformed');
    [$token] = mint(['valid' => true, 'exp' => $now + 3600]);
    assertTrue(KeyWardenClient::verifyToken($token, base64_encode('short'))['reason'] === 'bad_public_key', 'bad key');
});

echo "\nkeywarden(php): online validate\n";

check('validate posts to the gateway with both auth headers', function () {
    $cap = [];
    $r = KeyWardenClient::validate('CUST', [
        'apimKey' => 'apim', 'clientKey' => 'ck', 'machineId' => 'm1',
        'transport' => transportReturning(200, ['valid' => true, 'activeSeats' => 4], $cap),
    ]);
    assertTrue($r['valid'] === true && $r['activeSeats'] === 4, 'valid with seats');
    assertTrue(str_ends_with($cap['url'], '/keywarden/validate'), 'path');
    assertTrue($cap['headers']['Ocp-Apim-Subscription-Key'] === 'apim', 'apim header');
    assertTrue($cap['headers']['X-Client-Key'] === 'ck', 'client header');
    assertTrue($cap['headers']['X-Machine-Id'] === 'm1', 'machine header');
    assertTrue($cap['body'] === ['key' => 'CUST', 'machineId' => 'm1'], 'body');
});

check('a definitive valid:false is returned as DATA, not thrown', function () {
    $r = KeyWardenClient::validate('K', [
        'apimKey' => 'a', 'clientKey' => 'c',
        'transport' => transportReturning(200, ['valid' => false, 'reason' => 'seat_limit_exceeded']),
    ]);
    assertTrue($r['valid'] === false && $r['reason'] === 'seat_limit_exceeded', 'negative is data');
});

check('a 401 is thrown as the VENDOR\'s auth problem', function () {
    try {
        KeyWardenClient::validate('K', [
            'apimKey' => 'a', 'clientKey' => 'wrong',
            'transport' => transportReturning(401, ['error' => 'unauthorized_client']),
        ]);
    } catch (KeyWardenError $e) {
        assertTrue($e->errorCode === 'unauthorized_client' && $e->status === 401, '401 shape');
        return;
    }
    throw new \Exception('should have thrown');
});

check('a 5xx is thrown as validation_unavailable', function () {
    try {
        KeyWardenClient::validate('K', [
            'apimKey' => 'a', 'clientKey' => 'c',
            'transport' => transportReturning(503, null),
        ]);
    } catch (KeyWardenError $e) {
        assertTrue($e->errorCode === 'validation_unavailable', '5xx code');
        return;
    }
    throw new \Exception('should have thrown');
});

check('missing credentials throw before any request', function () {
    $cases = [
        [['clientKey' => 'c'], 'missing_apim_key'],
        [['apimKey' => 'a'], 'missing_client_key'],
    ];
    foreach ($cases as [$opts, $code]) {
        try {
            KeyWardenClient::validate('K', $opts);
            throw new \Exception('should have thrown');
        } catch (KeyWardenError $e) {
            assertTrue($e->errorCode === $code, "expected $code");
        }
    }
    try {
        KeyWardenClient::validate('', ['apimKey' => 'a', 'clientKey' => 'c']);
        throw new \Exception('should have thrown');
    } catch (KeyWardenError $e) {
        assertTrue($e->errorCode === 'missing_key', 'missing_key');
    }
});

echo "\nkeywarden(php): validateOrVerify fallback\n";

check('online success is used and marked source:online', function () {
    $r = KeyWardenClient::validateOrVerify('K', [
        'apimKey' => 'a', 'clientKey' => 'c',
        'transport' => transportReturning(200, ['valid' => true, 'token' => 'x']),
    ]);
    assertTrue($r['source'] === 'online' && $r['valid'] === true, 'online used');
});

check('an unreachable gateway falls back to the cached token', function () use ($now) {
    [$token, $pub] = mint(['valid' => true, 'exp' => $now + 3600]);
    $dead = function (array $req): array {
        throw new KeyWardenError('ECONNREFUSED', 'unreachable');
    };
    $r = KeyWardenClient::validateOrVerify('K', [
        'apimKey' => 'a', 'clientKey' => 'c', 'transport' => $dead,
        'cachedToken' => $token, 'publicKey' => $pub,
    ]);
    assertTrue($r['source'] === 'offline' && $r['valid'] === true, 'offline fallback');
});

check('a 401 is NOT masked by an offline fallback', function () use ($now) {
    [$token, $pub] = mint(['valid' => true, 'exp' => $now + 3600]);
    try {
        KeyWardenClient::validateOrVerify('K', [
            'apimKey' => 'a', 'clientKey' => 'wrong',
            'transport' => transportReturning(401, ['error' => 'unauthorized_client']),
            'cachedToken' => $token, 'publicKey' => $pub,
        ]);
    } catch (KeyWardenError $e) {
        assertTrue($e->status === 401, '401 preserved');
        return;
    }
    throw new \Exception('should have thrown');
});

echo "\nkeywarden(php): machineIdFrom\n";

check('machineIdFrom is stable and hashed', function () {
    $i = KeyWardenClient::machineIdFrom('host-abc', 'user-42');
    assertTrue(strlen($i) === 64 && ctype_xdigit($i), 'hex64');
    assertTrue($i === KeyWardenClient::machineIdFrom('host-abc', 'user-42'), 'stable');
    assertTrue($i !== KeyWardenClient::machineIdFrom('host-abc', 'user-43'), 'distinct');
    assertTrue(strpos($i, 'host-abc') === false, 'hashed');
});

echo "\nkeywarden(php): code protection (seal / unlock / unseal)\n";

// Mimic the SERVER: a random 32-byte key + machine-bound wrap.
function serverWrap(string $key, string $mid, string $kid): string
{
    $salt = random_bytes(16);
    $iv = random_bytes(12);
    $wk = hash_hkdf('sha256', $mid, 32, 'kw-ck-wrap-v1', $salt);
    $tag = '';
    $ct = openssl_encrypt($key, 'aes-256-gcm', $wk, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    return '1:' . $kid . ':' . base64_encode($salt) . ':' . base64_encode($iv) . ':' . base64_encode($tag) . ':' . base64_encode($ct);
}

check('seal -> unseal round-trips with the content key', function () {
    $key = random_bytes(32);
    $blob = KeyWardenClient::seal('licensed feature', base64_encode($key));
    assertTrue(strncmp($blob, 'KW-SEAL-1:', 10) === 0, 'blob prefix');
    assertTrue(KeyWardenClient::unseal($blob, $key) === 'licensed feature', 'round-trip');
});

check('unlock recovers the key only on the right machine', function () {
    $key = random_bytes(32);
    $ck = serverWrap($key, 'device-A', 'k1');
    assertTrue(KeyWardenClient::unlock($ck, 'device-A') === $key, 'right machine');
    $blocked = false;
    try {
        KeyWardenClient::unlock($ck, 'device-B');
    } catch (KeyWardenError $e) {
        $blocked = $e->errorCode === 'unlock_failed';
    }
    assertTrue($blocked, 'wrong machine blocked');
});

check('unlockFromToken pulls ck out of a validate token', function () {
    $key = random_bytes(32);
    $ck = serverWrap($key, 'device-A', 'k1');
    $tok = 'h.' . b64url(json_encode(['ck' => $ck])) . '.s';
    assertTrue(KeyWardenClient::unlockFromToken($tok, 'device-A') === $key, 'from token');
});

check('unsealOnline returns the content key', function () {
    $key = random_bytes(32);
    $ck = serverWrap($key, 'device-A', 'k1');
    $got = KeyWardenClient::unsealOnline('LIC', [
        'apimKey' => 'a',
        'machineId' => 'device-A',
        'transport' => transportReturning(200, ['ok' => true, 'ck' => $ck, 'keyId' => 'k1']),
    ]);
    assertTrue($got === $key, 'online key');
});

echo "\nkeywarden(php): free-trial helpers\n";

check('trialInfo reports a live trial with days left (rounded up)', function () use ($now) {
    $info = KeyWardenClient::trialInfo(['claims' => ['trial' => true, 'exp' => $now + 3 * 86400 + 100]], $now);
    assertTrue($info['isTrial'] === true, 'isTrial');
    assertTrue($info['expired'] === false, 'not expired');
    assertTrue($info['daysRemaining'] === 4, 'ceil(3d+100s) === 4');
    assertTrue($info['expiresAt'] === $now + 3 * 86400 + 100, 'expiresAt');
});

check('isTrial / daysRemaining accept a verify result', function () use ($now) {
    $r = ['valid' => true, 'claims' => ['trial' => true, 'exp' => $now + 7 * 86400]];
    assertTrue(KeyWardenClient::isTrial($r) === true, 'isTrial');
    assertTrue(KeyWardenClient::daysRemaining($r, $now) === 7, '7 days');
});

check('an expired trial reads expired true and 0 days', function () use ($now) {
    $info = KeyWardenClient::trialInfo(['trial' => true, 'exp' => $now - 10], $now);
    assertTrue($info['expired'] === true, 'expired');
    assertTrue($info['daysRemaining'] === 0, '0 days');
    assertTrue($info['secondsRemaining'] === 0, '0 seconds');
});

check('a non-trial perpetual key: isTrial false, no expiry', function () use ($now) {
    $info = KeyWardenClient::trialInfo(['plan' => 'pro'], $now);
    assertTrue($info['isTrial'] === false, 'not trial');
    assertTrue($info['expired'] === false, 'not expired');
    assertTrue($info['expiresAt'] === null, 'no expiry');
    assertTrue($info['daysRemaining'] === null, 'no days');
});

echo "\n  $PASS passed, $FAIL failed\n";
exit($FAIL === 0 ? 0 : 1);
