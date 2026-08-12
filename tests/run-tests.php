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

echo "\n  $PASS passed, $FAIL failed\n";
exit($FAIL === 0 ? 0 : 1);
