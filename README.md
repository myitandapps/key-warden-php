# key-warden/sdk (PHP)

The official PHP client for [Key-Warden](https://key-warden.com). Validate a
software licence online — seat-aware, revocation-aware — or verify a signed token
offline against your embedded public key, with no network round-trip.

Uses PHP's built-in [`sodium`](https://www.php.net/manual/en/book.sodium.php) for
Ed25519 (bundled since PHP 7.2) and `curl`. PHP 7.2+.

```bash
composer require key-warden/sdk
```

## Validate online

The authoritative check. Ask the platform whether a licence is good *right now*.

```php
use KeyWarden\KeyWardenClient;

$res = KeyWardenClient::validate($licenceKey, [
    'apimKey'   => getenv('KW_APIM_KEY'),     // your APIM subscription key
    'clientKey' => getenv('KW_CLIENT_KEY'),   // your validation key
    'machineId' => KeyWardenClient::machineIdFrom(gethostname(), $userId), // stable, hashed your side
]);

if (!$res['valid']) {
    lockFeatures($res['reason'] ?? null);
}
// $res['token'] is a freshly signed proof — cache it for the offline path below.
```

A `valid === false` (e.g. `revoked`, `expired`, `seat_limit_exceeded`) is **data**,
not an exception. A wrong `clientKey` throws a `KeyWarden\KeyWardenError` with
`errorCode === 'unauthorized_client'` — that's *your* auth failing, and your
customer should never see it as a licence problem.

## Verify offline

No connection? Verify a token you already hold against your **public** key —
the 32-byte raw key from your vendor console.

```php
$check = KeyWardenClient::verifyToken($cachedToken, getenv('KW_PUBLIC_KEY'));
if (!$check['valid']) {
    lockFeatures($check['reason']); // 'bad_signature' | 'expired' | ...
}
```

The token is `header.body.signature` (compact JWT style) and the Ed25519
signature covers the exact bytes `header.body`. This client verifies over those
bytes — it never decodes-then-reverifies, which is the one mistake that silently
breaks offline checks. Expiry is honoured within the offline grace window you set
at mint time.

## Online, with an offline fallback

```php
$res = KeyWardenClient::validateOrVerify($licenceKey, [
    'apimKey' => $apimKey, 'clientKey' => $clientKey, 'machineId' => $machineId,
    'cachedToken' => $lastGoodToken,          // from a previous validate()
    'publicKey'   => getenv('KW_PUBLIC_KEY'),
]);
// $res['source'] === 'online' | 'offline'
```

A rejected `clientKey` (401) is never masked by the offline path — only a genuine
reachability failure falls back.

## API

| Method | Purpose |
|---|---|
| `KeyWardenClient::validate($key, $opts)` | Online check. Returns `['valid', 'reason'?, 'activeSeats'?, 'token'?]`. |
| `KeyWardenClient::verifyToken($token, $rawPubB64, $now?)` | Offline check. Returns `['valid', 'reason'?, 'claims'?]`. |
| `KeyWardenClient::validateOrVerify($key, $opts)` | Online, falling back to a cached token when unreachable. |
| `KeyWardenClient::machineIdFrom(...$parts)` | A stable SHA-256 machine id; raw parts never leave the machine. |

Any real failure (bad credentials, unreachable gateway, server error) throws
`KeyWarden\KeyWardenError`, which carries `->errorCode` and `->status`. For tests,
pass a `'transport'` callable in `$opts` to stub the HTTP call.

## Verify the build yourself

```bash
composer test        # -> "16 passed, 0 failed"
```

## Publishing (Packagist)

Composer packages are distributed via [Packagist](https://packagist.org), which
reads a `composer.json` at a **repository root** and auto-updates on git tags —
there's no upload step or token. Because of that root requirement, publish this
package from its **own repository** (e.g. `myitandapps/key-warden-php`) rather than
a subfolder of the SDK monorepo: push it, submit the repo URL once at
packagist.org, and every `vX.Y.Z` tag thereafter publishes automatically.

## Code protection (seal / unlock / unseal)

Lock part of your product so it only runs for a valid, activated licence. Get
your **content key** (base64) from the vendor console → **Protect your code**.

```php
use KeyWarden\KeyWardenClient as KW;

// Build time — seal a file once:
file_put_contents('secret.sealed', KW::seal(file_get_contents('secret.php'), $MY_CONTENT_KEY_B64));

// Runtime — the key rides in the validate token as `ck`, machine-bound:
$res = KW::validate($licence, ['apimKey' => $apim, 'clientKey' => $ck, 'machineId' => $mid]);
$key  = KW::unlockFromToken($res['token'], $mid);   // raw content-key bytes
$code = KW::unseal($sealedBlob, $key);              // your decrypted file

// Or a live check every time (real-time revocation):
$key = KW::unsealOnline($licence, ['apimKey' => $apim, 'machineId' => $mid]);
```

All AES-256-GCM (via `openssl`, needs `hash_hkdf` — PHP 7.1.2+). Unlock needs the
SAME `machineId` you validate with. A revoked licence stops getting the key.

## Licence

MIT.
