# key-warden/sdk (PHP)

The official PHP client for [Key-Warden](https://key-warden.com). Validate a
software licence online — seat-aware, revocation-aware — or verify a signed token
offline against your embedded public key, with no network round-trip.

Uses PHP's built-in [`sodium`](https://www.php.net/manual/en/book.sodium.php) for
Ed25519 (bundled since PHP 7.2) and `curl`. PHP 7.2+.

Current version: **1.5.0**.

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

## Activation keys and grants

A Key-Warden key is **opaque** — `KW-XXXX-XXXX-XXXX-XXXX`. It carries no plan, no
seat count and no term. Those live on the licence record, so a renewal, an
upgrade, a seat top-up or a revocation lands at the customer's next check with
nothing for them to paste.

Every check returns a signed **grant** bound to that key, that machine and that
request. Verify it against the key **set** from your vendor console — a set, not
a single key, so a signing-key rotation never breaks installs that have not
updated yet:

```php
use KeyWarden\KeyWardenClient;
use KeyWarden\Grant;

$keys = [
    ['kid' => 'mitaa-k1', 'pub' => 'BASE64_32_BYTE_KEY'],
    ['kid' => 'mitaa-k2', 'pub' => 'BASE64_32_BYTE_KEY'],   // the incoming one
];

$res = KeyWardenClient::validate($licenceKey, [
    'apimKey'   => $apimKey,
    'clientKey' => $clientKey,
    'machineId' => $machineId,
    'keys'      => $keys,
    'product'   => 'acme-maps',
    'userCount' => $activeUsers,      // for banded plans
    'envType'   => 'production',      // or let KW_ENV_TYPE / WP_ENVIRONMENT_TYPE decide
    'siteLabel' => home_url(),        // optional, for the vendor console
]);

// $res['grantVerdict'] : 'accept' | 'deny' | 'fallback'  (absent if you baked no keys)
// $res['expiresAt']    : the licence term (NOT $res['claims']['exp'])
```

Offline, the same check without a network:

```php
$g = Grant::verify($cachedToken, $keys, [
    'activationKey' => $licenceKey,
    'machineId'     => $machineId,
    'nonce'         => $nonce,   // only if you still hold the one you sent
]);
// $g === ['verdict' => ..., 'reason' => ..., 'claims' => [...]]
if ($g['verdict'] === 'accept')   { run_app(); }
elseif ($g['verdict'] === 'deny') { lock_features($g['reason']); }
else                              { keep_last_known_good(); }   // 'fallback'
```

`offline_allowed` is **opt-in and omitted** when you have not enabled it in the
vendor console, so a cached grant returns `deny` / `offline_not_allowed` until
you do. That is the offline path only — a verdict that just came back live from
`validate()` is applied as-is.

### Three verdicts, and why `fallback` is not a denial

| Verdict | When | What you do |
|---|---|---|
| `accept` | good for this key and this machine | licence the product |
| `deny` | wrong key, wrong machine, forged, expired past grace | lock it |
| `fallback` | unknown `kid`, no keys baked in, unparseable | **keep your previous state** and re-check online |

`fallback` means the SDK could not judge the grant, not that the grant is bad.
Treating it as a denial turns a routine signing-key rotation into an outage. A
**known** kid whose signature fails is a different thing entirely — that is
forgery, and it denies.

### `expires_at` is the term; `exp` is the refresh window

The single most misread pair in the model.

- `Grant::expiresAt($claims)` / `$claims['expires_at']` — when the **licence**
  ends. Gate on this.
- `$claims['exp']` — when the **grant** goes stale and should be refreshed. It is
  `max(base TTL, grace + offline buffer)`, so an offline-enabled licence gets a
  grant that deliberately outlives its own grace window. Gating access on `exp`
  locks out paying customers.

`Grant::needsRefresh($claims)` and `Grant::inGrace($claims)` answer those two
questions directly.

### What `validate()` now sends

Three headers you get for free, and should not strip:

- `X-Kw-Nonce` — a fresh 128-bit nonce per call, echoed inside the signed grant.
  Without it a captured answer replays.
- `X-Kw-Env-Type` — `production` unless you say otherwise (or `KW_ENV_TYPE` /
  `WP_ENVIRONMENT_TYPE` says so). An undeclared staging site burns a **paid
  production seat** — on WordPress that is the single most common way a vendor
  runs out of seats they paid for. Anything unrecognised reads as production,
  never the cheaper pool by accident.
- `X-Site-Url` — the site label, for the vendor console.

A grant that fails verification sets `grantVerdict` / `grantReason` and
`trustworthy => false`. It does **not** flip `valid` to false — a verification
fault is ours, not the customer's, and must never downgrade a paying licence.

## Free trials

A trial licence is an ordinary Key-Warden key — validate it exactly like any
other. It just carries two extra claims: `trial => true` and an `exp` (unix
seconds). Once the trial ends, `verifyToken()`/`validate()` refuse it as
`expired` on their own. The trial helpers are for **display** — showing
"N days left" and switching to an expired state:

```php
$res = KeyWardenClient::verifyToken($cachedToken, getenv('KW_PUBLIC_KEY'));

if ($res['valid']) {
    $t = KeyWardenClient::trialInfo($res);   // ['isTrial','expired','expiresAt','secondsRemaining','daysRemaining']
    if ($t['isTrial']) {
        show_banner("Trial — {$t['daysRemaining']} day(s) left");
    }
    run_app();
} elseif (($res['reason'] ?? '') === 'expired') {
    show_paywall('Your trial has ended. Enter a licence key to continue.');
}
```

`trialInfo()` accepts a `verifyToken()`/`validate()` result or a raw claims
array. `isTrial($x)` and `daysRemaining($x)` are shortcuts. `daysRemaining` is
rounded up (the last partial day still reads "1 day left") and is `0` once
expired, `null` for a key with no `exp`. These helpers never grant access —
always gate on `verifyToken()`/`validate()` first. Trial keys are node-locked to
one device, so pass the same `machineId` you use for `validate()`.

## API

| Method | Purpose |
|---|---|
| `KeyWardenClient::validate($key, $opts)` | Online check. Returns `['valid', 'reason'?, 'activeSeats'?, 'token'?]`. |
| `KeyWardenClient::verifyToken($token, $rawPubB64, $now?)` | Offline check. Returns `['valid', 'reason'?, 'claims'?]`. |
| `KeyWardenClient::validateOrVerify($key, $opts)` | Online, falling back to a cached token when unreachable. |
| `KeyWardenClient::machineIdFrom(...$parts)` | A stable SHA-256 machine id; raw parts never leave the machine. |
| `Grant::verify($token, $keys, $opts)` | Offline grant check. Returns `['verdict', 'reason', 'claims'?]`. |
| `Grant::expiresAt($claims)` | The licence term as unix seconds — `expires_at`, never `exp`. `null` for perpetual. |
| `Grant::needsRefresh($claims, $now?)` | `true` once the grant's `exp` has passed and it should be re-fetched. |
| `Grant::inGrace($claims, $now?)` | `true` when the licence has lapsed but is still inside its offline grace window. |
| `KeyWardenClient::trialInfo($x, $now?)` | Trial facts for display: `['isTrial','expired','expiresAt','secondsRemaining','daysRemaining']`. |
| `KeyWardenClient::isTrial($x)` | `true` when the licence carries `trial => true`. |
| `KeyWardenClient::daysRemaining($x, $now?)` | Whole days left (rounded up); `0` once expired; `null` if no `exp`. |

Any real failure (bad credentials, unreachable gateway, server error) throws
`KeyWarden\KeyWardenError`, which carries `->errorCode` and `->status`. For tests,
pass a `'transport'` callable in `$opts` to stub the HTTP call.

## Verify the build yourself

```bash
composer test
#   == legacy surface ==     24 passed, 0 failed
#   == grant conformance ==  23 passed, 0 failed
#   == client contract ==    18 passed, 0 failed
#   == no-composer install == 4 passed, 0 failed
#   ALL SUITES PASSED
```

`tests/grant-vectors.json` is minted by the platform's **own** signer, not a
lookalike, and all four SDKs run the same vectors — so they cannot drift apart.

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
