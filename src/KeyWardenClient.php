<?php

declare(strict_types=1);

namespace KeyWarden;

/**
 * The official PHP client for Key-Warden.
 *
 * Two things, and only two:
 *
 *   validate($key, [...])        the ONLINE check. Asks the platform whether a
 *                                licence is good right now: seat-, revocation-
 *                                and expiry-aware. Returns a fresh signed token.
 *
 *   verifyToken($token, $pub)    the OFFLINE check. Verifies a token you already
 *                                hold against your embedded public key, no network.
 *
 * The token is a compact JWT-style envelope, header.body.signature, each part
 * base64url, the Ed25519 signature computed over the exact bytes "header.body".
 * This client verifies over those exact bytes - it never decodes-then-reverifies,
 * which is the one mistake that silently breaks offline checks.
 *
 * Requires ext-sodium (Ed25519, bundled with PHP 7.2+) and ext-curl.
 */
final class KeyWardenClient
{
    public const DEFAULT_BASE = 'https://api.key-warden.com';
    private const VALIDATE_PATH = '/keywarden/validate';

    /**
     * OFFLINE verification. Pure, no network.
     *
     * @param string   $token     header.body.signature as returned by validate().
     * @param string   $rawPubB64 your vendor public key, the 32 raw bytes, base64.
     * @param int|null $now       unix seconds; for testing. Defaults to real time.
     * @return array{valid: bool, reason?: string, claims?: array}
     */
    public static function verifyToken(string $token, string $rawPubB64, ?int $now = null): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return ['valid' => false, 'reason' => 'malformed_token'];
        }
        [$header, $body, $sig] = $parts;

        $raw = base64_decode($rawPubB64, true);
        // The vendor console hands out the raw 32-byte key; a PEM or an SPKI blob
        // is the wrong length, and that is a configuration mistake worth naming.
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return ['valid' => false, 'reason' => 'bad_public_key'];
        }

        $sigBytes = self::b64urlDecode($sig);
        if ($sigBytes === false || strlen($sigBytes) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return ['valid' => false, 'reason' => 'bad_signature'];
        }

        // The signature covers the STRING "header.body" exactly as transmitted -
        // not the decoded claims. Verify over those bytes and nothing else.
        $ok = sodium_crypto_sign_verify_detached($sigBytes, $header . '.' . $body, $raw);
        if (!$ok) {
            return ['valid' => false, 'reason' => 'bad_signature'];
        }

        $claimsJson = self::b64urlDecode($body);
        $claims = $claimsJson === false ? null : json_decode($claimsJson, true);
        if (!is_array($claims)) {
            return ['valid' => false, 'reason' => 'bad_claims'];
        }

        // Expiry is checked WITHIN the offline grace window set at mint time.
        $at = $now ?? time();
        $grace = isset($claims['grace_seconds']) ? (int) $claims['grace_seconds'] : 0;
        if (isset($claims['exp']) && $at > ((int) $claims['exp']) + $grace) {
            return ['valid' => false, 'reason' => 'expired', 'claims' => $claims];
        }

        // A signed NEGATIVE (valid:false) is a proof of revocation and is honoured.
        if (array_key_exists('valid', $claims) && $claims['valid'] === false) {
            return ['valid' => false, 'reason' => $claims['reason'] ?? 'not_valid', 'claims' => $claims];
        }

        return ['valid' => true, 'claims' => $claims];
    }

    /**
     * ONLINE validation against the gateway. Seat-, revocation- and expiry-aware.
     *
     * @param string $key  the customer's activation key.
     * @param array  $opts apimKey (required), clientKey (required), machineId,
     *                     baseUrl, timeout (seconds), transport (callable for tests).
     * @return array the gateway JSON, e.g. ['valid'=>true, 'activeSeats'=>4, 'token'=>'...'].
     * @throws KeyWardenError on missing creds, a rejected key (401), an unreachable
     *                        gateway, or a server error.
     */
    public static function validate(string $key, array $opts): array
    {
        if ($key === '') {
            throw new KeyWardenError('validate($key, ...): key must be a non-empty string', 'missing_key');
        }
        $apimKey = $opts['apimKey'] ?? '';
        $clientKey = $opts['clientKey'] ?? '';
        if ($apimKey === '') {
            throw new KeyWardenError('apimKey is required (your APIM subscription key)', 'missing_apim_key');
        }
        if ($clientKey === '') {
            throw new KeyWardenError('clientKey is required (your validation key)', 'missing_client_key');
        }

        $machineId = $opts['machineId'] ?? null;
        $baseUrl = rtrim($opts['baseUrl'] ?? self::DEFAULT_BASE, '/');
        $timeout = $opts['timeout'] ?? 15;

        $payload = ['key' => $key];
        if ($machineId) {
            $payload['machineId'] = $machineId;
        }
        $headers = [
            'Content-Type' => 'application/json',
            'Ocp-Apim-Subscription-Key' => $apimKey,
            'X-Client-Key' => $clientKey,
        ];
        if ($machineId) {
            $headers['X-Machine-Id'] = (string) $machineId;
        }

        $request = [
            'url' => $baseUrl . self::VALIDATE_PATH,
            'headers' => $headers,
            'body' => json_encode($payload),
            'timeout' => $timeout,
        ];

        $transport = $opts['transport'] ?? [self::class, 'curlTransport'];
        // The transport returns ['status'=>int, 'body'=>string|null]; a genuine
        // reachability failure throws KeyWardenError('...','unreachable'|'timeout').
        $response = $transport($request);
        $status = $response['status'] ?? 0;
        $rawBody = $response['body'] ?? null;

        $body = null;
        if (is_string($rawBody) && $rawBody !== '') {
            $decoded = json_decode($rawBody, true);
            $body = is_array($decoded) ? $decoded : null;
        }

        if ($status === 401) {
            throw new KeyWardenError(
                $body['reason'] ?? 'your validation key was rejected',
                $body['error'] ?? 'unauthorized_client',
                401
            );
        }
        if ($status >= 500 || $status === 0 || $body === null) {
            throw new KeyWardenError(
                $body['error'] ?? "gateway error ($status)",
                $body['error'] ?? 'validation_unavailable',
                $status ?: null
            );
        }

        // 200 with {valid} is the licence verdict - true or false, both normal.
        return $body;
    }

    /**
     * Validate online; on an unreachable gateway, fall back to a cached token.
     * A rejected validation key (401) is never masked by the offline path.
     *
     * @param array $opts as validate(), plus cachedToken and publicKey for the fallback.
     */
    public static function validateOrVerify(string $key, array $opts): array
    {
        try {
            $online = self::validate($key, $opts);
            $online['source'] = 'online';
            return $online;
        } catch (KeyWardenError $e) {
            if ($e->errorCode !== 'unreachable' && $e->errorCode !== 'timeout') {
                throw $e;
            }
            $cachedToken = $opts['cachedToken'] ?? null;
            $publicKey = $opts['publicKey'] ?? null;
            if (!$cachedToken || !$publicKey) {
                throw $e;
            }
            $off = self::verifyToken($cachedToken, $publicKey);
            $off['source'] = 'offline';
            return $off;
        }
    }

    /**
     * A stable, privacy-preserving machine id: SHA-256 over the parts you provide.
     * The raw parts never leave the machine - only their hash.
     */
    public static function machineIdFrom(string ...$parts): string
    {
        $joined = implode('|', array_filter($parts, static fn($p) => $p !== ''));
        if ($joined === '') {
            throw new KeyWardenError('machineIdFrom() needs at least one non-empty part', 'empty');
        }
        return hash('sha256', $joined);
    }

    // =====================================================================
    // ISV CODE PROTECTION (seal / unlock / unseal)  - v1.2.1
    //
    // Lock part of your product so it only runs for a valid, activated licence.
    //   seal($data, $key)            build time: lock a file with the content key.
    //   unlockFromToken($t, $mid)    runtime, offline: key from the validate token.
    //   unsealOnline($key, $opts)    runtime, online: live check, real-time revoke.
    //   unseal($blob, $key)          runtime: decrypt what you sealed.
    // All AES-256-GCM (via openssl). The content key is machine-bound: unlock
    // needs the SAME machineId you send to validate.
    // =====================================================================

    private const UNSEAL_PATH = '/keywarden/unseal';
    private const CK_WRAP_INFO = 'kw-ck-wrap-v1';

    private static function asKey($k): string
    {
        // Accept either the raw 32-byte key (e.g. from unlock()) or its base64
        // form (e.g. from the vendor console). A raw key is exactly 32 bytes;
        // base64 of 32 bytes is 44 chars, so the length tells them apart.
        $s = (string) $k;
        $key = strlen($s) === 32 ? $s : base64_decode($s, true);
        if ($key === false || strlen($key) !== 32) {
            throw new KeyWardenError('content key must be 32 bytes', 'bad_key');
        }
        return $key;
    }

    /** BUILD TIME: lock $data with your content key. Returns a "KW-SEAL-1:..." string. */
    public static function seal(string $data, string $contentKeyBase64): string
    {
        $key = self::asKey($contentKeyBase64);
        $iv = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($ct === false) {
            throw new KeyWardenError('seal failed', 'seal_failed');
        }
        return 'KW-SEAL-1:' . base64_encode($iv) . ':' . base64_encode($tag) . ':' . base64_encode($ct);
    }

    /** RUNTIME: turn a machine-bound $ck into the 32-byte content key. */
    public static function unlock(string $ck, string $machineId): string
    {
        $p = explode(':', $ck);
        if (count($p) !== 6 || $p[0] !== '1') {
            throw new KeyWardenError('bad ck format', 'bad_ck');
        }
        $salt = base64_decode($p[2], true);
        $iv = base64_decode($p[3], true);
        $tag = base64_decode($p[4], true);
        $body = base64_decode($p[5], true);
        $wrapKey = hash_hkdf('sha256', $machineId, 32, self::CK_WRAP_INFO, $salt);
        $out = openssl_decrypt($body, 'aes-256-gcm', $wrapKey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($out === false) {
            throw new KeyWardenError('could not unlock the content key - wrong machineId or tampered token', 'unlock_failed');
        }
        return $out;
    }

    /** RUNTIME: pull the content key out of a validate token's `ck` claim. */
    public static function unlockFromToken(string $token, string $machineId): string
    {
        $parts = explode('.', $token);
        if (count($parts) < 2) {
            throw new KeyWardenError('not a token', 'bad_token');
        }
        $json = base64_decode(strtr($parts[1], '-_', '+/'), true);
        $claims = $json !== false ? json_decode($json, true) : null;
        if (!is_array($claims)) {
            throw new KeyWardenError('could not read token', 'bad_token');
        }
        if (empty($claims['ck'])) {
            throw new KeyWardenError('this licence has no content key (product not protected)', 'no_ck');
        }
        return self::unlock($claims['ck'], $machineId);
    }

    /** RUNTIME, ONLINE: POST /unseal and return the content key. Real-time revocation. */
    public static function unsealOnline(string $key, array $opts): string
    {
        $apimKey = $opts['apimKey'] ?? '';
        $machineId = $opts['machineId'] ?? '';
        if ($apimKey === '') {
            throw new KeyWardenError('apimKey is required (your APIM subscription key)', 'missing_apim_key');
        }
        if ($machineId === '') {
            throw new KeyWardenError('machineId is required (the key is bound to it)', 'missing_machine_id');
        }
        $baseUrl = rtrim($opts['baseUrl'] ?? self::DEFAULT_BASE, '/');
        $payload = ['key' => $key];
        if (!empty($opts['product'])) {
            $payload['product'] = $opts['product'];
        }
        $request = [
            'url' => $baseUrl . self::UNSEAL_PATH,
            'headers' => [
                'Content-Type' => 'application/json',
                'Ocp-Apim-Subscription-Key' => $apimKey,
                'X-Machine-Id' => (string) $machineId,
            ],
            'body' => json_encode($payload),
            'timeout' => $opts['timeout'] ?? 15,
        ];
        $transport = $opts['transport'] ?? [self::class, 'curlTransport'];
        $response = $transport($request);
        $status = $response['status'] ?? 0;
        $rawBody = $response['body'] ?? null;
        $body = (is_string($rawBody) && $rawBody !== '') ? json_decode($rawBody, true) : null;
        if ($status >= 300 || $status === 0 || !is_array($body) || empty($body['ok']) || empty($body['ck'])) {
            throw new KeyWardenError(
                $body['error'] ?? "unseal failed ($status)",
                $body['error'] ?? 'unseal_failed',
                $status ?: null
            );
        }
        return self::unlock($body['ck'], (string) $machineId);
    }

    /** RUNTIME: decrypt a "KW-SEAL-1:..." blob with the content key from unlock*(). */
    public static function unseal(string $sealedBlob, string $contentKey): string
    {
        $p = explode(':', $sealedBlob);
        if (count($p) !== 4 || $p[0] !== 'KW-SEAL-1') {
            throw new KeyWardenError('not a KW-SEAL-1 blob', 'bad_blob');
        }
        $key = self::asKey($contentKey);
        $iv = base64_decode($p[1], true);
        $tag = base64_decode($p[2], true);
        $ct = base64_decode($p[3], true);
        $out = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($out === false) {
            throw new KeyWardenError('could not unseal - wrong key or tampered blob', 'unseal_failed');
        }
        return $out;
    }

    // ---- helpers ----------------------------------------------------------

    /**
     * The default transport: a single POST via curl.
     * @return array{status: int, body: string|null}
     */
    private static function curlTransport(array $req): array
    {
        $ch = curl_init($req['url']);
        $headers = [];
        foreach ($req['headers'] as $name => $value) {
            $headers[] = "$name: $value";
        }
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POSTFIELDS => $req['body'],
            CURLOPT_TIMEOUT => $req['timeout'],
        ]);
        $body = curl_exec($ch);
        if ($body === false) {
            $err = curl_error($ch);
            $errno = curl_errno($ch);
            curl_close($ch);
            $code = ($errno === CURLE_OPERATION_TIMEDOUT) ? 'timeout' : 'unreachable';
            throw new KeyWardenError("could not reach the gateway: $err", $code);
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        return ['status' => $status, 'body' => $body];
    }

    /** base64url decode, tolerant of missing padding. */
    private static function b64urlDecode(string $s)
    {
        $s = strtr($s, '-_', '+/');
        $pad = strlen($s) % 4;
        if ($pad) {
            $s .= str_repeat('=', 4 - $pad);
        }
        return base64_decode($s, true);
    }
}
