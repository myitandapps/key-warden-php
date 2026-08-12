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
