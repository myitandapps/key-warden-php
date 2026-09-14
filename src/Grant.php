<?php
declare(strict_types=1);

namespace KeyWarden;

/**
 * Grant verification (v1.4.0).
 *
 * A GRANT is what /validate returns on every successful check: a short-lived
 * Ed25519 token (header.payload.signature, base64url) bound to ONE activation
 * key and ONE machine. Between online checks the product verifies it locally.
 *
 * Two claims are constantly confused, so they are named apart here:
 *
 *   expires_at  the ENTITLEMENT. When the customer's licence actually ends.
 *   exp         the REFRESH window. When this grant goes stale and should be
 *               replaced. NOT the licence end. Its length is
 *               max(base TTL, grace + buffer), so an offline-enabled licence
 *               gets a grant that deliberately outlives its own grace window -
 *               a disconnected install must not go stale partway through the
 *               grace it was promised. Do not assume 24h.
 *
 * Three verdicts, not two. `fallback` is the one that matters:
 *
 *   accept    good for this key and this machine
 *   deny      provably not ours - wrong key, wrong machine, forged
 *   fallback  cannot be judged (unknown kid, no keys, malformed). Keep the last
 *             known-good verdict and re-check online. Denying here would turn a
 *             routine signing-key rotation into an outage for every install that
 *             has not taken the update yet.
 */
final class Grant
{
    private static function b64url(string $s): string
    {
        $s = strtr($s, '-_', '+/');
        return (string) base64_decode($s . str_repeat('=', (4 - strlen($s) % 4) % 4), false);
    }

    /** Accept [{kid,pub}], a bare base64 string (legacy), or a list of either. */
    private static function normaliseKeys($keys): array
    {
        if (empty($keys)) {
            return [];
        }
        if (is_string($keys)) {
            $keys = [['kid' => '', 'pub' => $keys]];
        }
        $out = [];
        foreach ((array) $keys as $k) {
            if (is_string($k) && $k !== '') {
                $out[] = ['kid' => '', 'pub' => $k];
            } elseif (is_array($k) && !empty($k['pub'])) {
                $out[] = ['kid' => (string) ($k['kid'] ?? ''), 'pub' => (string) $k['pub']];
            }
        }
        return $out;
    }

    /**
     * Which keys may verify a grant carrying this kid.
     *
     * A kid-less grant tries every key (legacy). A kid that matches a labelled
     * key uses that key ALONE - trying the others would let a retired key vouch
     * for a token minted under a different one. A kid matching nothing, while
     * the set IS labelled, yields no candidates: the rotation case, which the
     * caller turns into `fallback`, never a denial.
     */
    private static function selectKeys(array $keys, ?string $kid): array
    {
        if (!$keys) {
            return [];
        }
        if (!$kid) {
            return $keys;
        }
        $hit = array_values(array_filter($keys, static fn ($k) => $k['kid'] === $kid));
        if ($hit) {
            return $hit;
        }
        $labelled = (bool) array_filter($keys, static fn ($k) => $k['kid'] !== '');
        return $labelled ? [] : $keys;
    }

    private static function verifySig(string $signed, string $sig, string $rawPubB64): bool
    {
        $raw = base64_decode($rawPubB64, true);
        if (!is_string($raw) || strlen($raw) !== 32 || strlen($sig) !== 64) {
            return false;
        }
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new \RuntimeException('keywarden needs libsodium (ext-sodium) to verify a grant');
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, $signed, $raw);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * @param array|string $keys
     * @return array{verdict:string,reason:string,claims?:array}
     */
    public static function verify(string $token, $keys, array $opts = []): array
    {
        $now = isset($opts['now']) ? (float) $opts['now'] : microtime(true);

        if ($token === '') {
            return ['verdict' => 'fallback', 'reason' => 'no_grant'];
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return ['verdict' => 'fallback', 'reason' => 'malformed'];
        }
        $header = json_decode(self::b64url($parts[0]), true);
        $claims = json_decode(self::b64url($parts[1]), true);
        $sig    = self::b64url($parts[2]);
        if (!is_array($header) || !is_array($claims) || $sig === '') {
            return ['verdict' => 'fallback', 'reason' => 'malformed'];
        }
        $signed = $parts[0] . '.' . $parts[1];

        $ks = self::normaliseKeys($keys);
        if (!$ks) {
            return ['verdict' => 'fallback', 'reason' => 'no_keys'];
        }
        $cand = self::selectKeys($ks, isset($header['kid']) ? (string) $header['kid'] : null);
        if (!$cand) {
            return ['verdict' => 'fallback', 'reason' => 'unknown_kid', 'claims' => $claims];
        }

        $ok = false;
        foreach ($cand as $k) {
            if (self::verifySig($signed, $sig, $k['pub'])) {
                $ok = true;
                break;
            }
        }
        // A kid we DO know whose signature fails is forgery, not rotation.
        if (!$ok) {
            return ['verdict' => 'deny', 'reason' => 'bad_signature'];
        }

        $activationKey = (string) ($opts['activationKey'] ?? '');
        $machineId     = (string) ($opts['machineId'] ?? '');
        $nonce         = (string) ($opts['nonce'] ?? '');

        if ($activationKey !== '' && !empty($claims['sub'])
            && !hash_equals((string) $claims['sub'], hash('sha256', $activationKey))) {
            return ['verdict' => 'deny', 'reason' => 'wrong_key', 'claims' => $claims];
        }
        if ($machineId !== '' && !empty($claims['mid'])
            && !hash_equals((string) $claims['mid'], hash('sha256', $machineId))) {
            return ['verdict' => 'deny', 'reason' => 'wrong_machine', 'claims' => $claims];
        }
        // Only when a live nonce is supplied: a cached grant has none to compare to.
        if ($nonce !== '' && !empty($claims['cnonce'])
            && !hash_equals((string) $claims['cnonce'], $nonce)) {
            return ['verdict' => 'deny', 'reason' => 'replayed', 'claims' => $claims];
        }

        // Offline permission is OPT-IN and the claim is OMITTED when the vendor
        // has not enabled it, so absent must read as "not allowed", not "unknown".
        if (($claims['offline_allowed'] ?? null) !== true) {
            return ['verdict' => 'deny', 'reason' => 'offline_not_allowed', 'claims' => $claims];
        }

        // expires_at absent/null => perpetual. Never read a missing term as expired.
        if (!empty($claims['expires_at'])) {
            $end = strtotime((string) $claims['expires_at']);
            if ($end !== false) {
                $grace = max((float) ($claims['grace_seconds'] ?? 0), 0);
                if ($now > $end + $grace) {
                    return ['verdict' => 'deny', 'reason' => 'expired', 'claims' => $claims];
                }
            }
        }

        return ['verdict' => 'accept', 'reason' => 'ok', 'claims' => $claims];
    }

    /** The ENTITLEMENT end as a unix timestamp, or null for perpetual. */
    public static function expiresAt(?array $claims): ?int
    {
        if (!$claims || empty($claims['expires_at'])) {
            return null;
        }
        $t = strtotime((string) $claims['expires_at']);
        return $t === false ? null : $t;
    }

    /** True once this grant should be replaced. This is `exp`, and only `exp`. */
    public static function needsRefresh(?array $claims, ?int $now = null): bool
    {
        if (!$claims || empty($claims['exp'])) {
            return true;
        }
        return ($now ?? time()) >= (int) $claims['exp'];
    }

    /** Past the term but still licensed - worth warning the user about. */
    public static function inGrace(?array $claims, ?int $now = null): bool
    {
        $end = self::expiresAt($claims);
        if ($end === null) {
            return false;
        }
        return ($now ?? time()) > $end;
    }
}
