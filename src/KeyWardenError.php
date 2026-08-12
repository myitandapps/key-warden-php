<?php

declare(strict_types=1);

namespace KeyWarden;

/**
 * A problem with the request or the vendor's own auth - NOT a licence verdict.
 *
 * A licence that is simply not valid comes back as ['valid' => false, ...];
 * only real failures (bad credentials, unreachable gateway, server error) throw.
 */
final class KeyWardenError extends \Exception
{
    /** @var string machine-readable code, e.g. "unauthorized_client", "unreachable". */
    public $errorCode;

    /** @var int|null HTTP status, when the failure came from the gateway. */
    public $status;

    public function __construct(string $message, string $errorCode, ?int $status = null)
    {
        parent::__construct($message);
        $this->errorCode = $errorCode;
        $this->status = $status;
    }
}
