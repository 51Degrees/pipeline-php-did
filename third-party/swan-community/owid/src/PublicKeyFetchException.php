<?php

/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

declare(strict_types=1);

namespace SwanCommunity\Owid;

use Throwable;

/**
 * Raised by PublicKeyFetch when the public key of a creator could not be
 * obtained.
 *
 * Carries the status a caller should report for the identifier, which is
 * never a signature that does not match because the signature was never
 * examined, the domain the key was asked of, and the response code, which is
 * 0 where no response arrived at all.
 */
final class PublicKeyFetchException extends OwidException
{
    public function __construct(
        string $message,
        private readonly SignatureStatus $status,
        private readonly string $domain,
        private readonly int $statusCode = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * The status to report for the identifier whose key could not be
     * obtained.
     */
    public function status(): SignatureStatus
    {
        return $this->status;
    }

    /**
     * The domain the key was asked of.
     */
    public function domain(): string
    {
        return $this->domain;
    }

    /**
     * The response code, or 0 where no response arrived at all.
     */
    public function statusCode(): int
    {
        return $this->statusCode;
    }
}
