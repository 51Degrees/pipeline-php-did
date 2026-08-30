<?php
/* *********************************************************************
 * This Original Work is copyright of 51 Degrees Mobile Experts Limited.
 * Copyright 2026 51 Degrees Mobile Experts Limited, Davidson House,
 * Forbury Square, Reading, Berkshire, United Kingdom RG1 3EU.
 *
 * This Original Work is licensed under the European Union Public Licence
 * (EUPL) v.1.2 and is subject to its terms as set out below.
 *
 * If a copy of the EUPL was not distributed with this file, You can obtain
 * one at https://opensource.org/licenses/EUPL-1.2.
 *
 * The 'Compatible Licences' set out in the Appendix to the EUPL (as may be
 * amended by the European Commission) shall be deemed incompatible for
 * the purposes of the Work and the provisions of the compatibility
 * clause in Article 5 of the EUPL shall not apply.
 *
 * If using the Work as, or as part of, a network application, by
 * including the attribution notice(s) required under Article 5 of the EUPL
 * in the end user terms of the application under an appropriate heading,
 * such notice(s) shall fulfill the requirements of that article.
 * ********************************************************************* */

declare(strict_types=1);

namespace fiftyone\pipeline\did;

use RuntimeException;

/**
 * The cloud answered with a status the client does not turn into a result.
 * Carries the HTTP status and the response body so the caller can see what
 * the service said.
 */
class CloudException extends RuntimeException
{
    private int $statusCode;
    private string $body;

    public function __construct(int $statusCode, string $body, string $message)
    {
        parent::__construct($message, $statusCode);
        $this->statusCode = $statusCode;
        $this->body = $body;
    }

    /** The HTTP status the cloud answered with. */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /** The response body exactly as received. */
    public function getBody(): string
    {
        return $this->body;
    }
}
