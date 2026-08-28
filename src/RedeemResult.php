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

use DateTimeImmutable;
use DateTimeZone;

/**
 * The typed answer to {@see DidClient::redeem()}, built from the body the
 * cloud's redeem endpoint sent with a 200 or a 503.
 *
 * The two time fields describe the redemption rather than the identifier.
 * {@see RedeemResult::$verifiedAt} is when the verify endpoint checked the
 * context and sealed the result, and
 * {@see RedeemResult::$secondsSinceVerified} is how long ago that was by the
 * service's clock, in whole seconds. Both are present on the redeemed and
 * expired outcomes and null otherwise.
 */
final class RedeemResult
{
    /** The format the cloud writes `verifiedAt` in, ISO 8601 UTC to the second. */
    public const VERIFIED_AT_FORMAT = 'Y-m-d\TH:i:s\Z';

    /** The creator context verdict. */
    public readonly ContextOutcome $context;

    /**
     * The `context` string exactly as the cloud sent it, so a value this
     * build maps to {@see ContextOutcome::Unreadable} because it is not
     * known is still visible. Empty when the field was absent.
     */
    public readonly string $rawContext;

    /** The signature outcome, {@see SignatureOutcome::Unknown} when absent. */
    public readonly SignatureOutcome $signature;

    /**
     * Factor name to outcome, present only when the cloud sent `factors`,
     * which is the mismatch case.
     *
     * @var array<string, FactorOutcome>|null
     */
    public readonly ?array $factors;

    /** When the context was verified and sealed, UTC, or null. */
    public readonly ?DateTimeImmutable $verifiedAt;

    /** Whole seconds between sealing and redemption, or null. */
    public readonly ?int $secondsSinceVerified;

    /** The HTTP status, 200 or 503. */
    public readonly int $statusCode;

    /** The response body exactly as received. */
    public readonly string $raw;

    /**
     * @param array<string, FactorOutcome>|null $factors
     */
    public function __construct(
        ContextOutcome $context,
        string $rawContext,
        SignatureOutcome $signature,
        ?array $factors,
        ?DateTimeImmutable $verifiedAt,
        ?int $secondsSinceVerified,
        int $statusCode,
        string $raw
    ) {
        $this->context = $context;
        $this->rawContext = $rawContext;
        $this->signature = $signature;
        $this->factors = $factors;
        $this->verifiedAt = $verifiedAt;
        $this->secondsSinceVerified = $secondsSinceVerified;
        $this->statusCode = $statusCode;
        $this->raw = $raw;
    }

    /**
     * Builds the result from a redeem response. A body that is not a JSON
     * object, or one without a `context`, reads as
     * {@see ContextOutcome::Unreadable}, so nothing unexpected passes as a
     * verdict.
     */
    public static function fromResponse(int $statusCode, string $body): self
    {
        $json = json_decode($body, true);
        if (!is_array($json)) {
            $json = [];
        }
        $rawContext = isset($json['context']) && is_string($json['context'])
            ? $json['context']
            : '';
        $signature = isset($json['signature']) && is_string($json['signature'])
            ? $json['signature']
            : null;

        $factors = null;
        if (isset($json['factors']) && is_array($json['factors'])) {
            $factors = [];
            foreach ($json['factors'] as $name => $value) {
                $factors[(string) $name] = FactorOutcome::fromCloud(
                    is_string($value) ? $value : null
                );
            }
        }

        $verifiedAt = null;
        if (isset($json['verifiedAt']) && is_string($json['verifiedAt'])) {
            $parsed = DateTimeImmutable::createFromFormat(
                self::VERIFIED_AT_FORMAT,
                $json['verifiedAt'],
                new DateTimeZone('UTC')
            );
            $verifiedAt = $parsed === false ? null : $parsed;
        }

        $seconds = null;
        if (isset($json['secondsSinceVerified'])
            && is_numeric($json['secondsSinceVerified'])
        ) {
            $seconds = (int) $json['secondsSinceVerified'];
        }

        return new self(
            ContextOutcome::fromCloud($rawContext),
            $rawContext,
            SignatureOutcome::fromCloud($signature),
            $factors,
            $verifiedAt,
            $seconds,
            $statusCode,
            $body
        );
    }

    /**
     * The result in the cloud's own shape (`signature`, `context`,
     * `factors` when present, `verifiedAt`, `secondsSinceVerified`), for a
     * server that relays a redemption to a page as JSON. Fields the cloud
     * did not send are left out, as the cloud leaves them out.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $array = [];
        if ($this->signature !== SignatureOutcome::Unknown) {
            $array['signature'] = $this->signature->value;
        }
        $array['context'] = $this->context->value;
        if ($this->factors !== null) {
            $factors = [];
            foreach ($this->factors as $name => $outcome) {
                $factors[$name] = $outcome->value;
            }
            $array['factors'] = $factors;
        }
        if ($this->verifiedAt !== null) {
            $array['verifiedAt'] = $this->verifiedAt->format(
                self::VERIFIED_AT_FORMAT
            );
        }
        if ($this->secondsSinceVerified !== null) {
            $array['secondsSinceVerified'] = $this->secondsSinceVerified;
        }
        return $array;
    }
}
