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

use Exception;

/**
 * The single exception type raised when writing, signing, or configuring a
 * creator. Each named constructor produces a clear message describing what
 * went wrong.
 *
 * Reading is not here. Bytes arriving from outside are read with the try
 * methods on Owid, which report a ParseStatus, because data that is not an
 * OWID is an ordinary outcome and not a fault in the program.
 */
// Not final, so that a subclass can carry more than a message, such as the
// status to report when a key could not be obtained, whilst remaining
// catchable as an OwidException.
class OwidException extends Exception
{
    /**
     * The length in bytes of a valid OWID signature.
     */
    public const SIGNATURE_LENGTH = 64;

    /**
     * The greatest number of characters an OWID domain can hold. RFC 1035
     * section 2.3.4, "Size limits", restricts the total length of a domain
     * name, counting label octets and label length octets, to 255 octets or
     * less. That 255 is the wire format, which spends one length octet on
     * every label and one zero octet on the root, whereas OWID stores the
     * presentation form, the text "example.com", where the dots stand in for
     * the label length octets and the root has no text at all, so exactly
     * two of those 255 octets have no character here and the limit is 253.
     */
    public const MAXIMUM_DOMAIN_LENGTH = 253;

    /**
     * The version has no encoding for the field being written. Only the marker
     * for an absent node has none, as it carries no date, and no OWID can hold
     * that version any more, so this is reached by a caller writing the format
     * with the Io helpers directly. Reading reports an unknown version byte as
     * a ParseStatus rather than raising.
     */
    public static function unsupportedVersion(int $version): self
    {
        return new self("OWID version '$version' not supported");
    }

    /**
     * The signature is not exactly the required number of bytes.
     */
    public static function invalidSignatureLength(int $length): self
    {
        $expected = self::SIGNATURE_LENGTH;
        return new self(
            "signature length '$length' not compatible with '$expected' " .
            "OWID signature length"
        );
    }

    /**
     * The domain is empty, or contains a null character which would conflict
     * with the null terminated string encoding.
     */
    public static function invalidDomain(string $domain): self
    {
        return new self("domain '$domain' is not valid");
    }

    /**
     * The domain handed in for writing is longer than the greatest number of
     * characters a domain name can hold. The same bound on a read is reported
     * as ParseStatus::InvalidDomainEncoding instead, because bytes arriving
     * from outside are data rather than a fault in the program. The domain is
     * not named because a value that long says nothing useful in a log.
     */
    public static function domainTooLong(): self
    {
        $maximum = self::MAXIMUM_DOMAIN_LENGTH;
        return new self(
            "OWID domain is longer than the '$maximum' characters a domain " .
            "name can hold"
        );
    }

    /**
     * The date can not be represented in the encoding used by the version.
     */
    public static function dateOutOfRange(): self
    {
        return new self(
            'date can not be stored in the encoding for the OWID version'
        );
    }

    /**
     * The payload is larger than the unsigned 32 bit length prefix allows.
     */
    public static function payloadTooLarge(int $length): self
    {
        return new self(
            "payload length '$length' exceeds the unsigned 32 bit limit"
        );
    }

    /**
     * A key could not be imported, exported, or used. The message contains the
     * underlying detail.
     */
    public static function key(string $detail): self
    {
        return new self("key operation failed because $detail");
    }

    /**
     * The crypto instance can not be used for the operation requested. For
     * example, an attempt to sign with a verify only instance.
     */
    public static function keyMissing(string $operation): self
    {
        return new self("instance of Crypto cannot be used to $operation");
    }

    /**
     * The format parameter for the public key end point was not the one
     * encoding defined, "spki".
     */
    public static function invalidKeyFormat(string $format): self
    {
        return new self(
            "the only format defined is 'spki', received '$format'"
        );
    }
}
