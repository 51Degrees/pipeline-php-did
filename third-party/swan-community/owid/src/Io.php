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

use DateTimeImmutable;
use DateTimeInterface;

/**
 * Low level write helpers for the OWID binary format, and the base date the
 * format counts from. The format uses little endian unsigned 32 bit integers,
 * null terminated strings, and a fixed 64 byte signature. Strings in PHP are
 * byte arrays, so all buffers here are plain strings holding raw bytes.
 *
 * Reading lives in Owid, which walks the buffer by index and reports a status
 * rather than raising, because the bytes come from outside and being malformed
 * is an ordinary outcome for them.
 */
final class Io
{
    /**
     * Unix timestamp of the base date 2020-01-01T00:00:00 UTC. The date and
     * time information is stored as hours or minutes after this date.
     */
    public const BASE_TIMESTAMP = 1577836800;

    /**
     * Returns the base date for OWIDs as a UTC immutable date and time.
     */
    public static function baseDate(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . self::BASE_TIMESTAMP);
    }

    /**
     * Returns the whole minutes from the base date to the date, or -1 where
     * the count cannot be held in the four byte field of versions 2 and 3,
     * being a date before the base or beyond the field. The arithmetic is
     * the one writeDate uses, so the value a fetch names is the value the
     * OWID carries.
     */
    public static function minutesSinceBase(DateTimeInterface $date): int
    {
        $elapsed = $date->getTimestamp() - self::BASE_TIMESTAMP;
        if ($elapsed < 0) {
            return -1;
        }
        $minutes = intdiv($elapsed, 60);
        if ($minutes > 0xFFFFFFFF) {
            return -1;
        }
        return $minutes;
    }

    /**
     * Appends a single byte, given as an unsigned integer, to the buffer.
     */
    public static function writeByte(string &$buffer, int $value): void
    {
        $buffer .= chr($value & 0xFF);
    }

    /**
     * Writes the string followed by the null terminator. The only such string
     * in an OWID is the creator domain. The value must not contain a null
     * character as that would conflict with the terminator, and must not be
     * longer than the greatest number of characters a domain name can hold,
     * because reading stops looking for the terminator at that bound and
     * would refuse anything longer. Without this the library could write an
     * OWID it then refused to read, and the fault would land on whoever read
     * it rather than on the creator that caused it. This is the later of the
     * two write side checks. Since an OWID can only be parsed or created, and
     * both routes are bounded, no OWID can now carry a domain this refuses, so
     * what it guards is a caller writing the format with these helpers
     * directly.
     *
     * @throws OwidException when the value contains a null byte, or is
     *                       longer than a domain name can hold.
     */
    public static function writeString(string &$buffer, string $value): void
    {
        if (strpos($value, "\0") !== false) {
            throw OwidException::invalidDomain($value);
        }
        if (strlen($value) > OwidException::MAXIMUM_DOMAIN_LENGTH) {
            throw OwidException::domainTooLong();
        }
        $buffer .= $value . "\0";
    }

    /**
     * Writes an unsigned 32 bit little endian integer.
     */
    public static function writeUint32(string &$buffer, int $value): void
    {
        $buffer .= pack('V', $value);
    }

    /**
     * Writes a byte array prefixed with its length as an unsigned 32 bit
     * integer.
     *
     * @throws OwidException when the value is longer than the prefix allows.
     */
    public static function writeByteArray(string &$buffer, string $value): void
    {
        $length = strlen($value);
        if ($length > 0xFFFFFFFF) {
            throw OwidException::payloadTooLarge($length);
        }
        self::writeUint32($buffer, $length);
        $buffer .= $value;
    }

    /**
     * Writes the fixed length signature, validating the length.
     *
     * @throws OwidException when the signature is not the required length.
     */
    public static function writeSignature(string &$buffer, string $value): void
    {
        if (strlen($value) !== OwidException::SIGNATURE_LENGTH) {
            throw OwidException::invalidSignatureLength(strlen($value));
        }
        $buffer .= $value;
    }

    /**
     * Writes the date using the encoding associated with the version. The
     * value is truncated to the minute, or the hour for version 1, by the
     * integer arithmetic.
     *
     * @throws OwidException when the version has no date encoding or the date
     *                       falls outside the range the encoding allows.
     */
    public static function writeDate(
        string &$buffer,
        DateTimeImmutable $date,
        Version $version
    ): void {
        $elapsed = $date->getTimestamp() - self::BASE_TIMESTAMP;
        switch ($version) {
            case Version::Version1:
                $hours = intdiv($elapsed, 3600);
                if ($hours < 0 || $hours > 0xFFFF) {
                    throw OwidException::dateOutOfRange();
                }
                $buffer .= pack('n', $hours);
                return;
            case Version::Version2:
            case Version::Version3:
                $minutes = intdiv($elapsed, 60);
                if ($minutes < 0 || $minutes > 0xFFFFFFFF) {
                    throw OwidException::dateOutOfRange();
                }
                self::writeUint32($buffer, $minutes);
                return;
            default:
                throw OwidException::unsupportedVersion($version->asByte());
        }
    }
}
