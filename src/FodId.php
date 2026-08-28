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
use InvalidArgumentException;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\Version;

/**
 * A strongly typed reader for the 51Did (51Degrees Identifier) value returned
 * by the 51Degrees Cloud service.
 *
 * A 51Did is described at three levels. The **51Did** is the identifier as a
 * whole. The **envelope** is the signed {@see Owid} that carries it (version,
 * domain, date, payload, signature), re-issued fresh on every call. The
 * **value** is the stable, comparable part of the payload after the Flags and
 * License Id, exposed via {@see FodId::getHash()}. Two 51Dids for the same
 * inputs share the same value even though their envelopes differ. *Compare
 * values, never envelopes.*
 *
 * Payload layout. The header (offsets 0-4) is shared by every identifier type;
 * bits 6-7 of Flags select the {@see IdType} and the length of the value that
 * follows (32-byte SHA-256 for Probabilistic and HashedEmail, or 16 GUID bytes
 * for Random). An identifier carrying a creator context has a further
 * section after the value, which the reader keeps in the payload and does
 * not interpret.
 *
 * The cloud issues a 51Did in standard base64 with padding, and a page puts
 * one in a link in the URL-safe alphabet without padding, so
 * {@see FodId::fromBase64()} accepts either form and
 * {@see FodId::asBase64Url()} produces the URL-safe one.
 *
 * The owid-php {@see Owid} is `final`, so this type **composes** an OWID (holds
 * the wrapped envelope and delegates OWID-level concerns to it) rather than
 * inheriting from it. The wrapped OWID is **copied** on construction (an Owid
 * is mutable), so a FodId is fully decoupled from the caller's instance and
 * can never desync from its envelope. Constructing a {@see FodId} does **not**
 * verify the signature; call {@see FodId::verify()} explicitly.
 */
final class FodId
{
    /** Byte offset of the Flags field within the payload. */
    public const FLAGS_OFFSET = 0;
    /** Byte offset of the License Id field within the payload. */
    public const LICENSE_ID_OFFSET = 1;
    /** Byte length of the License Id field. */
    public const LICENSE_ID_LENGTH = 4;
    /** Byte offset of the value (Hash) field within the payload. */
    public const HASH_OFFSET = 5;
    /** Byte length of the SHA-256 value. */
    public const HASH_LENGTH = 32;
    /** Byte length of the header (Flags + License Id) common to every type. */
    public const HEADER_LENGTH = self::HASH_OFFSET;
    /** Byte length of the GUID value carried by Random identifiers. */
    public const GUID_LENGTH = 16;
    /** Minimum byte length of a Random 51Did payload. */
    public const RANDOM_PAYLOAD_LENGTH = self::HEADER_LENGTH + self::GUID_LENGTH;
    /** Minimum byte length of a Probabilistic or HashedEmail 51Did payload. */
    public const PAYLOAD_LENGTH = self::HASH_OFFSET + self::HASH_LENGTH;
    /** Largest possible byte length of a serialized 51Did envelope. */
    public const MAXIMUM_BYTE_LENGTH = 136;

    private const MAXIMUM_PAYLOAD_LENGTH = 56;

    private Owid $owid;
    private int $flags;
    private int $licenseId;
    private string $hash;

    /**
     * Promotes an already-parsed {@see Owid} into a 51Did by unpacking its
     * payload.
     *
     * The OWID is **copied** (round-tripped through its byte form), not
     * aliased, so a FodId can never desync from its envelope if the caller
     * later mutates the OWID they passed in. The OWID must therefore be signed
     * (serializable).
     *
     * @throws InvalidArgumentException when the envelope exceeds
     *     {@see FodId::MAXIMUM_BYTE_LENGTH} or its payload length is outside
     *     the range a 51Did can have.
     * @throws \SwanCommunity\Owid\OwidException if the OWID cannot be
     *                                           serialized (e.g. it is unsigned)
     */
    public function __construct(Owid $owid)
    {
        if (strlen($owid->domain) > self::MAXIMUM_BYTE_LENGTH) {
            throw self::tooLong();
        }
        $wire = $owid->asByteArray();
        if (strlen($wire) > self::MAXIMUM_BYTE_LENGTH) {
            throw self::tooLong(strlen($wire));
        }
        if (strlen($owid->payload) > self::MAXIMUM_PAYLOAD_LENGTH) {
            throw self::payloadTooLong(strlen($owid->payload));
        }
        $this->owid = Owid::fromByteArray($wire);
        $payload = $this->owid->payload;
        $length = strlen($payload);
        if ($length < self::HEADER_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                '51Did payload must be at least %d bytes; got %d.',
                self::HEADER_LENGTH,
                $length
            ));
        }
        $this->flags = ord($payload[self::FLAGS_OFFSET]);
        // Little-endian unsigned 32-bit. 'V' yields a non-negative int on
        // 64-bit PHP (max 4294967295 < PHP_INT_MAX), so the high bit never
        // becomes negative.
        $this->licenseId = unpack(
            'V',
            substr($payload, self::LICENSE_ID_OFFSET, self::LICENSE_ID_LENGTH)
        )[1];
        $type = IdType::fromFlags($this->flags);
        $valueLength = match ($type) {
            IdType::Random => self::GUID_LENGTH,
            IdType::Reserved => $length - self::HEADER_LENGTH,
            default => self::HASH_LENGTH,
        };
        if ($length < self::HEADER_LENGTH + $valueLength) {
            throw new InvalidArgumentException(sprintf(
                '51Did payload for the %s type must be at least %d bytes; '
                . 'got %d.',
                $type->name,
                self::HEADER_LENGTH + $valueLength,
                $length
            ));
        }
        $this->hash = substr($payload, self::HASH_OFFSET, $valueLength);
    }

    /**
     * Parses a 51Did from its base64-encoded OWID string, in either the
     * standard alphabet (`+` and `/`, as the cloud issues it) or the URL-safe
     * one (`-` and `_`, as a page puts it in a link), with or without
     * padding. The string is normalised to the standard padded form before
     * decoding, exactly as the cloud's endpoints normalise it.
     *
     * @throws \SwanCommunity\Owid\OwidException when the string is not valid
     *                                           base64 or not a valid OWID.
     * @throws InvalidArgumentException when the decoded envelope is too long.
     */
    public static function fromBase64(string $base64): self
    {
        $standard = self::toStandardBase64($base64);
        $maximumBase64Length = (int) ceil(self::MAXIMUM_BYTE_LENGTH / 3) * 4;
        if (strlen($standard) > $maximumBase64Length) {
            throw self::tooLong();
        }
        return new self(Owid::fromBase64($standard));
    }

    /**
     * Restores a string in either base64 alphabet to the standard alphabet
     * with padding: `-` becomes `+`, `_` becomes `/`, and `==` or `=` is
     * added when the length modulo 4 is 2 or 3. A string already in the
     * standard padded form is returned unchanged.
     */
    public static function toStandardBase64(string $value): string
    {
        $standard = strtr($value, '-_', '+/');
        switch (strlen($standard) % 4) {
            case 2:
                return $standard . '==';
            case 3:
                return $standard . '=';
            default:
                return $standard;
        }
    }

    /**
     * Parses a 51Did from the raw bytes of an OWID envelope.
     *
     * @throws \SwanCommunity\Owid\OwidException when the bytes are not a valid
     *                                           OWID.
     * @throws InvalidArgumentException when the buffer is too long.
     */
    public static function fromByteArray(string $buffer): self
    {
        if (strlen($buffer) > self::MAXIMUM_BYTE_LENGTH) {
            throw self::tooLong(strlen($buffer));
        }
        return new self(Owid::fromByteArray($buffer));
    }

    private static function tooLong(?int $actual = null): InvalidArgumentException
    {
        $detail = $actual === null ? '' : sprintf('; got %d', $actual);
        return new InvalidArgumentException(sprintf(
            'A 51Did must not exceed %d bytes%s.',
            self::MAXIMUM_BYTE_LENGTH,
            $detail
        ));
    }

    private static function payloadTooLong(int $actual): InvalidArgumentException
    {
        return new InvalidArgumentException(sprintf(
            'A 51Did payload must not exceed %d bytes; got %d.',
            self::MAXIMUM_PAYLOAD_LENGTH,
            $actual
        ));
    }

    /**
     * Promotes an already-parsed OWID into a 51Did. The constructor **copies**
     * the OWID (round-tripped through its byte form), not aliases it, so a
     * FodId can never desync from its envelope if the caller later mutates the
     * OWID it passed in. The supplied OWID must therefore be signed
     * (serializable).
     *
     * @throws \SwanCommunity\Owid\OwidException if the OWID cannot be
     *                                           serialized (e.g. it is unsigned)
     * @throws InvalidArgumentException when the envelope is too long.
     */
    public static function fromOwid(Owid $owid): self
    {
        return new self($owid);
    }

    /** The 1-byte usage flags bit-mask from the payload (0-255). */
    public function getFlags(): int
    {
        return $this->flags;
    }

    /** The identifier type carried in bits 6-7 of {@see FodId::getFlags()}. */
    public function getType(): IdType
    {
        return IdType::fromFlags($this->flags);
    }

    /**
     * The 4-byte little-endian License Id field (0 to 4294967295).
     *
     * On an identifier carrying a creator context the four bytes at offset
     * 1 hold an encrypted value that only 51Degrees can turn back into a
     * licence identifier, so this is the field's raw value and identifies
     * nothing outside 51Degrees.
     */
    public function getLicenseId(): int
    {
        return $this->licenseId;
    }

    /**
     * The value bytes (a 32-byte SHA-256, or 16 GUID bytes for Random) as a
     * binary string. This is the stable, comparable part of the envelope - use
     * it as the cache / dedup key.
     */
    public function getHash(): string
    {
        return $this->hash;
    }

    /** The OWID version. */
    public function getVersion(): Version
    {
        return $this->owid->version;
    }

    /** The domain of the OWID creator. */
    public function getDomain(): string
    {
        return $this->owid->domain;
    }

    /** The OWID creation date. */
    public function getDate(): DateTimeImmutable
    {
        return $this->owid->date;
    }

    /**
     * The envelope's own date as the unsigned 32-bit count of minutes since
     * 2020-01-01T00:00:00Z, which is how the wire form carries it. This is
     * the value the OWID `public-key?date=` parameter takes, and the integer
     * to use when comparing creation times.
     */
    public function getDateMinutes(): int
    {
        return intdiv(
            $this->owid->date->getTimestamp() - Io::BASE_TIMESTAMP,
            60
        );
    }

    /** The OWID payload bytes. */
    public function getPayload(): string
    {
        return $this->owid->payload;
    }

    /** The 64-byte OWID signature. */
    public function getSignature(): string
    {
        return $this->owid->signature;
    }

    /**
     * Returns the OWID as a base64 string in the standard alphabet with
     * padding, as the cloud issues it.
     *
     * @throws \SwanCommunity\Owid\OwidException
     */
    public function asBase64(): string
    {
        return $this->owid->asBase64();
    }

    /**
     * Returns the OWID as a base64 string in the URL-safe alphabet (`-` and
     * `_`) without padding, so it can go in a URL without further encoding.
     * {@see FodId::fromBase64()} reads this form back.
     *
     * @throws \SwanCommunity\Owid\OwidException
     */
    public function asBase64Url(): string
    {
        return rtrim(strtr($this->owid->asBase64(), '+/', '-_'), '=');
    }

    /**
     * Returns the OWID as a byte array including the signature.
     *
     * @throws \SwanCommunity\Owid\OwidException
     */
    public function asByteArray(): string
    {
        return $this->owid->asByteArray();
    }

    /**
     * Verifies the OWID signature against the supplied public key. This is an
     * explicit, separate step - construction never verifies.
     *
     * @throws \SwanCommunity\Owid\OwidException
     */
    public function verify(string $publicPem): bool
    {
        return $this->owid->verifyWithPublicKey($publicPem, []);
    }
}
