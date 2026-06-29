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
 * for Random).
 *
 * The owid-php {@see Owid} is `final`, so this type **composes** an OWID (holds
 * the wrapped envelope and delegates OWID-level concerns to it) rather than
 * inheriting from it. Constructing a {@see FodId} does **not** verify the
 * signature; call {@see FodId::verify()} explicitly. Payload bytes are held as
 * a PHP string, which is immutable, so no defensive copy is required.
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

    private Owid $owid;
    private int $flags;
    private int $licenseId;
    private string $hash;

    /**
     * Promotes an already-parsed {@see Owid} into a 51Did by unpacking its
     * payload.
     *
     * @throws InvalidArgumentException when the payload is shorter than the
     *                                  minimum for its identifier type.
     */
    public function __construct(Owid $owid)
    {
        $this->owid = $owid;
        $payload = $owid->payload;
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
     * Parses a 51Did from its base64-encoded OWID string.
     *
     * @throws \SwanCommunity\Owid\OwidException when the string is not valid
     *                                           base64 or not a valid OWID.
     */
    public static function fromBase64(string $base64): self
    {
        return new self(Owid::fromBase64($base64));
    }

    /**
     * Parses a 51Did from the raw bytes of an OWID envelope.
     *
     * @throws \SwanCommunity\Owid\OwidException when the bytes are not a valid
     *                                           OWID.
     */
    public static function fromByteArray(string $buffer): self
    {
        return new self(Owid::fromByteArray($buffer));
    }

    /** Promotes an already-parsed OWID into a 51Did (alias of the constructor). */
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

    /** The 4-byte little-endian License Id (0 to 4294967295). */
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

    /** The wrapped OWID envelope. */
    public function getOwid(): Owid
    {
        return $this->owid;
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
     * Returns the OWID as a base64 string.
     *
     * @throws \SwanCommunity\Owid\OwidException
     */
    public function asBase64(): string
    {
        return $this->owid->asBase64();
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
