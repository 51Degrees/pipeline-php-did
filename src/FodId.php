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
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\ParseResult;
use SwanCommunity\Owid\SignatureStatus;
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
 * Payload layout. The header (offsets 0-4) is shared by every identifier
 * type, and bits 6-7 of Flags select the {@see IdType} and the length of the
 * value that follows (32-byte SHA-256 for Probabilistic and HashedEmail, or
 * 16 GUID bytes for Random). An identifier carrying a creator context has a
 * further section after the value, which the reader keeps in the payload and
 * does not interpret. There is no upper bound on the payload here, because
 * the lengths of that section belong to the cloud and an older reader has to
 * keep accepting an identifier from a newer one.
 *
 * Reading is two steps. The OWID library reads the envelope and this class
 * then reads the payload inside it. The `try` factories,
 * {@see FodId::tryFromBase64()}, {@see FodId::tryFromByteArray()} and
 * {@see FodId::tryFromOwid()}, answer with a {@see FodIdParseResult} rather
 * than raising, because the value arrives from outside and failing to be a
 * 51Did is an ordinary outcome, and whoever sends the value chooses how often
 * that happens. The older factories, {@see FodId::fromBase64()},
 * {@see FodId::fromByteArray()}, {@see FodId::fromOwid()} and the
 * constructor, raise for the same inputs and are kept for callers written
 * against them. Both run the same checks.
 *
 * The cloud issues a 51Did in standard base64 with padding, and a page puts
 * one in a link in the URL-safe alphabet without padding, so the base64
 * factories accept either form and {@see FodId::asBase64Url()} produces the
 * URL-safe one.
 *
 * The owid-php {@see Owid} is `final`, so this type **composes** an OWID
 * (holds the envelope and delegates OWID-level concerns to it) rather than
 * inheriting from it. An OWID only exists once it has been read or signed
 * and its fields are read only, so the one handed in is held as it is.
 * Reading a {@see FodId} does **not** verify the signature, and a parsed
 * 51Did is not necessarily genuine. Call {@see FodId::verify()} or
 * {@see FodId::signatureStatus()} explicitly.
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
     * Promotes an already-read {@see Owid} into a 51Did by unpacking its
     * payload.
     *
     * A payload must be at least the base length for its identifier type.
     * Anything beyond the base is a creator context section, whose exact
     * lengths belong to the cloud, so any longer payload is accepted here.
     * {@see FodId::tryFromOwid()} answers with a status where this raises.
     *
     * @throws InvalidArgumentException when the payload is shorter than the
     *                                  header, or than the minimum for its
     *                                  identifier type.
     */
    public function __construct(Owid $owid)
    {
        $read = self::readPayload($owid->payload);
        if ($read instanceof FodIdParseStatus) {
            throw new InvalidArgumentException(
                self::describe($read, $owid->payload)
            );
        }
        $this->owid = $owid;
        [$this->flags, $this->licenseId, $this->hash] = $read;
    }

    /**
     * Reads a 51Did from its base64-encoded OWID string, answering rather
     * than raising when the value is not one.
     *
     * The value may be anything at all, because it is external data, so a
     * null, an empty string or a value of another type (for example the
     * array PHP builds when a query string repeats a parameter with
     * brackets) is reported by status rather than raised. A string in
     * either alphabet is accepted, standard (`+` and `/`, as the cloud
     * issues it) or URL-safe (`-` and `_`, as a page puts it in a link),
     * with or without padding, and surrounding whitespace is removed, as
     * the cloud's endpoints normalise the alphabet and the padding.
     *
     * The result carries the OWID library's own status when the envelope
     * could not be read, and {@see FodIdParseStatus::PayloadTooShort} or
     * {@see FodIdParseStatus::InvalidTypePayloadLength} when the envelope
     * was sound and the payload does not fit a 51Did. Success says nothing
     * about the signature.
     *
     * @param mixed $value the base64 text, or anything a caller was handed
     */
    public static function tryFromBase64(mixed $value): FodIdParseResult
    {
        if (is_string($value)) {
            $value = self::toStandardBase64($value);
        }
        return self::fromEnvelope(Owid::tryFromBase64($value));
    }

    /**
     * Reads a 51Did from the raw bytes of an OWID envelope, answering
     * rather than raising when the bytes are not one. The buffer must be
     * one whole envelope and nothing else. The statuses are those of
     * {@see FodId::tryFromBase64()} less the base64 one.
     *
     * @param mixed $buffer the raw bytes, or anything a caller was handed
     */
    public static function tryFromByteArray(mixed $buffer): FodIdParseResult
    {
        return self::fromEnvelope(Owid::tryFromByteArray($buffer));
    }

    /**
     * Reads a 51Did from an already-read {@see Owid}, answering
     * {@see FodIdParseStatus::PayloadTooShort} or
     * {@see FodIdParseStatus::InvalidTypePayloadLength} rather than raising
     * when the payload does not fit.
     */
    public static function tryFromOwid(Owid $owid): FodIdParseResult
    {
        $read = self::readPayload($owid->payload);
        if ($read instanceof FodIdParseStatus) {
            return FodIdParseResult::failed($read);
        }
        return FodIdParseResult::parsed(new self($owid));
    }

    /**
     * Parses a 51Did from its base64-encoded OWID string, in either
     * alphabet, with or without padding, and raises when the value is not
     * one. {@see FodId::tryFromBase64()} answers with a status for the same
     * inputs and is the surface to use for values arriving from outside.
     *
     * @throws OwidException when the string is not valid base64 or not a
     *                       valid OWID, with the message naming the OWID
     *                       library's status.
     * @throws InvalidArgumentException when the envelope is sound and the
     *                                  payload does not fit a 51Did.
     */
    public static function fromBase64(string $base64): self
    {
        return new self(self::envelopeOrThrow(
            Owid::tryFromBase64(self::toStandardBase64($base64))
        ));
    }

    /**
     * Restores a string in either base64 alphabet to the standard alphabet
     * with padding. Leading and trailing whitespace is removed first, since
     * a value read from a header, a file or a form often carries a newline
     * and the padding has to be counted from the characters that remain.
     * Then `-` becomes `+`, `_` becomes `/`, and `==` or `=` is added when
     * the length modulo 4 is 2 or 3. A string already in the standard
     * padded form is returned unchanged.
     */
    public static function toStandardBase64(string $value): string
    {
        $standard = strtr(trim($value), '-_', '+/');
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
     * Parses a 51Did from the raw bytes of an OWID envelope and raises when
     * the bytes are not one. {@see FodId::tryFromByteArray()} answers with a
     * status for the same inputs.
     *
     * @throws OwidException when the bytes are not a valid OWID, with the
     *                       message naming the OWID library's status.
     * @throws InvalidArgumentException when the envelope is sound and the
     *                                  payload does not fit a 51Did.
     */
    public static function fromByteArray(string $buffer): self
    {
        return new self(self::envelopeOrThrow(Owid::tryFromByteArray($buffer)));
    }

    /**
     * Promotes an already-read OWID into a 51Did, raising when its payload
     * does not fit. The same as the constructor, kept as the named form.
     *
     * @throws InvalidArgumentException when the payload is shorter than the
     *                                  header, or than the minimum for its
     *                                  identifier type.
     */
    public static function fromOwid(Owid $owid): self
    {
        return new self($owid);
    }

    /**
     * Continues a read from the OWID library's answer. A failed envelope
     * read is passed on with the library's status exactly as reported, so
     * nothing about it is mapped down or renamed, and only a sound envelope
     * goes on to the payload checks.
     */
    private static function fromEnvelope(ParseResult $result): FodIdParseResult
    {
        if (!$result->ok) {
            return FodIdParseResult::failed($result->status);
        }
        return self::tryFromOwid($result->owid);
    }

    /**
     * The OWID from the library's answer, or the exception the throwing
     * factories have always documented. The library itself no longer raises
     * on reading, so the exception is made here, carrying the library's
     * status name, to keep the catch blocks of existing callers working.
     *
     * @throws OwidException when the envelope could not be read.
     */
    private static function envelopeOrThrow(ParseResult $result): Owid
    {
        if (!$result->ok) {
            throw new OwidException(
                'The value is not a valid OWID envelope ('
                . $result->status->value . ').'
            );
        }
        return $result->owid;
    }

    /**
     * Reads the header and the value from a payload, or names why the
     * payload does not fit a 51Did. This is the one place the payload rules
     * live, so the raising and the answering surfaces cannot drift apart.
     *
     * The header must be present before the type can be read, and the type
     * then says how many value bytes must follow. A Reserved identifier
     * takes whatever follows the header, which is the existing best-effort
     * reading of a type not yet assigned. Anything after the value is a
     * creator context section and is left in the payload unread.
     *
     * @return array{int, int, string}|FodIdParseStatus the flags, the licence
     *     id and the value bytes, or the reason the payload does not fit
     */
    private static function readPayload(string $payload): array|FodIdParseStatus
    {
        $length = strlen($payload);
        if ($length < self::HEADER_LENGTH) {
            return FodIdParseStatus::PayloadTooShort;
        }
        $flags = ord($payload[self::FLAGS_OFFSET]);
        $valueLength = self::valueLength(IdType::fromFlags($flags), $length);
        if ($length < self::HEADER_LENGTH + $valueLength) {
            return FodIdParseStatus::InvalidTypePayloadLength;
        }
        // Little-endian unsigned 32-bit. 'V' yields a non-negative int on
        // 64-bit PHP (max 4294967295 < PHP_INT_MAX), so the high bit never
        // becomes negative.
        $licenseId = unpack(
            'V',
            substr($payload, self::LICENSE_ID_OFFSET, self::LICENSE_ID_LENGTH)
        )[1];
        return [
            $flags,
            $licenseId,
            substr($payload, self::HASH_OFFSET, $valueLength),
        ];
    }

    /**
     * The number of value bytes the type requires after the header, given
     * the payload length for the Reserved case, which takes the remainder.
     */
    private static function valueLength(IdType $type, int $payloadLength): int
    {
        return match ($type) {
            IdType::Random => self::GUID_LENGTH,
            IdType::Reserved => $payloadLength - self::HEADER_LENGTH,
            default => self::HASH_LENGTH,
        };
    }

    /**
     * The message for the exception the raising surfaces carry when a
     * payload does not fit, naming the status and the byte counts.
     */
    private static function describe(
        FodIdParseStatus $status,
        string $payload
    ): string {
        $length = strlen($payload);
        if ($status === FodIdParseStatus::PayloadTooShort) {
            return sprintf(
                '51Did payload must be at least %d bytes and %d were given '
                . '(%s).',
                self::HEADER_LENGTH,
                $length,
                $status->value
            );
        }
        $type = IdType::fromFlags(ord($payload[self::FLAGS_OFFSET]));
        return sprintf(
            '51Did payload for the %s type must be at least %d bytes and %d '
            . 'were given (%s).',
            $type->name,
            self::HEADER_LENGTH + self::valueLength($type, $length),
            $length,
            $status->value
        );
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
     * binary string. This is the stable, comparable part of the envelope, so
     * use it as the cache and dedup key.
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
     * @throws OwidException
     */
    public function asBase64(): string
    {
        return $this->owid->asBase64();
    }

    /**
     * Returns the OWID as a base64 string in the URL-safe alphabet (`-` and
     * `_`) without padding, so it can go in a URL without further encoding.
     * {@see FodId::fromBase64()} and {@see FodId::tryFromBase64()} read this
     * form back.
     *
     * @throws OwidException
     */
    public function asBase64Url(): string
    {
        return rtrim(strtr($this->owid->asBase64(), '+/', '-_'), '=');
    }

    /**
     * Returns the OWID as a byte array including the signature.
     *
     * @throws OwidException
     */
    public function asByteArray(): string
    {
        return $this->owid->asByteArray();
    }

    /**
     * Verifies the OWID signature against the supplied public key. This is
     * an explicit, separate step, as reading never verifies. False means
     * the signature does not match this key, and a key that cannot be read
     * is raised rather than reported as a mismatch. Where the difference
     * between the two changes what the caller does, use
     * {@see FodId::signatureStatus()}.
     *
     * @throws OwidException when the PEM is not a valid public key.
     */
    public function verify(string $publicPem): bool
    {
        return $this->owid->verifyWithPublicKey($publicPem, []);
    }

    /**
     * Says whether the signature is genuine for the public key given, and
     * where the question could not be answered, says that instead of
     * reporting a forgery. {@see SignatureStatus::SignatureInvalid} is the
     * only answer that means the identifier should be distrusted, and a key
     * that cannot be read is {@see SignatureStatus::InvalidKey}.
     */
    public function signatureStatus(string $publicPem): SignatureStatus
    {
        return $this->owid->signatureStatus($publicPem, []);
    }
}
