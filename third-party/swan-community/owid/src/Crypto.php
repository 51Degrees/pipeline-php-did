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

use OpenSSLAsymmetricKey;

/**
 * All the public and support methods associated with signing and verification.
 * Nothing to do with the web or HTTP.
 *
 * OWID uses ECDSA with the NIST P-256 curve (also known as secp256r1 or
 * prime256v1) and the SHA-256 hash, as required by the specification. The
 * signature is the 64 byte concatenation of the big endian r and s values.
 *
 * The openssl extension produces and consumes ASN.1 DER signatures, so this
 * class converts between DER and the raw 64 byte form on the way in and out.
 */
final class Crypto
{
    /**
     * The number of bytes in each of the r and s values, and so half the
     * length of a raw signature.
     */
    private const COORDINATE_LENGTH = 32;

    private ?OpenSSLAsymmetricKey $signingKey;
    private ?OpenSSLAsymmetricKey $verifyingKey;

    private function __construct(
        ?OpenSSLAsymmetricKey $signingKey,
        ?OpenSSLAsymmetricKey $verifyingKey
    ) {
        $this->signingKey = $signingKey;
        $this->verifyingKey = $verifyingKey;
    }

    /**
     * Creates a new instance and generates a public and private key pair used
     * to sign and verify OWIDs.
     *
     * @throws OwidException when the key pair can not be generated.
     */
    public static function new(): self
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($key === false) {
            throw OwidException::key(self::lastOpenSslError());
        }
        return new self($key, self::deriveVerifyingKey($key));
    }

    /**
     * Creates a new instance for signing OWIDs from the private key PEM
     * provided. Both PKCS#8 ("PRIVATE KEY") and SEC1 ("EC PRIVATE KEY") PEM
     * forms are accepted. The verifying key is derived from the private key so
     * the instance can also verify.
     *
     * @throws OwidException when the PEM is empty or not a valid P-256 private
     *                       key.
     */
    public static function newSignOnly(string $privatePem): self
    {
        if (trim($privatePem) === '') {
            throw OwidException::key('private key PEM is empty');
        }
        $key = openssl_pkey_get_private($privatePem);
        if ($key === false) {
            throw OwidException::key(self::lastOpenSslError());
        }
        return new self($key, self::deriveVerifyingKey($key));
    }

    /**
     * Creates a new instance for verifying OWIDs from the public key PEM
     * provided in Subject Public Key Info (SPKI) form.
     *
     * @throws OwidException when the PEM is empty or not a valid P-256 public
     *                       key.
     */
    public static function newVerifyOnly(string $publicPem): self
    {
        if (trim($publicPem) === '') {
            throw OwidException::key('public key PEM is empty');
        }
        $key = openssl_pkey_get_public($publicPem);
        if ($key === false) {
            throw OwidException::key(self::lastOpenSslError());
        }
        return new self(null, $key);
    }

    /**
     * Creates an instance for verifying OWIDs from the public key PEM
     * provided, or returns null when the material cannot be read as a public
     * key.
     *
     * Key material arriving from a well known end point is external data, so
     * being unreadable is an operational fault rather than an exceptional one.
     * Answering with null lets the caller report it as InvalidKey, which is
     * what was needed on 30 August 2026 when the end points served PEM a
     * strict parser rejects, because reporting that as an invalid signature
     * would have read as an attack. The reason the material could not be read
     * is deliberately not returned, as the caller has nothing to do with it
     * beyond reporting the key as unusable.
     */
    public static function tryVerifyOnly(string $publicPem): ?self
    {
        try {
            return self::newVerifyOnly($publicPem);
        } catch (OwidException $e) {
            // Catching here costs an exception only when an operator's key is
            // wrong, which is rare and not chosen by whoever sends
            // identifiers, unlike a parse failure.
            return null;
        }
    }

    /**
     * Signs the byte array with the private key and returns the 64 byte
     * signature in the raw r concatenated with s form.
     *
     * @throws OwidException when the instance can not sign or the signing
     *                       operation fails.
     */
    public function signByteArray(string $data): string
    {
        if ($this->signingKey === null) {
            throw OwidException::keyMissing('generate a signature');
        }
        $der = '';
        $result = openssl_sign(
            $data,
            $der,
            $this->signingKey,
            OPENSSL_ALGO_SHA256
        );
        if ($result === false) {
            throw OwidException::key(self::lastOpenSslError());
        }
        $raw = self::derToRaw($der);
        if (strlen($raw) !== OwidException::SIGNATURE_LENGTH) {
            throw OwidException::invalidSignatureLength(strlen($raw));
        }
        return $raw;
    }

    /**
     * Returns true if the signature is valid for the data. A signature of the
     * wrong length raises an exception. A signature of the right length that
     * does not match the data returns false rather than raising.
     *
     * @throws OwidException when the instance can not verify or the signature
     *                       length is wrong.
     */
    public function verifyByteArray(string $data, string $signature): bool
    {
        if ($this->verifyingKey === null) {
            throw OwidException::keyMissing('verify a signature');
        }
        if (strlen($signature) !== OwidException::SIGNATURE_LENGTH) {
            throw OwidException::invalidSignatureLength(strlen($signature));
        }
        return $this->signatureStatus($data, $signature) ===
            SignatureStatus::SignatureValid;
    }

    /**
     * Says whether the signature is genuine for the data, and where the
     * question could not be answered, says that instead.
     *
     * A signature of the wrong length, a key this instance does not hold, or a
     * provider failure each leave the signature unjudged, and none of them is
     * reported as SignatureInvalid, which means only that a well formed
     * signature did not match.
     */
    public function signatureStatus(
        string $data,
        string $signature
    ): SignatureStatus {
        if ($this->verifyingKey === null) {
            return SignatureStatus::InvalidKey;
        }
        if (strlen($signature) !== OwidException::SIGNATURE_LENGTH) {
            return SignatureStatus::InvalidSignatureLength;
        }
        $der = self::rawToDer($signature);
        $result = openssl_verify(
            $data,
            $der,
            $this->verifyingKey,
            OPENSSL_ALGO_SHA256
        );
        // openssl_verify returns 1 for a valid signature, 0 for an invalid
        // signature, and -1 when an error occurs. The error is the provider
        // failing on inputs that were both valid, which says nothing about the
        // identifier and must not be reported as if it did.
        if ($result === -1) {
            self::lastOpenSslError();
            return SignatureStatus::VerificationError;
        }
        return $result === 1
            ? SignatureStatus::SignatureValid
            : SignatureStatus::SignatureInvalid;
    }

    /**
     * Returns the public key in Subject Public Key Info (SPKI) PEM form for
     * use with the well known end points or other implementations.
     *
     * @throws OwidException when the instance has no public key or the export
     *                       fails.
     */
    public function subjectPublicKeyInfo(): string
    {
        if ($this->verifyingKey === null) {
            throw OwidException::keyMissing('export a public key');
        }
        $details = openssl_pkey_get_details($this->verifyingKey);
        if ($details === false || !isset($details['key'])) {
            throw OwidException::key(self::lastOpenSslError());
        }
        return $details['key'];
    }

    /**
     * Returns the public key in PEM form. An alias of
     * subjectPublicKeyInfo.
     *
     * @throws OwidException when the instance has no public key or the export
     *                       fails.
     */
    public function publicKeyPem(): string
    {
        return $this->subjectPublicKeyInfo();
    }

    /**
     * Returns the private key in PKCS#8 PEM form.
     *
     * @throws OwidException when the instance has no private key or the export
     *                       fails.
     */
    public function privateKeyPem(): string
    {
        if ($this->signingKey === null) {
            throw OwidException::keyMissing('export a private key');
        }
        $pem = '';
        $result = openssl_pkey_export($this->signingKey, $pem);
        if ($result === false) {
            throw OwidException::key(self::lastOpenSslError());
        }
        return $pem;
    }

    /**
     * True if the instance can be used to sign OWIDs.
     */
    public function canSign(): bool
    {
        return $this->signingKey !== null;
    }

    /**
     * True if the instance can be used to verify OWIDs.
     */
    public function canVerify(): bool
    {
        return $this->verifyingKey !== null;
    }

    /**
     * Converts a DER encoded ECDSA signature into the raw 64 byte form, the
     * 32 byte big endian r value followed by the 32 byte big endian s value.
     *
     * The DER form is a SEQUENCE holding two INTEGERs. Each INTEGER may carry
     * a leading 0x00 byte when the high bit of the value would otherwise make
     * it negative, and that byte is stripped here. Each value is then left
     * padded with zeros to the coordinate length.
     *
     * @throws OwidException when the DER structure is malformed.
     */
    public static function derToRaw(string $der): string
    {
        $position = 0;
        $length = strlen($der);

        // The outer SEQUENCE.
        if ($position >= $length || ord($der[$position]) !== 0x30) {
            throw OwidException::key('signature is not a DER sequence');
        }
        $position += 1;
        // Consume the SEQUENCE length. The content length is not needed beyond
        // skipping the length bytes because the two INTEGERs are read directly.
        self::readDerLength($der, $position);

        $r = self::readDerInteger($der, $position);
        $s = self::readDerInteger($der, $position);

        return self::padCoordinate($r) . self::padCoordinate($s);
    }

    /**
     * Converts a raw 64 byte signature, the 32 byte big endian r value
     * followed by the 32 byte big endian s value, into a DER encoded ECDSA
     * signature for the openssl verify call.
     *
     * @throws OwidException when the signature is not 64 bytes.
     */
    public static function rawToDer(string $signature): string
    {
        if (strlen($signature) !== OwidException::SIGNATURE_LENGTH) {
            throw OwidException::invalidSignatureLength(strlen($signature));
        }
        $r = substr($signature, 0, self::COORDINATE_LENGTH);
        $s = substr($signature, self::COORDINATE_LENGTH, self::COORDINATE_LENGTH);

        $rInteger = self::encodeDerInteger($r);
        $sInteger = self::encodeDerInteger($s);

        $content = $rInteger . $sInteger;
        return "\x30" . self::encodeDerLength(strlen($content)) . $content;
    }

    /**
     * Reads an ASN.1 length from the buffer at the position given, advancing
     * the position past the length bytes, and returns the length value.
     *
     * @throws OwidException when the length encoding is malformed.
     */
    private static function readDerLength(string $der, int &$position): int
    {
        if ($position >= strlen($der)) {
            throw OwidException::key('signature length is missing');
        }
        $first = ord($der[$position]);
        $position += 1;
        if ($first < 0x80) {
            return $first;
        }
        $byteCount = $first & 0x7F;
        if ($byteCount === 0 || $position + $byteCount > strlen($der)) {
            throw OwidException::key('signature length is malformed');
        }
        $value = 0;
        for ($index = 0; $index < $byteCount; $index += 1) {
            $value = ($value << 8) | ord($der[$position]);
            $position += 1;
        }
        return $value;
    }

    /**
     * Reads a DER INTEGER from the buffer at the position given, advancing the
     * position past it, and returns the big endian value bytes with any
     * leading 0x00 sign byte removed.
     *
     * @throws OwidException when the INTEGER encoding is malformed.
     */
    private static function readDerInteger(string $der, int &$position): string
    {
        if ($position >= strlen($der) || ord($der[$position]) !== 0x02) {
            throw OwidException::key('signature value is not a DER integer');
        }
        $position += 1;
        $length = self::readDerLength($der, $position);
        if ($length <= 0 || $position + $length > strlen($der)) {
            throw OwidException::key('signature value length is malformed');
        }
        $value = substr($der, $position, $length);
        $position += $length;
        // Strip the leading sign byte added so the value reads as positive.
        return ltrim($value, "\x00") === '' ? "\x00" : self::stripSignByte($value);
    }

    /**
     * Removes a single leading 0x00 sign byte when present, leaving the
     * meaningful big endian value.
     */
    private static function stripSignByte(string $value): string
    {
        if (strlen($value) > 1 && $value[0] === "\x00") {
            return substr($value, 1);
        }
        return $value;
    }

    /**
     * Left pads the big endian value with zeros to the coordinate length,
     * trimming any excess leading zeros first.
     *
     * @throws OwidException when the value is wider than the coordinate length.
     */
    private static function padCoordinate(string $value): string
    {
        $trimmed = ltrim($value, "\x00");
        if ($trimmed === '') {
            $trimmed = "\x00";
        }
        if (strlen($trimmed) > self::COORDINATE_LENGTH) {
            throw OwidException::key('signature value is too large');
        }
        return str_pad(
            $trimmed,
            self::COORDINATE_LENGTH,
            "\x00",
            STR_PAD_LEFT
        );
    }

    /**
     * Encodes a big endian value as a DER INTEGER, prepending a 0x00 sign byte
     * when the high bit of the first content byte is set so the value is read
     * as positive.
     */
    private static function encodeDerInteger(string $value): string
    {
        $trimmed = ltrim($value, "\x00");
        if ($trimmed === '') {
            $trimmed = "\x00";
        }
        if ((ord($trimmed[0]) & 0x80) !== 0) {
            $trimmed = "\x00" . $trimmed;
        }
        return "\x02" . self::encodeDerLength(strlen($trimmed)) . $trimmed;
    }

    /**
     * Encodes a length as ASN.1 DER. Short form is used for lengths below 128,
     * which covers every signature value, but the long form is supported for
     * completeness.
     */
    private static function encodeDerLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';
        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Derives a public key handle from a private key handle. The openssl
     * verify call needs a key imported from public key material, so the SPKI
     * PEM is exported from the private key and re-imported as a public key.
     *
     * @throws OwidException when the public key can not be derived.
     */
    private static function deriveVerifyingKey(
        OpenSSLAsymmetricKey $privateKey
    ): OpenSSLAsymmetricKey {
        $details = openssl_pkey_get_details($privateKey);
        if ($details === false || !isset($details['key'])) {
            throw OwidException::key(self::lastOpenSslError());
        }
        $publicKey = openssl_pkey_get_public($details['key']);
        if ($publicKey === false) {
            throw OwidException::key(self::lastOpenSslError());
        }
        return $publicKey;
    }

    /**
     * Returns the most recent openssl error message, draining the error queue.
     */
    private static function lastOpenSslError(): string
    {
        $message = '';
        while (($error = openssl_error_string()) !== false) {
            $message = $error;
        }
        return $message === '' ? 'unknown openssl error' : $message;
    }
}
