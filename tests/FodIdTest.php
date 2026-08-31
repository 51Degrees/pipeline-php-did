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

namespace fiftyone\pipeline\did\tests;

use DateTimeImmutable;
use fiftyone\pipeline\did\FodId;
use fiftyone\pipeline\did\FodIdParseResult;
use fiftyone\pipeline\did\FodIdParseStatus;
use fiftyone\pipeline\did\IdType;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\OwidException;
use SwanCommunity\Owid\ParseStatus;
use SwanCommunity\Owid\SignatureStatus;
use TypeError;

class FodIdTest extends TestCase
{
    private const TEST_DOMAIN = '51degrees.com';
    // 0xA5: usage bits plus the HashedEmail type tag in bits 6-7.
    private const CANONICAL_FLAGS = 0xA5;
    private const CANONICAL_LICENSE_ID = 0x12345678;

    private Crypto $crypto;
    private Creator $creator;
    private string $publicPem;

    protected function setUp(): void
    {
        $this->crypto = Crypto::new();
        $this->publicPem = $this->crypto->publicKeyPem();
        $this->creator = new Creator(self::TEST_DOMAIN, $this->crypto);
    }

    // ----- Helpers -----

    private static function canonicalHash(): string
    {
        $hash = '';
        for ($i = 0; $i < FodId::HASH_LENGTH; $i++) {
            $hash .= chr(0x20 + $i);
        }
        return $hash;
    }

    private static function canonicalPayload(): string
    {
        return chr(self::CANONICAL_FLAGS)
            . pack('V', self::CANONICAL_LICENSE_ID)
            . self::canonicalHash();
    }

    private static function canonicalGuid(): string
    {
        $guid = '';
        for ($i = 0; $i < FodId::GUID_LENGTH; $i++) {
            $guid .= chr(0x40 + $i);
        }
        return $guid;
    }

    private static function canonicalRandomPayload(): string
    {
        return chr((1 << 6) | 0b001)            // Random tag + usage bits
            . pack('V', self::CANONICAL_LICENSE_ID)
            . self::canonicalGuid();
    }

    /**
     * A creator domain longer than the public cloud's, as a self-hosted
     * container deployed under its own name would sign with.
     */
    private static function longDomain(): string
    {
        return str_repeat('creator-context-', 8) . 'example.com';
    }

    /** A signed envelope over the payload, by the only route that signs. */
    private function signedOwid(string $payload): Owid
    {
        return $this->creator->create($payload);
    }

    private function signedOwidBase64(string $payload): string
    {
        return $this->signedOwid($payload)->asBase64();
    }

    /** A signed envelope dated as given, for tests that compare dates. */
    private function signedOwidAt(
        DateTimeImmutable $date,
        string $payload
    ): Owid {
        return Envelopes::owid($this->crypto, self::TEST_DOMAIN, $date, $payload);
    }

    /**
     * The three facts of a successful read, asserted together every time
     * so that no test checks one and assumes the others.
     */
    private function assertParsed(FodIdParseResult $result): FodId
    {
        $this->assertTrue($result->ok);
        $this->assertInstanceOf(FodId::class, $result->fodId);
        $this->assertSame(ParseStatus::Parsed, $result->status);
        return $result->fodId;
    }

    /**
     * The three facts of a failed read. The status is compared by identity,
     * so an OWID status must be the library's own enum case and not a copy
     * or a renaming of it.
     */
    private function assertFailed(
        FodIdParseResult $result,
        ParseStatus|FodIdParseStatus $status
    ): void {
        $this->assertFalse($result->ok);
        $this->assertNull($result->fodId);
        $this->assertSame($status, $result->status);
    }

    // ----- Current .NET coverage -----

    public function testConstantsAreInternallyConsistent(): void
    {
        $this->assertSame(
            FodId::PAYLOAD_LENGTH,
            FodId::HASH_OFFSET + FodId::HASH_LENGTH
        );
        $this->assertSame(
            FodId::HASH_OFFSET,
            FodId::LICENSE_ID_OFFSET + FodId::LICENSE_ID_LENGTH
        );
        $this->assertSame(
            FodId::RANDOM_PAYLOAD_LENGTH,
            FodId::HASH_OFFSET + FodId::GUID_LENGTH
        );
    }

    public function testExposesOwidLevelFields(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        // OWID-level concerns are delegated to the wrapped envelope.
        $this->assertSame(self::TEST_DOMAIN, $fod->getDomain());
        $this->assertNotNull($fod->getVersion());
    }

    public function testFromBase64UnpacksAllThreeFields(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame(self::TEST_DOMAIN, $fod->getDomain());
    }

    public function testFromByteArrayUnpacksAllThreeFields(): void
    {
        $buffer = $this->signedOwid(self::canonicalPayload())->asByteArray();
        $fod = FodId::fromByteArray($buffer);
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame(self::TEST_DOMAIN, $fod->getDomain());
    }

    public function testFromOwidUnpacksAllThreeFields(): void
    {
        $owid = $this->signedOwid(self::canonicalPayload());
        $fod = FodId::fromOwid($owid);
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame($owid->domain, $fod->getDomain());
        $this->assertSame($owid->date, $fod->getDate());
        $this->assertSame($owid->version, $fod->getVersion());
        $this->assertSame($owid->payload, $fod->getPayload());
        $this->assertSame($owid->signature, $fod->getSignature());
    }

    public function testConstructorUnpacksAllThreeFields(): void
    {
        // The public constructor is the same read as fromOwid.
        $owid = $this->signedOwid(self::canonicalPayload());
        $fod = new FodId($owid);
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame($owid->asByteArray(), $fod->asByteArray());
    }

    public function testNullOwidThrows(): void
    {
        $this->expectException(TypeError::class);
        // @phpstan-ignore-next-line - deliberately passing null to a typed param
        FodId::fromOwid(null);
    }

    public function testLicenseIdIsLittleEndian(): void
    {
        $payload = self::canonicalPayload();
        $payload[FodId::LICENSE_ID_OFFSET] = "\x01";
        $payload[FodId::LICENSE_ID_OFFSET + 1] = "\x00";
        $payload[FodId::LICENSE_ID_OFFSET + 2] = "\x00";
        $payload[FodId::LICENSE_ID_OFFSET + 3] = "\x00";
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(1, $fod->getLicenseId());
    }

    public function testLicenseIdMaxValue(): void
    {
        $payload = self::canonicalPayload();
        for ($i = 0; $i < 4; $i++) {
            $payload[FodId::LICENSE_ID_OFFSET + $i] = "\xFF";
        }
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(4294967295, $fod->getLicenseId());
    }

    public function testLicenseIdHighBitStaysUnsigned(): void
    {
        $payload = self::canonicalPayload();
        $payload[FodId::LICENSE_ID_OFFSET] = "\x00";
        $payload[FodId::LICENSE_ID_OFFSET + 1] = "\x00";
        $payload[FodId::LICENSE_ID_OFFSET + 2] = "\x00";
        $payload[FodId::LICENSE_ID_OFFSET + 3] = "\x80";
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(0x80000000, $fod->getLicenseId());
    }

    public function testFlagsZeroValueExposed(): void
    {
        $payload = self::canonicalPayload();
        $payload[FodId::FLAGS_OFFSET] = "\x00";
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(0, $fod->getFlags());
    }

    public function testFlagsAllBitsSetExposed(): void
    {
        $payload = self::canonicalPayload();
        $payload[FodId::FLAGS_OFFSET] = "\xFF";
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(255, $fod->getFlags());
    }

    public function testHashIsImmutableValue(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $hash = $fod->getHash();
        $hash[0] = "\x00";  // copy-on-write; must not affect the FodId
        $this->assertSame(self::canonicalHash(), $fod->getHash());
    }

    public function testPayloadOneByteShortThrows(): void
    {
        $base64 = $this->signedOwidBase64(str_repeat("\x00", FodId::PAYLOAD_LENGTH - 1));
        $this->expectException(InvalidArgumentException::class);
        FodId::fromBase64($base64);
    }

    public function testPayloadEmptyThrows(): void
    {
        $base64 = $this->signedOwidBase64('');
        $this->expectException(InvalidArgumentException::class);
        FodId::fromBase64($base64);
    }

    public function testNullBase64Throws(): void
    {
        $this->expectException(TypeError::class);
        // @phpstan-ignore-next-line
        FodId::fromBase64(null);
    }

    public function testNullBufferThrows(): void
    {
        $this->expectException(TypeError::class);
        // @phpstan-ignore-next-line
        FodId::fromByteArray(null);
    }

    public function testInvalidBase64Throws(): void
    {
        $this->expectException(OwidException::class);
        FodId::fromBase64('This is not valid Base64!@#$');
    }

    public function testPayloadLargerThanSpecUsesFirst37Bytes(): void
    {
        $payload = self::canonicalPayload() . str_repeat("\xCC", 27); // 64 bytes
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame(FodId::HASH_LENGTH, strlen($fod->getHash()));
    }

    public function testLongDomainAndLongContextSectionAreRead(): void
    {
        // The creator domain is a deployment parameter, and a context
        // section of a version the reader does not implement may be any
        // length, so neither may stop an identifier parsing.
        $domain = self::longDomain();
        $payload = self::canonicalPayload() . str_repeat("\xCC", 200);
        $owid = (new Creator($domain, $this->crypto))->create($payload);
        foreach ([
            FodId::fromOwid($owid),
            FodId::fromByteArray($owid->asByteArray()),
            FodId::fromBase64($owid->asBase64()),
        ] as $fod) {
            $this->assertSame($domain, $fod->getDomain());
            $this->assertSame($payload, $fod->getPayload());
            $this->assertSame(self::canonicalHash(), $fod->getHash());
        }
    }

    public function testIsCryptographicallyVerifiable(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $this->assertTrue($fod->verify($this->publicPem));
        $this->assertSame(
            SignatureStatus::SignatureValid,
            $fod->signatureStatus($this->publicPem)
        );
    }

    public function testBase64RoundtripPreservesAllFields(): void
    {
        $fod1 = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $fod2 = FodId::fromBase64($fod1->asBase64());
        $this->assertSame($fod1->getFlags(), $fod2->getFlags());
        $this->assertSame($fod1->getLicenseId(), $fod2->getLicenseId());
        $this->assertSame($fod1->getHash(), $fod2->getHash());
        $this->assertSame($fod1->getDomain(), $fod2->getDomain());
    }

    // ----- Type model -----

    public function testTypeDecodedFromTopTwoFlagBits(): void
    {
        $this->assertSame(IdType::Probabilistic, $this->typeFor(0b0000_0101));
        $this->assertSame(IdType::HashedEmail, $this->typeFor(0b1000_0101));
        $this->assertSame(IdType::Reserved, $this->typeFor(0b1100_0101));
    }

    private function typeFor(int $flags): IdType
    {
        $payload = self::canonicalPayload();
        $payload[FodId::FLAGS_OFFSET] = chr($flags);
        return FodId::fromBase64($this->signedOwidBase64($payload))->getType();
    }

    public function testTypeRandomWhenBits01(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalRandomPayload()));
        $this->assertSame(IdType::Random, $fod->getType());
    }

    public function testRandomPayload21BytesParses(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalRandomPayload()));
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(FodId::GUID_LENGTH, strlen($fod->getHash()));
        $this->assertSame(self::canonicalGuid(), $fod->getHash());
    }

    public function testRandomPayloadOneByteShortThrows(): void
    {
        $payload = substr(self::canonicalRandomPayload(), 0, FodId::RANDOM_PAYLOAD_LENGTH - 1);
        $base64 = $this->signedOwidBase64($payload);
        $this->expectException(InvalidArgumentException::class);
        FodId::fromBase64($base64);
    }

    public function testRandomPayloadLargerThanSpecUsesFirst16ValueBytes(): void
    {
        $payload = self::canonicalRandomPayload()
            . str_repeat("\xCC", FodId::PAYLOAD_LENGTH - FodId::RANDOM_PAYLOAD_LENGTH);
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(IdType::Random, $fod->getType());
        $this->assertSame(FodId::GUID_LENGTH, strlen($fod->getHash()));
    }

    public function testHashedEmailPayloadOneByteShortThrows(): void
    {
        $payload = substr(self::canonicalPayload(), 0, FodId::PAYLOAD_LENGTH - 1);
        $base64 = $this->signedOwidBase64($payload);
        $this->expectException(InvalidArgumentException::class);
        FodId::fromBase64($base64);
    }

    public function testReservedHeaderOnlyParses(): void
    {
        $payload = chr(0b1100_0000) . str_repeat("\x00", FodId::HASH_OFFSET - 1);
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(IdType::Reserved, $fod->getType());
        $this->assertSame(0, strlen($fod->getHash()));
        // The answering surface agrees, as Reserved keeps its best-effort
        // reading and never reports a type length.
        $read = $this->assertParsed(FodId::tryFromBase64(
            $this->signedOwidBase64($payload)
        ));
        $this->assertSame(IdType::Reserved, $read->getType());
    }

    // ----- Gap tests (runbook section 6b) -----

    public function testCompareTwo51DidsSamePayload(): void
    {
        // Two reissues of the same value at different times.
        $payload = self::canonicalPayload();
        $a = $this->signedOwidAt(
            new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            $payload
        );
        $b = $this->signedOwidAt(
            new DateTimeImmutable('2026-01-01T00:05:00+00:00'),
            $payload
        );

        $fa = FodId::fromBase64($a->asBase64());
        $fb = FodId::fromBase64($b->asBase64());

        $this->assertSame($fa->getHash(), $fb->getHash());        // value stable
        $this->assertNotEquals($fa->getDate(), $fb->getDate());   // envelope differs
        $this->assertNotSame($fa->getSignature(), $fb->getSignature());
        $this->assertNotSame($a->asBase64(), $b->asBase64());
    }

    public function testConstructionDoesNotVerify(): void
    {
        // An envelope with a present but tampered (invalid) signature still
        // reads and exposes all three fields, because reading must not
        // verify.
        $raw = $this->signedOwid(self::canonicalPayload())->asByteArray();
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\xFF"; // corrupt sig
        $fod = FodId::fromByteArray($raw);
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertFalse($fod->verify($this->publicPem));
    }

    public function testVerifyWithWrongKeyReturnsFalse(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $otherPublicPem = Crypto::new()->publicKeyPem();
        $this->assertFalse($fod->verify($otherPublicPem));
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            $fod->signatureStatus($otherPublicPem)
        );
    }

    public function testRoundtripThroughBytesConstructorPreservesAllFields(): void
    {
        $fod1 = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $fod2 = FodId::fromByteArray($fod1->asByteArray());
        $this->assertSame($fod1->getFlags(), $fod2->getFlags());
        $this->assertSame($fod1->getLicenseId(), $fod2->getLicenseId());
        $this->assertSame($fod1->getHash(), $fod2->getHash());
        $this->assertSame($fod1->getDomain(), $fod2->getDomain());
    }

    // ----- Both base64 alphabets, asBase64Url and getDateMinutes -----

    /**
     * A signed envelope whose standard base64 form contains at least one
     * of the two characters the URL-safe alphabet replaces, so the forms
     * under test are distinct strings. Signatures are random, so a few
     * attempts may be needed.
     */
    private function envelopeWithAlphabetCharacters(): string
    {
        for ($attempt = 0; $attempt < 100; $attempt++) {
            $standard = $this->signedOwidBase64(self::canonicalPayload());
            if (strpbrk($standard, '+/') !== false) {
                return $standard;
            }
        }
        $this->fail('No envelope with + or / after 100 attempts.');
    }

    public function testFromBase64AcceptsStandardUrlSafeAndUnpaddedForms(): void
    {
        $standard = $this->envelopeWithAlphabetCharacters();
        $urlSafe = strtr($standard, '+/', '-_');
        $unpadded = rtrim($urlSafe, '=');
        $this->assertNotSame($standard, $urlSafe);

        $fromStandard = FodId::fromBase64($standard);
        $fromUrlSafe = FodId::fromBase64($urlSafe);
        $fromUnpadded = FodId::fromBase64($unpadded);
        $this->assertSame($fromStandard->asByteArray(), $fromUrlSafe->asByteArray());
        $this->assertSame($fromStandard->asByteArray(), $fromUnpadded->asByteArray());
        $this->assertSame(self::canonicalHash(), $fromUnpadded->getHash());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fromUnpadded->getLicenseId());

        // The answering surface normalises the same way.
        foreach ([$standard, $urlSafe, $unpadded] as $form) {
            $read = $this->assertParsed(FodId::tryFromBase64($form));
            $this->assertSame($fromStandard->asByteArray(), $read->asByteArray());
        }
    }

    public function testToStandardBase64RestoresAlphabetAndPadding(): void
    {
        $standard = $this->envelopeWithAlphabetCharacters();
        $unpadded = rtrim(strtr($standard, '+/', '-_'), '=');
        $this->assertSame($standard, FodId::toStandardBase64($unpadded));
        $this->assertSame($standard, FodId::toStandardBase64($standard));
        $this->assertSame('QQ==', FodId::toStandardBase64('QQ'));
        $this->assertSame('QUI=', FodId::toStandardBase64('QUI'));
        $this->assertSame('QUJD', FodId::toStandardBase64('QUJD'));
    }

    public function testSurroundingWhitespaceIsIgnored(): void
    {
        // A value read from a header, a file or a form often carries a
        // newline or a space, and base64 decoding skips those, so the
        // padding has to be counted from the trimmed string.
        $standard = $this->envelopeWithAlphabetCharacters();
        $clean = rtrim(strtr($standard, '+/', '-_'), '=');
        $expected = FodId::fromBase64($clean)->asByteArray();
        foreach ([$clean . "\n", ' ' . $clean, $clean . ' '] as $given) {
            $this->assertSame(
                $expected,
                FodId::fromBase64($given)->asByteArray()
            );
            $this->assertSame(
                $expected,
                $this->assertParsed(FodId::tryFromBase64($given))->asByteArray()
            );
        }
        $this->assertSame($standard, FodId::toStandardBase64($clean . "\n"));
    }

    public function testAsBase64UrlRoundTrips(): void
    {
        $standard = $this->envelopeWithAlphabetCharacters();
        $fod = FodId::fromBase64($standard);
        $urlSafe = $fod->asBase64Url();
        $this->assertSame(0, preg_match('#[+/=]#', $urlSafe));
        $this->assertSame(rtrim(strtr($standard, '+/', '-_'), '='), $urlSafe);
        $again = FodId::fromBase64($urlSafe);
        $this->assertSame($fod->asByteArray(), $again->asByteArray());
        $this->assertSame($standard, $again->asBase64());
    }

    public function testDateMinutesEqualsTheEnvelopeDateField(): void
    {
        $minutes = 3456789;
        $date = new DateTimeImmutable('@' . (Io::BASE_TIMESTAMP + $minutes * 60));
        $fod = FodId::fromOwid($this->signedOwidAt($date, self::canonicalPayload()));
        $this->assertSame($minutes, $fod->getDateMinutes());
        // The wire form carries the same value little-endian after the
        // version byte and the null-terminated domain.
        $offset = 1 + strlen(self::TEST_DOMAIN) + 1;
        $this->assertSame(
            $minutes,
            unpack('V', substr($fod->asByteArray(), $offset, 4))[1]
        );
    }

    public function testDateMinutesIsZeroAtTheBaseDate(): void
    {
        $date = new DateTimeImmutable('@' . Io::BASE_TIMESTAMP);
        $fod = FodId::fromOwid($this->signedOwidAt($date, self::canonicalPayload()));
        $this->assertSame(0, $fod->getDateMinutes());
    }

    public function testContextSectionIsKeptInThePayload(): void
    {
        // A creator context identifier is longer than the base and the
        // reader must keep accepting it, with the section after the value.
        $section = "\x00" . str_repeat("\xAB", 18);
        $payload = self::canonicalPayload() . $section;
        $fod = FodId::fromBase64($this->signedOwidBase64($payload));
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame($payload, $fod->getPayload());
        $this->assertSame($section, substr($fod->getPayload(), FodId::PAYLOAD_LENGTH));
    }

    // ----- Reading without raising (runbook Phase 5) -----

    public function testTryFromBase64ParsesACanonicalIdentifier(): void
    {
        $owid = $this->signedOwid(self::canonicalPayload());
        $fod = $this->assertParsed(FodId::tryFromBase64($owid->asBase64()));
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame(IdType::HashedEmail, $fod->getType());
        $this->assertSame(self::TEST_DOMAIN, $fod->getDomain());
        $this->assertSame($owid->asByteArray(), $fod->asByteArray());
    }

    public function testTryFromByteArrayParsesACanonicalIdentifier(): void
    {
        $owid = $this->signedOwid(self::canonicalRandomPayload());
        $fod = $this->assertParsed(FodId::tryFromByteArray($owid->asByteArray()));
        $this->assertSame(IdType::Random, $fod->getType());
        $this->assertSame(self::canonicalGuid(), $fod->getHash());
        $this->assertSame($owid->asByteArray(), $fod->asByteArray());
    }

    public function testTryFromOwidParsesACanonicalIdentifier(): void
    {
        $owid = $this->signedOwid(self::canonicalPayload());
        $fod = $this->assertParsed(FodId::tryFromOwid($owid));
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertSame($owid->signature, $fod->getSignature());
    }

    public function testTryFromBase64AcceptsALongerSelfHostedCreatorDomain(): void
    {
        $domain = self::longDomain();
        $owid = (new Creator($domain, $this->crypto))->create(self::canonicalPayload());
        foreach ([
            FodId::tryFromBase64($owid->asBase64()),
            FodId::tryFromBase64($owid->asBase64()),
            FodId::tryFromByteArray($owid->asByteArray()),
            FodId::tryFromOwid($owid),
        ] as $result) {
            $fod = $this->assertParsed($result);
            $this->assertSame($domain, $fod->getDomain());
            $this->assertSame(self::canonicalHash(), $fod->getHash());
            $this->assertTrue($fod->verify($this->publicPem));
        }
    }

    public function testTryFromBase64AcceptsALongerCreatorContextSection(): void
    {
        // A context section of a version this reader does not implement
        // may be any length, so an older reader stays forward compatible
        // with identifiers a newer cloud issues.
        $section = "\x00" . str_repeat("\xAB", 200);
        foreach ([
            self::canonicalPayload() . $section,
            self::canonicalRandomPayload() . $section,
        ] as $payload) {
            $owid = $this->signedOwid($payload);
            foreach ([
                FodId::tryFromBase64($owid->asBase64()),
                FodId::tryFromByteArray($owid->asByteArray()),
                FodId::tryFromOwid($owid),
            ] as $result) {
                $fod = $this->assertParsed($result);
                $this->assertSame($payload, $fod->getPayload());
                $this->assertSame(
                    $section,
                    substr($fod->getPayload(), FodId::HEADER_LENGTH + strlen($fod->getHash()))
                );
            }
        }
    }

    public function testALongerPayloadIsNotRejectedForItsLength(): void
    {
        // There is no upper bound in this package. Every length past the
        // base for the type reads, and the value is the same each time.
        foreach ([1, 19, 64, 200, 4096] as $extra) {
            $payload = self::canonicalPayload() . str_repeat("\xCC", $extra);
            $fod = $this->assertParsed(FodId::tryFromBase64(
                $this->signedOwidBase64($payload)
            ));
            $this->assertSame(self::canonicalHash(), $fod->getHash());
            $this->assertSame(FodId::PAYLOAD_LENGTH + $extra, strlen($fod->getPayload()));
        }
    }

    public function testTooShortRandomPayloadReportsInvalidTypePayloadLength(): void
    {
        $random = self::canonicalRandomPayload();
        foreach ([
            FodId::HEADER_LENGTH,               // header only, no value
            FodId::RANDOM_PAYLOAD_LENGTH - 1,   // one byte short of the GUID
        ] as $length) {
            $owid = $this->signedOwid(substr($random, 0, $length));
            foreach ([
                FodId::tryFromBase64($owid->asBase64()),
                FodId::tryFromByteArray($owid->asByteArray()),
                FodId::tryFromOwid($owid),
            ] as $result) {
                $this->assertFailed(
                    $result,
                    FodIdParseStatus::InvalidTypePayloadLength
                );
            }
        }
    }

    public function testTooShortHashPayloadReportsInvalidTypePayloadLength(): void
    {
        // Probabilistic and HashedEmail both carry a 32 byte value, and a
        // Random-sized payload under either tag is a byte count that fits
        // the wrong type.
        foreach ([0b0000_0101, 0b1000_0101] as $flags) {
            $payload = self::canonicalPayload();
            $payload[FodId::FLAGS_OFFSET] = chr($flags);
            foreach ([
                FodId::HEADER_LENGTH,
                FodId::RANDOM_PAYLOAD_LENGTH,
                FodId::PAYLOAD_LENGTH - 1,
            ] as $length) {
                $owid = $this->signedOwid(substr($payload, 0, $length));
                foreach ([
                    FodId::tryFromBase64($owid->asBase64()),
                    FodId::tryFromByteArray($owid->asByteArray()),
                    FodId::tryFromOwid($owid),
                ] as $result) {
                    $this->assertFailed(
                        $result,
                        FodIdParseStatus::InvalidTypePayloadLength
                    );
                }
            }
        }
    }

    public function testPayloadShorterThanTheHeaderReportsPayloadTooShort(): void
    {
        // Every length under the header, including no payload at all, is
        // the same answer, because the type cannot be read to say more.
        for ($length = 0; $length < FodId::HEADER_LENGTH; $length++) {
            $owid = $this->signedOwid(substr(self::canonicalPayload(), 0, $length));
            foreach ([
                FodId::tryFromBase64($owid->asBase64()),
                FodId::tryFromByteArray($owid->asByteArray()),
                FodId::tryFromOwid($owid),
            ] as $result) {
                $this->assertFailed($result, FodIdParseStatus::PayloadTooShort);
            }
        }
    }

    public function testInvalidBase64ReportsTheOwidStatus(): void
    {
        foreach ([
            'This is not valid Base64!@#$',
            'A',                     // a length that encodes no whole byte
            '****',
            $this->signedOwidBase64(self::canonicalPayload()) . '!',
        ] as $value) {
            $this->assertFailed(
                FodId::tryFromBase64($value),
                ParseStatus::InvalidBase64
            );
        }
    }

    public function testAnOwidDeclarationMismatchIsPassedThroughUnchanged(): void
    {
        // A byte after the envelope makes the declared payload count
        // disagree with the bytes present. The library's status arrives
        // as itself, and with no 51Did there is nothing whose signature
        // could be examined.
        $raw = $this->signedOwid(self::canonicalPayload())->asByteArray();
        $longer = $raw . "\x00";
        $this->assertFailed(
            FodId::tryFromByteArray($longer),
            ParseStatus::ByteCountMismatch
        );
        $this->assertFailed(
            FodId::tryFromBase64(base64_encode($longer)),
            ParseStatus::ByteCountMismatch
        );
        // A declaration raised above the bytes present is the same answer.
        $offset = 1 + strlen(self::TEST_DOMAIN) + 1 + 4;
        $inflated = $raw;
        $inflated[$offset] = chr(ord($raw[$offset]) + 1);
        $this->assertFailed(
            FodId::tryFromByteArray($inflated),
            ParseStatus::ByteCountMismatch
        );
    }

    public function testEveryOwidStatusIsPassedThroughAsTheLibraryReportsIt(): void
    {
        $cases = [
            [ParseStatus::AbsentNode, "\x00"],
            [ParseStatus::UnsupportedVersion, "\x09" . self::TEST_DOMAIN . "\x00"],
            [ParseStatus::UnexpectedEnd, "\x03" . self::TEST_DOMAIN],
            [ParseStatus::UnexpectedEnd, "\x03" . self::TEST_DOMAIN . "\x00\x01"],
            [ParseStatus::InvalidDomainEncoding, "\x03" . str_repeat('a', 300)],
        ];
        foreach ($cases as [$status, $bytes]) {
            $this->assertFailed(FodId::tryFromByteArray($bytes), $status);
            $this->assertFailed(FodId::tryFromBase64(base64_encode($bytes)), $status);
        }
    }

    public function testAbsentOrWrongTypedInputIsReportedNotRaised(): void
    {
        foreach ([null, '', ' ', "\n", "\t \r\n"] as $absent) {
            $this->assertFailed(
                FodId::tryFromBase64($absent),
                ParseStatus::MissingInput
            );
        }
        foreach ([null, ''] as $absent) {
            $this->assertFailed(
                FodId::tryFromByteArray($absent),
                ParseStatus::MissingInput
            );
        }
        // A repeated query parameter with brackets reaches PHP as an array.
        foreach ([['a', 'b'], 42, 1.5, true, new \stdClass()] as $other) {
            $this->assertFailed(
                FodId::tryFromBase64($other),
                ParseStatus::InvalidInputType
            );
            $this->assertFailed(
                FodId::tryFromByteArray($other),
                ParseStatus::InvalidInputType
            );
        }
    }

    public function testAParsedIdentifierWithABadSignatureVerifiesAsInvalid(): void
    {
        // Structurally sound and cryptographically wrong. Reading succeeds,
        // because reading never verifies, and the verification then says
        // exactly that the signature does not match.
        $raw = $this->signedOwid(self::canonicalPayload())->asByteArray();
        $raw[strlen($raw) - 5] = $raw[strlen($raw) - 5] ^ "\x01";
        $fod = $this->assertParsed(FodId::tryFromBase64(base64_encode($raw)));
        $this->assertSame(self::canonicalHash(), $fod->getHash());
        $this->assertFalse($fod->verify($this->publicPem));
        $this->assertSame(
            SignatureStatus::SignatureInvalid,
            $fod->signatureStatus($this->publicPem)
        );
    }

    public function testAKeyThatCannotBeReadIsNotReportedAsAnInvalidSignature(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        foreach (['', 'not a key', "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"] as $pem) {
            $status = $fod->signatureStatus($pem);
            $this->assertSame(SignatureStatus::InvalidKey, $status);
            $this->assertNotSame(SignatureStatus::SignatureInvalid, $status);
            try {
                $fod->verify($pem);
                $this->fail('Expected verify to raise for a key it cannot read.');
            } catch (OwidException $exception) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testTheThrowingSurfaceStillThrowsTheDocumentedTypes(): void
    {
        $raw = $this->signedOwid(self::canonicalPayload())->asByteArray();
        $shortHash = $this->signedOwid(substr(self::canonicalPayload(), 0, FodId::PAYLOAD_LENGTH - 1));
        $shortRandom = $this->signedOwid(substr(self::canonicalRandomPayload(), 0, FodId::HEADER_LENGTH));
        $noHeader = $this->signedOwid("\xA5\x01");

        // The envelope could not be read, so the OWID exception, naming
        // the library's status in the message.
        $owidFailures = [
            [fn () => FodId::fromBase64('not base64!'), ParseStatus::InvalidBase64],
            [fn () => FodId::fromBase64(base64_encode($raw . "\x00")), ParseStatus::ByteCountMismatch],
            [fn () => FodId::fromByteArray($raw . "\x00"), ParseStatus::ByteCountMismatch],
            [fn () => FodId::fromByteArray("\x00"), ParseStatus::AbsentNode],
            [fn () => FodId::fromByteArray("\x03" . self::TEST_DOMAIN), ParseStatus::UnexpectedEnd],
            [fn () => FodId::fromBase64(''), ParseStatus::MissingInput],
        ];
        foreach ($owidFailures as [$read, $status]) {
            try {
                $read();
                $this->fail('Expected an OwidException for ' . $status->value);
            } catch (OwidException $exception) {
                $this->assertStringContainsString($status->value, $exception->getMessage());
            }
        }

        // The envelope was sound and the payload does not fit, so the
        // argument exception, naming the package's status.
        $payloadFailures = [
            [fn () => FodId::fromBase64($shortHash->asBase64()), FodIdParseStatus::InvalidTypePayloadLength],
            [fn () => FodId::fromByteArray($shortRandom->asByteArray()), FodIdParseStatus::InvalidTypePayloadLength],
            [fn () => FodId::fromOwid($noHeader), FodIdParseStatus::PayloadTooShort],
            [fn () => new FodId($noHeader), FodIdParseStatus::PayloadTooShort],
        ];
        foreach ($payloadFailures as [$read, $status]) {
            try {
                $read();
                $this->fail('Expected an InvalidArgumentException for ' . $status->value);
            } catch (InvalidArgumentException $exception) {
                $this->assertStringContainsString($status->value, $exception->getMessage());
            }
        }
    }

    public function testTheTwoSurfacesAgreeOnEveryInput(): void
    {
        // Whatever the answering surface refuses, the raising surface
        // raises for, and whatever one reads the other reads to the same
        // bytes, because both run the one set of checks.
        $good = $this->signedOwid(self::canonicalPayload());
        $inputs = [
            $good->asBase64(),
            FodId::fromOwid($good)->asBase64Url(),
            $this->signedOwidBase64(self::canonicalRandomPayload()),
            $this->signedOwidBase64(self::canonicalPayload() . str_repeat("\xAB", 50)),
            $this->signedOwidBase64(''),
            $this->signedOwidBase64(substr(self::canonicalPayload(), 0, 20)),
            'garbage',
            base64_encode($good->asByteArray() . "\x01"),
            '',
        ];
        foreach ($inputs as $input) {
            $result = FodId::tryFromBase64($input);
            try {
                $fod = FodId::fromBase64($input);
                $this->assertTrue($result->ok, 'fromBase64 read what tryFromBase64 refused');
                $this->assertSame($fod->asByteArray(), $result->fodId->asByteArray());
            } catch (OwidException | InvalidArgumentException $exception) {
                $this->assertFalse($result->ok, 'fromBase64 raised where tryFromBase64 read');
                $this->assertStringContainsString($result->status->value, $exception->getMessage());
            }
        }
    }

    public function testAResultCannotBeAltered(): void
    {
        $result = FodId::tryFromBase64('garbage');
        $this->expectException(\Error::class);
        // @phpstan-ignore-next-line - the point is that the write is refused
        $result->ok = true;
    }
}
