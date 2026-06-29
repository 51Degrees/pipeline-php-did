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
use fiftyone\pipeline\did\IdType;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\OwidException;
use TypeError;

class FodIdTest extends TestCase
{
    private const TEST_DOMAIN = '51degrees.com';
    // 0xA5: usage bits plus the HashedEmail type tag in bits 6-7.
    private const CANONICAL_FLAGS = 0xA5;
    private const CANONICAL_LICENSE_ID = 0x12345678;

    private Creator $creator;
    private string $publicPem;

    protected function setUp(): void
    {
        $crypto = Crypto::new();
        $this->publicPem = $crypto->publicKeyPem();
        $this->creator = new Creator(self::TEST_DOMAIN, $crypto);
    }

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

    private static function canonicalRandomPayload(): string
    {
        $guid = '';
        for ($i = 0; $i < FodId::GUID_LENGTH; $i++) {
            $guid .= chr(0x40 + $i);
        }
        return chr((1 << 6) | 0b001)            // Random tag + usage bits
            . pack('V', self::CANONICAL_LICENSE_ID)
            . $guid;
    }

    private function signedOwid(string $payload): Owid
    {
        $owid = new Owid(self::TEST_DOMAIN, null, $payload);
        $this->creator->sign($owid);
        return $owid;
    }

    private function signedOwidBase64(string $payload): string
    {
        return $this->signedOwid($payload)->asBase64();
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

    public function testFodIdIsAnOwid(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $this->assertInstanceOf(Owid::class, $fod->getOwid());
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
        $this->assertEquals($owid->date, $fod->getDate());
        $this->assertSame($owid->version, $fod->getVersion());
        $this->assertSame($owid->payload, $fod->getPayload());
        $this->assertSame($owid->signature, $fod->getSignature());
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

    public function testIsCryptographicallyVerifiable(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $this->assertTrue($fod->verify($this->publicPem));
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
        $guid = '';
        for ($i = 0; $i < FodId::GUID_LENGTH; $i++) {
            $guid .= chr(0x40 + $i);
        }
        $this->assertSame($guid, $fod->getHash());
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
    }

    // ----- Gap tests (runbook section 6b) -----

    public function testCompareTwo51DidsSamePayload(): void
    {
        $payload = self::canonicalPayload();
        $a = $this->signedOwid($payload);
        $b = $this->signedOwid($payload);
        // sign() stamps "now" to the minute, so set distinct dates to
        // represent two reissues at different times.
        $a->date = new DateTimeImmutable('2026-01-01T00:00:00+00:00');
        $b->date = new DateTimeImmutable('2026-01-01T00:05:00+00:00');

        $fa = FodId::fromBase64($a->asBase64());
        $fb = FodId::fromBase64($b->asBase64());

        $this->assertSame($fa->getHash(), $fb->getHash());        // value stable
        $this->assertNotEquals($fa->getDate(), $fb->getDate());   // envelope differs
        $this->assertNotSame($fa->getSignature(), $fb->getSignature());
        $this->assertNotSame($a->asBase64(), $b->asBase64());
    }

    public function testConstructionDoesNotVerify(): void
    {
        // An unsigned OWID (empty signature) still constructs and exposes all
        // three fields - construction must not verify.
        $unsigned = new Owid(self::TEST_DOMAIN, null, self::canonicalPayload());
        $fod = FodId::fromOwid($unsigned);
        $this->assertSame(self::CANONICAL_FLAGS, $fod->getFlags());
        $this->assertSame(self::CANONICAL_LICENSE_ID, $fod->getLicenseId());
        $this->assertSame(self::canonicalHash(), $fod->getHash());
    }

    public function testVerifyWithWrongKeyReturnsFalse(): void
    {
        $fod = FodId::fromBase64($this->signedOwidBase64(self::canonicalPayload()));
        $otherPublicPem = Crypto::new()->publicKeyPem();
        $this->assertFalse($fod->verify($otherPublicPem));
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
}
