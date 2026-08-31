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
use RuntimeException;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Io;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\Version;

/**
 * Writes signed envelopes with a chosen date and version for the tests.
 *
 * A Creator stamps the moment of signing and the current version, and an
 * OWID's fields are read only once it exists, so a test that needs an
 * identifier dated inside a particular key period, or carrying an older
 * version, writes the wire form itself with the library's own field
 * writers, signs the fields exactly as the library does, and reads the
 * bytes back through the public parse. Nothing here reaches into the
 * library, so the tests stay honest about how an OWID comes to exist.
 */
final class Envelopes
{
    /**
     * The wire form of one envelope with the fields given, signed with the
     * crypto given over the same bytes the library signs.
     */
    public static function bytes(
        Crypto $crypto,
        string $domain,
        DateTimeImmutable $date,
        string $payload,
        Version $version = Version::Version3
    ): string {
        $buffer = '';
        Io::writeByte($buffer, $version->asByte());
        Io::writeString($buffer, $domain);
        Io::writeDate($buffer, $date, $version);
        Io::writeByteArray($buffer, $payload);
        $signature = $crypto->signByteArray($buffer);
        Io::writeSignature($buffer, $signature);
        return $buffer;
    }

    /**
     * The same envelope read back as an OWID, which a test expects to be
     * well formed, failing the run with the reason when it is not.
     */
    public static function owid(
        Crypto $crypto,
        string $domain,
        DateTimeImmutable $date,
        string $payload,
        Version $version = Version::Version3
    ): Owid {
        $result = Owid::tryFromByteArray(
            self::bytes($crypto, $domain, $date, $payload, $version)
        );
        if (!$result->ok) {
            throw new RuntimeException(
                'The test envelope did not parse: ' . $result->status->value
            );
        }
        return $result->owid;
    }
}
