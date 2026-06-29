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

/**
 * Offline example for the 51Did (FodId) reader.
 *
 * The 51Degrees Cloud service issues real 51Dids. To keep this example
 * self-contained and offline, it builds a sample 51Did in process - generate
 * an ECDSA P-256 key pair, sign a canonical 37-byte payload - then parses it
 * back and prints the three payload fields. It also shows the headline use
 * case: a 51Did is re-issued fresh on every call (the envelope, hence the
 * base64, changes), but the value (the Hash) is stable. Compare values, never
 * envelopes.
 */

require __DIR__ . '/../vendor/autoload.php';

use fiftyone\pipeline\did\FodId;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Owid;

const DOMAIN = '51degrees.com';

/** A canonical 37-byte Probabilistic payload. */
function samplePayload(): string
{
    $hash = '';
    for ($i = 0; $i < FodId::HASH_LENGTH; $i++) {
        $hash .= chr(0x20 + $i);
    }
    return chr(0x00) . pack('V', 0x12345678) . $hash;
}

/** Issues (signs) a 51Did over the payload and returns it as base64. */
function issue(Creator $creator, string $payload): string
{
    $owid = new Owid(DOMAIN, null, $payload);
    $creator->sign($owid);
    return $owid->asBase64();
}

$crypto = Crypto::new();
$creator = new Creator(DOMAIN, $crypto);
$payload = samplePayload();

$fodId = FodId::fromBase64(issue($creator, $payload));

echo "51Did parsed from base64:\n";
echo '  Domain    : ' . $fodId->getDomain() . "\n";
echo '  Type      : ' . $fodId->getType()->name . "\n";
echo '  Flags     : 0x' . dechex($fodId->getFlags()) . "\n";
echo '  LicenseId : ' . $fodId->getLicenseId() . "\n";
echo '  Hash      : ' . bin2hex($fodId->getHash()) . "\n";
echo '  Verifies  : ' . ($fodId->verify($crypto->publicKeyPem()) ? 'true' : 'false') . "\n";

$reissued = FodId::fromBase64(issue($creator, $payload));
$sameEnvelope = $fodId->asBase64() === $reissued->asBase64();
$sameValue = $fodId->getHash() === $reissued->getHash();

echo "\nSame payload, re-issued:\n";
echo '  Same envelope (base64) : ' . ($sameEnvelope ? 'true' : 'false') . "\n";
echo '  Same value (Hash)      : ' . ($sameValue ? 'true' : 'false') . "\n";

if ($sameEnvelope || !$sameValue) {
    throw new RuntimeException(
        'Expected a different envelope but the same value across reissues.'
    );
}
