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
 * self-contained and offline, it builds a sample 51Did in process by
 * generating an ECDSA P-256 key pair and signing a canonical 37-byte
 * payload, then reads it back and prints the three payload fields. It also
 * shows the headline use case, which is that a 51Did is re-issued fresh on
 * every call (the envelope, hence the base64, changes) while the match key
 * is stable. Compare match keys, never envelopes.
 *
 * Reading answers rather than raising. A value arriving from outside may be
 * anything at all, so tryFromBase64 reports whether it was a 51Did and, when
 * not, the specific reason, and the example shows a few of those too.
 */

require __DIR__ . '/../vendor/autoload.php';

use fiftyone\pipeline\did\FodId;
use SwanCommunity\Owid\Creator;
use SwanCommunity\Owid\Crypto;

const DOMAIN = '51degrees.com';

/** A canonical 37-byte Probabilistic payload. */
function samplePayload(): string
{
    $matchKey = '';
    for ($i = 0; $i < FodId::HASH_LENGTH; $i++) {
        $matchKey .= chr(0x20 + $i);
    }
    return chr(0x00) . pack('V', 0x12345678) . $matchKey;
}

/**
 * Issues a 51Did over the payload and returns it as base64. The creator
 * signs the envelope into existence, as there is no unsigned stage.
 */
function issue(Creator $creator, string $payload): string
{
    return $creator->create($payload)->asBase64();
}

$crypto = Crypto::new();
$creator = new Creator(DOMAIN, $crypto);
$payload = samplePayload();

$result = FodId::tryFromBase64(issue($creator, $payload));
if (!$result->ok) {
    throw new RuntimeException(
        'The sample 51Did did not read: ' . $result->status->value
    );
}
$fodId = $result->fodId;

echo "51Did read from base64 (status " . $result->status->value . "):\n";
echo '  Domain    : ' . $fodId->getDomain() . "\n";
echo '  Type      : ' . $fodId->getType()->name . "\n";
echo '  Flags     : 0x' . dechex($fodId->getFlags()) . "\n";
echo '  LicenseId : ' . $fodId->getLicenseId() . "\n";
echo '  Match key : ' . bin2hex($fodId->getMatchKey()) . "\n";
// Reading never verifies, so the signature is a separate question.
echo '  Verifies  : ' . ($fodId->verify($crypto->publicKeyPem()) ? 'true' : 'false') . "\n";
echo '  Signature : ' . $fodId->signatureStatus($crypto->publicKeyPem())->value . "\n";

$reissued = FodId::fromBase64(issue($creator, $payload));
$sameEnvelope = $fodId->asBase64() === $reissued->asBase64();
$sameMatchKey = $fodId->getMatchKey() === $reissued->getMatchKey();

echo "\nSame payload, re-issued:\n";
echo '  Same envelope (base64) : ' . ($sameEnvelope ? 'true' : 'false') . "\n";
echo '  Same match key         : ' . ($sameMatchKey ? 'true' : 'false') . "\n";

if ($sameEnvelope || !$sameMatchKey) {
    throw new RuntimeException(
        'Expected a different envelope but the same match key across reissues.'
    );
}

// Values that are not a 51Did are an ordinary outcome with a named reason.
echo "\nValues that are not a 51Did:\n";
$examples = [
    'not base64 at all'      => 'not a 51Did!',
    'nothing'                => '',
    'a payload of two bytes' => issue($creator, "\x00\x01"),
    'a Random tag, no GUID'  => issue($creator, chr(1 << 6) . pack('V', 1)),
];
foreach ($examples as $label => $value) {
    $read = FodId::tryFromBase64($value);
    printf(
        "  %-22s : ok=%s value=%s status=%s\n",
        $label,
        $read->ok ? 'true' : 'false',
        $read->fodId === null ? 'none' : 'present',
        $read->status->value
    );
    if ($read->ok) {
        throw new RuntimeException("Expected {$label} not to read.");
    }
}
