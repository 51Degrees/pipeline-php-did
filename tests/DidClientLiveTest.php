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

use fiftyone\pipeline\did\ContextOutcome;
use fiftyone\pipeline\did\DidClient;
use fiftyone\pipeline\did\FodId;
use fiftyone\pipeline\did\IdType;
use fiftyone\pipeline\did\Usage;
use fiftyone\pipeline\did\NotSupportedException;
use PHPUnit\Framework\TestCase;

/**
 * Live tests against the cloud, skipped without a resource key in
 * `_51DEGREES_RESOURCE_KEY` (or the legacy `RESOURCE_KEY`). The licence key
 * is read from `_51DEGREES_LICENSE_KEY` (or `LICENSE_KEY`) and the API base
 * from `FOD_CLOUD_API_URL`, the same variables the examples read. Each test
 * costs uses against the subscription behind the resource key.
 */
class DidClientLiveTest extends TestCase
{
    private string $resource;
    private DidClient $client;

    protected function setUp(): void
    {
        $resource = getenv('_51DEGREES_RESOURCE_KEY') ?: getenv('RESOURCE_KEY');
        if (!$resource) {
            $this->markTestSkipped(
                'Set _51DEGREES_RESOURCE_KEY to run the live tests.'
            );
        }
        $this->resource = $resource;
        $licence = getenv('_51DEGREES_LICENSE_KEY') ?: getenv('LICENSE_KEY');
        $this->client = new DidClient($resource, $licence ?: null);
    }

    /**
     * Creates a 51Did through the cloud `json` endpoint, which is not part
     * of the client because the identifier describes the caller's own
     * connection.
     */
    private function create(): FodId
    {
        $url = $this->client->getEndpoint() . 'json?' . http_build_query([
            'resource' => $this->resource,
            'id.usage' => 'non-marketing',
        ]) . '&values=FODiD.IdProbGlobal&values=FODiD.IdProbLic';
        $context = stream_context_create(['http' => [
            'header' => "User-Agent: fiftyone-pipeline-did-php-tests\r\n",
            'ignore_errors' => true,
        ]]);
        $body = @file_get_contents($url, false, $context);
        $this->assertNotFalse($body, 'No response from the json endpoint.');
        $json = json_decode($body, true);
        $this->assertIsArray(
            $json,
            'The json endpoint did not answer with JSON: '
            . substr($body, 0, 200)
        );
        $value = $json['fodid']['idproblic']
            ?? $json['fodid']['idprobglobal']
            ?? null;
        $this->assertIsString(
            $value,
            'The json endpoint returned no probabilistic identifier: '
            . substr($body, 0, 200)
        );
        return FodId::fromBase64($value);
    }

    public function testCreatedIdentifierVerifiesOfflineAndThroughTheCloud(): void
    {
        $fodId = $this->create();
        $this->assertTrue(
            $this->client->verifySignature($fodId),
            'Offline signature check failed.'
        );
        $this->assertTrue(
            $this->client->verify($fodId),
            'Cloud signature check failed.'
        );
        $this->assertTrue(
            $this->client->verify($fodId->asBase64Url()),
            'Cloud check of the URL-safe form failed.'
        );
    }

    public function testRedeemWithGarbageResultIsUnreadable(): void
    {
        $fodId = $this->create();
        try {
            $result = $this->client->redeem($fodId, 'not-base64url!!', 'challenge');
        } catch (NotSupportedException $exception) {
            $this->markTestSkipped(
                'The host does not offer the creator context.'
            );
        }
        $this->assertSame(200, $result->statusCode);
        $this->assertSame(ContextOutcome::Unreadable, $result->context);
    }
    /**
     * The versioned Model Terms for Marketing document a marketing 51Did is
     * created under.
     *
     * Written out here rather than read from the package, because a test
     * that asked the package what it expects would agree with itself
     * whatever the package said. The literal is what a receiver has to be
     * able to fetch.
     */
    private const MODEL_TERMS_FOR_MARKETING_2 = 'https://m4ow.uk/mtm/2.txt';

    /**
     * Asks the json endpoint for a 51Did with the given query parameter and
     * returns every identifier it answered with. An empty list means the
     * resource key is not entitled to that usage, which the caller reports
     * rather than fails.
     *
     * @return list<FodId>
     */
    private function identifiersFor(string $name, string $value): array
    {
        $url = $this->client->getEndpoint() . 'json?' . http_build_query([
            'resource' => $this->resource,
            $name => $value,
        ]) . '&values=FODiD.IdProbGlobal&values=FODiD.IdProbLic';
        $context = stream_context_create(['http' => [
            'header' => "User-Agent: fiftyone-pipeline-did-php-tests\r\n",
            'ignore_errors' => true,
        ]]);
        $body = @file_get_contents($url, false, $context);
        $this->assertNotFalse($body, 'No response from the json endpoint.');
        $json = json_decode($body, true);
        $this->assertIsArray(
            $json,
            'The json endpoint did not answer with JSON: '
            . substr((string)$body, 0, 200)
        );

        $identifiers = [];
        foreach (['idprobglobal', 'idproblic'] as $field) {
            $value = $json['fodid'][$field] ?? null;
            if (is_string($value) && $value !== '') {
                $identifiers[] = FodId::fromBase64($value);
            }
        }
        return $identifiers;
    }

    /**
     * Asserts the terms and every field the flags byte carries, read
     * through the accessors rather than by masking. The usage values are
     * cumulative, being 001, 011 and 111, so a caller masking the byte for
     * the non-marketing bit reads every marketing identifier as
     * non-marketing.
     */
    private function assertAligned(
        string $label,
        FodId $fodId,
        Usage $usage,
        ?string $terms,
        bool $usageIsIndirect
    ): void {
        $this->assertSame($usage, $fodId->getUsage(), "$label: usage");
        $this->assertSame(
            $usageIsIndirect,
            $fodId->isUsageIndirect(),
            "$label: whether the usage is indirect"
        );
        $this->assertSame($terms, $fodId->getTerms(), "$label: terms");
        $this->assertSame(
            IdType::Probabilistic,
            $fodId->getType(),
            "$label: an idprob* value must be a probabilistic identifier"
        );
    }

    /**
     * Every id.usage the service offers, read back through the package.
     *
     * A non-marketing identifier may not reach a demand source at all, so
     * there is nothing for a receiver to agree to and it states no terms.
     * The two marketing usages both carry the Model Terms for Marketing,
     * and those are the rows that show the service wrote the byte, because
     * an identifier from a service predating the Terms release ends at the
     * match key and reads as no terms.
     */
    public function testEveryUsageReadsBackTheTermsAndFlagsTheServiceWrote(): void
    {
        $cases = [
            ['non-marketing', Usage::NonMarketing, null],
            ['standard', Usage::Standard, self::MODEL_TERMS_FOR_MARKETING_2],
            ['personalized', Usage::Personalized, self::MODEL_TERMS_FOR_MARKETING_2],
        ];

        $checked = 0;
        foreach ($cases as [$name, $usage, $terms]) {
            $identifiers = $this->identifiersFor('id.usage', $name);
            if ($identifiers === []) {
                fwrite(STDERR, "id.usage=$name: no identifier returned, so "
                    . "this key is not entitled to that usage.\n");
                continue;
            }
            foreach ($identifiers as $index => $fodId) {
                $this->assertAligned(
                    "$name[$index]", $fodId, $usage, $terms, false);
            }
            if ($terms !== null) {
                $checked += count($identifiers);
            }
        }

        // Reported as a skip rather than written to stderr, because a
        // runner prints the counts and not the output, so a run that proved
        // nothing would otherwise look identical to one that proved
        // everything.
        if ($checked === 0) {
            $this->markTestSkipped(
                'This resource key returned no marketing 51Did, so no terms '
                . 'address was read and this run did not prove it. Use a key '
                . 'entitled to the standard or personalized usage.'
            );
        }
    }

    /**
     * A consent management platform sends an IAB TCF consent string and no
     * usage of its own. The service decodes the string, decides the usage
     * from the purposes it grants, and records in the identifier that it
     * did so, which is bit 3 of the flags byte.
     *
     * This is the half a caller cannot state for itself. An identifier
     * whose usage was stated in the request and one whose usage was decoded
     * from a consent string are both legitimate, and they are different
     * assertions about how the permission was obtained, so a receiver has
     * to be able to tell them apart.
     *
     * The strings are the ones the cloud's own IabTcfElement tests use,
     * repeated here rather than shared, for the same reason as the address
     * above. The first grants all twelve purposes and the second the
     * Appendix 1 standard set of 1, 2, 7, 8 and 11.
     */
    public function testConsentStringSetsTheUsageIsIndirectBit(): void
    {
        $cases = [
            ['AAAAAAAAAAAAAAAAAAAAAAAAAP_w', Usage::Personalized],
            ['AAAAAAAAAAAAAAAAAAAAAAAAAMMg', Usage::Standard],
        ];

        $proven = 0;
        foreach ($cases as [$tcString, $usage]) {
            // No id.usage is sent. A stated usage wins over a consent
            // string, so sending one would leave the bit clear and this
            // would prove the opposite of what it says.
            $identifiers = $this->identifiersFor('tcstring', $tcString);
            if ($identifiers === []) {
                fwrite(STDERR, "consent string granting {$usage->name}: no "
                    . "identifier returned, so this key is not entitled to "
                    . "that marketing usage.\n");
                continue;
            }
            foreach ($identifiers as $index => $fodId) {
                // A consent string granting a marketing usage produces a
                // marketing identifier, so the terms travel with it too.
                $this->assertAligned(
                    "consent/{$usage->name}[$index]",
                    $fodId,
                    $usage,
                    self::MODEL_TERMS_FOR_MARKETING_2,
                    true
                );
            }
            $proven += count($identifiers);
        }

        // Same reasoning as the usage test above.
        if ($proven === 0) {
            $this->markTestSkipped(
                'This resource key returned no identifier for either consent '
                . 'string, so the usage-from-consent bit was never read and '
                . 'this run did not prove it.'
            );
        }
    }
}
