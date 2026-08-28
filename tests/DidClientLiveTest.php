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
}
