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
use DateTimeZone;
use fiftyone\pipeline\did\CloudException;
use fiftyone\pipeline\did\ContextOutcome;
use fiftyone\pipeline\did\DidClient;
use fiftyone\pipeline\did\FactorOutcome;
use fiftyone\pipeline\did\FodId;
use fiftyone\pipeline\did\NotSupportedException;
use fiftyone\pipeline\did\SignatureOutcome;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\Owid;
use SwanCommunity\Owid\Version;

/**
 * Unit tests for {@see DidClient} with an injected transport, no network.
 */
class DidClientTest extends TestCase
{
    private const RESOURCE = 'AQS5HKcyRESOURCE';
    private const LICENCE = 'LICENCEKEYNEVERINURL';
    private const ENDPOINT = 'https://cloud.example/api/v4/';
    private const DOMAIN = '51degrees.com';

    /** The message the cloud sends for a value that does not parse. */
    private const NOT_A_51DID =
        'Value for 51did is not a valid Base64-encoded 51Did.';

    /** A week, the spacing the key generators currently write. */
    private const WEEK = 7 * 24 * 60 * 60;

    /** Start of the first key of the schedule under test. */
    private const T0 = '2026-08-03T00:00:00+00:00';

    /** Recorded transport calls, each with method, url, headers and body. */
    private array $requests = [];

    /** Queued transport answers, each with status and body, used in order. */
    private array $responses = [];

    /** The clock the client under test reads. */
    private int $now;

    private Crypto $keyA;
    private Crypto $keyB;
    private Crypto $keyC;

    protected function setUp(): void
    {
        $this->requests = [];
        $this->responses = [];
        $this->now = self::at(self::T0)->getTimestamp() + self::WEEK;
        $this->keyA = Crypto::new();
        $this->keyB = Crypto::new();
        $this->keyC = Crypto::new();
    }

    // ----- Helpers -----

    private static function at(string $iso): DateTimeImmutable
    {
        return new DateTimeImmutable($iso, new DateTimeZone('UTC'));
    }

    private static function shift(
        DateTimeImmutable $at,
        int $seconds
    ): DateTimeImmutable {
        return $at->setTimestamp($at->getTimestamp() + $seconds);
    }

    /** A canonical Probabilistic payload, header plus a 32 byte value. */
    private static function payload(): string
    {
        $hash = '';
        for ($i = 0; $i < FodId::HASH_LENGTH; $i++) {
            $hash .= chr(0x20 + $i);
        }
        return chr(0x05) . pack('V', 0x12345678) . $hash;
    }

    /**
     * A 51Did dated as given and signed with the crypto given, so the
     * envelope carries a chosen date rather than the time of signing.
     */
    private function signedAt(
        DateTimeImmutable $date,
        Crypto $crypto,
        ?string $payload = null,
        Version $version = Version::Version3
    ): FodId {
        $owid = new Owid(self::DOMAIN, $date, $payload ?? self::payload());
        $owid->version = $version;
        $owid->signature = $crypto->signByteArray($owid->dataForCrypto());
        return FodId::fromOwid($owid);
    }

    /**
     * A three key schedule starting at T0 with a week between starts, keyed
     * A, B, C, as the cloud's key endpoint answers it.
     *
     * @return array<int, array<string, string>>
     */
    private function schedule(string $startField = 'startsAt'): array
    {
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        return [
            [$startField => $t0->format('c'),
                'publicKey' => $this->keyA->publicKeyPem()],
            [$startField => $t1->format('c'),
                'publicKey' => $this->keyB->publicKeyPem()],
            [$startField => $t2->format('c'),
                'publicKey' => $this->keyC->publicKeyPem()],
        ];
    }

    private function queue(int $status, string $body): void
    {
        $this->responses[] = ['status' => $status, 'body' => $body];
    }

    private function queueJson(int $status, array $json): void
    {
        $this->queue($status, json_encode($json));
    }

    private function client(?string $licence = self::LICENCE): DidClient
    {
        $transport = function (
            string $method,
            string $url,
            array $headers,
            string $body
        ): array {
            $this->requests[] = compact('method', 'url', 'headers', 'body');
            if ($this->responses === []) {
                throw new RuntimeException("No response queued for {$url}.");
            }
            return array_shift($this->responses);
        };
        return new DidClient(
            self::RESOURCE,
            $licence,
            self::ENDPOINT,
            $transport,
            fn (): int => $this->now
        );
    }

    private function lastRequest(): array
    {
        return $this->requests[count($this->requests) - 1];
    }

    // ----- Construction -----

    public function testEmptyResourceKeyThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new DidClient('');
    }

    public function testEndpointIsNormalisedToOneTrailingSlash(): void
    {
        $given = [
            'https://cloud.example/api/v4',
            'https://cloud.example/api/v4//',
        ];
        foreach ($given as $endpoint) {
            $client = new DidClient(self::RESOURCE, null, $endpoint);
            $this->assertSame(
                'https://cloud.example/api/v4/',
                $client->getEndpoint()
            );
        }
    }

    public function testEndpointReadsEnvironmentVariableWhenAbsent(): void
    {
        $previous = getenv(DidClient::ENDPOINT_VARIABLE);
        putenv(DidClient::ENDPOINT_VARIABLE . '=https://other.example/api/v4');
        try {
            $client = new DidClient(self::RESOURCE);
            $this->assertSame('https://other.example/api/v4/', $client->getEndpoint());
        } finally {
            putenv(DidClient::ENDPOINT_VARIABLE
                . ($previous === false ? '' : '=' . $previous));
        }
    }

    public function testEndpointDefaultsToThePublicCloud(): void
    {
        $previous = getenv(DidClient::ENDPOINT_VARIABLE);
        putenv(DidClient::ENDPOINT_VARIABLE);
        try {
            $this->assertSame(
                DidClient::DEFAULT_ENDPOINT,
                (new DidClient(self::RESOURCE))->getEndpoint()
            );
        } finally {
            if ($previous !== false) {
                putenv(DidClient::ENDPOINT_VARIABLE . '=' . $previous);
            }
        }
    }

    // ----- Key list -----

    public function testPublicKeysReadsStartsAt(): void
    {
        $this->queueJson(200, $this->schedule());
        $keys = $this->client()->publicKeys();
        $this->assertCount(3, $keys);
        $this->assertSame(
            self::at(self::T0)->getTimestamp(),
            $keys[0]->startsAt->getTimestamp()
        );
        $this->assertSame($this->keyA->publicKeyPem(), $keys[0]->pem);
        $request = $this->lastRequest();
        $this->assertSame('GET', $request['method']);
        $this->assertSame(
            self::ENDPOINT . 'id/key/' . self::RESOURCE,
            $request['url']
        );
        $this->assertStringNotContainsString(self::LICENCE, $request['url']);
        $this->assertMatchesRegularExpression(
            '#^User-Agent: 51degrees/fiftyone\.pipeline\.did/\S+$#',
            $request['headers'][0]
        );
    }

    public function testPublicKeysFallsBackToCreated(): void
    {
        $this->queueJson(200, $this->schedule('created'));
        $keys = $this->client()->publicKeys();
        $this->assertCount(3, $keys);
        $this->assertSame(
            self::at(self::T0)->getTimestamp() + self::WEEK,
            $keys[1]->startsAt->getTimestamp()
        );
    }

    public function testPublicKeysIgnoresWeekStart(): void
    {
        $schedule = $this->schedule();
        $schedule[0]['weekStart'] = '2000-01-01T00:00:00Z';
        $this->queueJson(200, $schedule);
        $keys = $this->client()->publicKeys();
        $this->assertSame(
            self::at(self::T0)->getTimestamp(),
            $keys[0]->startsAt->getTimestamp()
        );
    }

    public function testPublicKeysAnswersFromCacheOnSecondCall(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $client->publicKeys();
        $this->assertCount(1, $this->requests);
    }

    public function testPublicKeysErrorStatusThrowsCloudException(): void
    {
        $this->queueJson(401, ['errors' => ['bad resource key']]);
        try {
            $this->client()->publicKeys();
            $this->fail('Expected a CloudException.');
        } catch (CloudException $exception) {
            $this->assertSame(401, $exception->getStatusCode());
            $this->assertStringContainsString(
                'bad resource key',
                $exception->getBody()
            );
        }
    }

    public function testPublicKeysNonListThrows(): void
    {
        $this->queue(200, 'not json');
        $this->expectException(RuntimeException::class);
        $this->client()->publicKeys();
    }

    public function testPublicKeyForNoRefetchInsideTheSchedule(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $key = $client->publicKeyFor($this->signedAt($inside, $this->keyB));
        $this->assertSame($this->keyB->publicKeyPem(), $key->pem);
        $this->assertCount(1, $this->requests);
    }

    public function testPublicKeyForRefetchesWhenDateIsLaterThanNewestStart(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $t0 = self::at(self::T0);
        $newer = Crypto::new();
        $schedule = $this->schedule();
        $schedule[] = [
            'startsAt' => self::shift($t0, 3 * self::WEEK)->format('c'),
            'publicKey' => $newer->publicKeyPem(),
        ];
        $this->queueJson(200, $schedule);
        $later = self::shift($t0, 3 * self::WEEK + 60);
        $key = $client->publicKeyFor($this->signedAt($later, $newer));
        $this->assertCount(2, $this->requests);
        $this->assertSame($newer->publicKeyPem(), $key->pem);
    }

    public function testPublicKeyForRefetchesOnceWhenNothingIsInForce(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $this->queueJson(200, $this->schedule());
        $before = self::shift(self::at(self::T0), -self::WEEK);
        $this->assertNull($client->publicKeyFor($this->signedAt($before, $this->keyA)));
        $this->assertCount(2, $this->requests);
    }

    public function testPublicKeyForRefetchesWhenTheListIsADayOld(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $this->now += DidClient::KEY_LIST_MAX_AGE_SECONDS + 1;
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), 3600);
        $client->publicKeyFor($this->signedAt($inside, $this->keyA));
        $this->assertCount(2, $this->requests);
    }

    public function testPublicKeyForDoesNotRefetchWhenTheListIsYoungerThanADay(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $this->now += DidClient::KEY_LIST_MAX_AGE_SECONDS - 60;
        $inside = self::shift(self::at(self::T0), 3600);
        $client->publicKeyFor($this->signedAt($inside, $this->keyA));
        $this->assertCount(1, $this->requests);
    }

    // ----- Selection -----

    public function testPublicKeyForIsTheLatestStartOnOrBeforeTheDate(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $t0 = self::at(self::T0);
        $this->assertSame(
            $this->keyA->publicKeyPem(),
            $client->publicKeyFor($this->signedAt($t0, $this->keyA))->pem
        );
        $inB = self::shift($t0, self::WEEK);
        $this->assertSame(
            $this->keyB->publicKeyPem(),
            $client->publicKeyFor($this->signedAt($inB, $this->keyB))->pem
        );
        // A date after the newest start held triggers one refetch, and the
        // newest key is still the answer when the list has not grown.
        $this->queueJson(200, $this->schedule());
        $inC = self::shift($t0, 5 * self::WEEK);
        $this->assertSame(
            $this->keyC->publicKeyPem(),
            $client->publicKeyFor($this->signedAt($inC, $this->keyC))->pem
        );
        $this->assertCount(2, $this->requests);
    }

    public function testEarlierNeighbourAcceptedWithinToleranceAfterBoundary(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $boundary = self::shift(self::at(self::T0), self::WEEK);
        $tolerance = DidClient::BOUNDARY_TOLERANCE_SECONDS;
        $justAfter = self::shift($boundary, $tolerance - 60);
        $this->assertTrue($client->verifySignature(
            $this->signedAt($justAfter, $this->keyA)
        ));
        $wellAfter = self::shift($boundary, $tolerance + 60);
        $this->assertFalse($client->verifySignature(
            $this->signedAt($wellAfter, $this->keyA)
        ));
    }

    public function testLaterNeighbourAcceptedWithinToleranceBeforeBoundary(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $boundary = self::shift(self::at(self::T0), self::WEEK);
        $tolerance = DidClient::BOUNDARY_TOLERANCE_SECONDS;
        $justBefore = self::shift($boundary, -($tolerance - 60));
        $this->assertTrue($client->verifySignature(
            $this->signedAt($justBefore, $this->keyB)
        ));
        $wellBefore = self::shift($boundary, -($tolerance + 60));
        $this->assertFalse($client->verifySignature(
            $this->signedAt($wellBefore, $this->keyB)
        ));
    }

    public function testNoCandidateBeforeTheSchedule(): void
    {
        $this->queueJson(200, $this->schedule());
        // The refetch for a date nothing covers.
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $tolerance = DidClient::BOUNDARY_TOLERANCE_SECONDS;
        $before = self::shift(self::at(self::T0), -($tolerance + 60));
        $fodId = $this->signedAt($before, $this->keyA);
        $this->assertFalse($client->verifySignature($fodId));
        $this->queueJson(200, $this->schedule());
        $this->assertNull($client->publicKeyFor($fodId));
    }

    // ----- Offline verification -----

    public function testVerifySignatureTrueWithTheKeyInForce(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $this->assertTrue($this->client()->verifySignature(
            $this->signedAt($inside, $this->keyB)
        ));
    }

    public function testVerifySignatureFalseWithTheWrongKey(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $this->assertFalse($this->client()->verifySignature(
            $this->signedAt($inside, $this->keyC)
        ));
    }

    public function testVerifySignatureFalseForVersion2(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $fodId = $this->signedAt($inside, $this->keyB, null, Version::Version2);
        $this->assertSame(Version::Version2, $fodId->getVersion());
        $this->assertFalse($this->client()->verifySignature($fodId));
        $this->assertCount(0, $this->requests);
    }

    public function testVerifySignatureFalseForPayloadShorterThanBase(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        // A Reserved type header-only payload parses as a FodId but is
        // shorter than the base for a 32 byte match key.
        $payload = chr(0b1100_0000)
            . str_repeat("\x00", FodId::HEADER_LENGTH - 1);
        $fodId = $this->signedAt($inside, $this->keyB, $payload);
        $this->assertFalse($this->client()->verifySignature($fodId));
        $this->assertCount(0, $this->requests);
    }

    public function testVerifySignatureTrueForPayloadLongerThanBase(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        // A creator context section after the base, which the signature
        // covers.
        $payload = self::payload() . "\x00" . str_repeat("\xAB", 18);
        $this->assertTrue($this->client()->verifySignature(
            $this->signedAt($inside, $this->keyB, $payload)
        ));
    }

    public function testVerifySignatureTrueForRandomIdentifier(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $payload = chr(1 << 6) . pack('V', 1)
            . str_repeat("\x42", FodId::GUID_LENGTH);
        $this->assertTrue($this->client()->verifySignature(
            $this->signedAt($inside, $this->keyB, $payload)
        ));
    }

    // ----- Cloud verification -----

    public function testVerifyValid(): void
    {
        $this->queueJson(200, ['valid' => true]);
        $fodId = $this->signedAt(self::at(self::T0), $this->keyA);
        $this->assertTrue($this->client()->verify($fodId));
        $request = $this->lastRequest();
        $this->assertSame('GET', $request['method']);
        // Both names, so a cloud reading only the older owid name and one
        // reading 51did first both find the identifier.
        $this->assertSame(
            self::ENDPOINT . 'id/verify/' . self::RESOURCE
                . '?51did=' . $fodId->asBase64Url()
                . '&owid=' . $fodId->asBase64Url(),
            $request['url']
        );
        $this->assertStringNotContainsString(self::LICENCE, $request['url']);
    }

    public function testVerifyInvalid(): void
    {
        $this->queueJson(400, ['valid' => false]);
        $this->assertFalse($this->client()->verify('AzUxZC5jb20A'));
    }

    public function testVerifyErrorsThrowsWithTheCloudMessage(): void
    {
        $this->queueJson(400, ['errors' => [self::NOT_A_51DID]]);
        try {
            $this->client()->verify('not a 51did');
            $this->fail('Expected an InvalidArgumentException.');
        } catch (InvalidArgumentException $exception) {
            $this->assertStringContainsString(
                self::NOT_A_51DID,
                $exception->getMessage()
            );
        }
    }

    public function testVerifyOtherStatusThrowsCloudException(): void
    {
        $this->queue(500, 'boom');
        $this->expectException(CloudException::class);
        $this->client()->verify('AzUxZC5jb20A');
    }

    // ----- Redeem -----

    public function testRedeemSendsAPostFormWithTheFields(): void
    {
        $this->queueJson(200, [
            'signature' => 'verified',
            'context' => 'verified',
            'verifiedAt' => '2026-08-07T09:15:32Z',
            'secondsSinceVerified' => 2,
        ]);
        $fodId = $this->signedAt(self::at(self::T0), $this->keyA);
        $this->client()->redeem($fodId, 'SEALED', 'CHALLENGE');
        $request = $this->lastRequest();
        $this->assertSame('POST', $request['method']);
        // The bare path. The cloud's POST route takes the resource key from
        // the form, and neither key is in the URL.
        $this->assertSame(self::ENDPOINT . 'id/redeem', $request['url']);
        $this->assertStringNotContainsString(self::LICENCE, $request['url']);
        $this->assertStringNotContainsString(self::RESOURCE, $request['url']);
        $this->assertStringNotContainsString('?', $request['url']);
        parse_str($request['body'], $form);
        $this->assertSame([
            'resource' => self::RESOURCE,
            '51did' => $fodId->asBase64Url(),
            'result' => 'SEALED',
            'challenge' => 'CHALLENGE',
            'license' => self::LICENCE,
        ], $form);
        $this->assertContains(
            'Content-Type: application/x-www-form-urlencoded',
            $request['headers']
        );
    }

    public function testRedeemOmitsLicenceWhenNoneGiven(): void
    {
        $this->queueJson(200, ['context' => 'unreadable']);
        $this->client(null)->redeem('AzUxZC5jb20A', 'SEALED', '');
        parse_str($this->lastRequest()['body'], $form);
        $this->assertArrayNotHasKey('license', $form);
        $this->assertSame(
            ['resource', '51did', 'result', 'challenge'],
            array_keys($form)
        );
    }

    public function testRedeemedWithFactors(): void
    {
        $this->queueJson(200, [
            'signature' => 'verified',
            'context' => 'mismatch',
            'factors' => ['transport' => 'verified', 'device' => 'mismatch',
                'browserip' => 'verified', 'connectionip' => 'verified',
                'asn' => 'verified', 'browser' => 'mismatch'],
            'verifiedAt' => '2026-08-07T09:15:32Z',
            'secondsSinceVerified' => 2,
        ]);
        $result = $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Mismatch, $result->context);
        $this->assertSame(SignatureOutcome::Verified, $result->signature);
        $this->assertSame(FactorOutcome::Verified, $result->factors['transport']);
        $this->assertSame(FactorOutcome::Mismatch, $result->factors['device']);
        $this->assertCount(6, $result->factors);
        $this->assertSame(
            '2026-08-07T09:15:32Z',
            $result->verifiedAt->format('Y-m-d\TH:i:s\Z')
        );
        $this->assertSame(2, $result->secondsSinceVerified);
        $this->assertSame(200, $result->statusCode);
        $this->assertSame('mismatch', $result->rawContext);
        $this->assertSame([
            'transport' => 'verified', 'device' => 'mismatch',
            'browserip' => 'verified', 'connectionip' => 'verified',
            'asn' => 'verified', 'browser' => 'mismatch',
        ], $result->toArray()['factors']);
    }

    public function testRedeemedWithoutFactors(): void
    {
        $body = ['signature' => 'invalid', 'context' => 'verified',
            'verifiedAt' => '2026-08-07T09:15:32Z', 'secondsSinceVerified' => 0];
        $this->queueJson(200, $body);
        $result = $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Verified, $result->context);
        $this->assertSame(SignatureOutcome::Invalid, $result->signature);
        $this->assertNull($result->factors);
        $this->assertSame(0, $result->secondsSinceVerified);
        $this->assertSame($body, $result->toArray());
        $this->assertSame(json_encode($body), $result->raw);
    }

    public function testRedeemExpired(): void
    {
        $this->queueJson(200, ['context' => 'expired',
            'verifiedAt' => '2026-08-07T09:15:32Z', 'secondsSinceVerified' => 14]);
        $result = $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Expired, $result->context);
        $this->assertSame(SignatureOutcome::Unknown, $result->signature);
        $this->assertSame(14, $result->secondsSinceVerified);
        $this->assertNotNull($result->verifiedAt);
        $this->assertArrayNotHasKey('signature', $result->toArray());
    }

    public function testRedeemReplayed(): void
    {
        $this->queueJson(200, ['context' => 'replayed']);
        $result = $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Replayed, $result->context);
        $this->assertNull($result->verifiedAt);
        $this->assertNull($result->secondsSinceVerified);
        $this->assertSame(['context' => 'replayed'], $result->toArray());
    }

    public function testRedeemUnreadable(): void
    {
        $this->queueJson(200, ['context' => 'unreadable']);
        $result = $this->client()->redeem('AzUxZC5jb20A', 'not-base64url!!', 'C');
        $this->assertSame(ContextOutcome::Unreadable, $result->context);
        $this->assertSame(200, $result->statusCode);
    }

    public function testRedeemUnconfirmedIs503(): void
    {
        $this->queueJson(503, ['context' => 'unconfirmed']);
        $result = $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Unconfirmed, $result->context);
        $this->assertSame(503, $result->statusCode);
    }

    public function testRedeemUnknownContextFailsClosedAndKeepsTheRaw(): void
    {
        $this->queueJson(200, ['context' => 'somethingnew']);
        $result = $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Unreadable, $result->context);
        $this->assertSame('somethingnew', $result->rawContext);
    }

    public function testRedeemNonJsonBodyFailsClosed(): void
    {
        $this->queue(200, '<html>proxy</html>');
        $result = $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Unreadable, $result->context);
        $this->assertSame('', $result->rawContext);
        $this->assertSame('<html>proxy</html>', $result->raw);
    }

    public function testRedeem400ThrowsWithTheCloudErrors(): void
    {
        $this->queueJson(400, ['errors' => [self::NOT_A_51DID]]);
        try {
            $this->client()->redeem('garbage', 'SEALED', 'C');
            $this->fail('Expected an InvalidArgumentException.');
        } catch (InvalidArgumentException $exception) {
            $this->assertStringContainsString(
                self::NOT_A_51DID,
                $exception->getMessage()
            );
        }
    }

    public function testRedeem404ThrowsNotSupported(): void
    {
        $this->queue(404, '');
        try {
            $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
            $this->fail('Expected a NotSupportedException.');
        } catch (NotSupportedException $exception) {
            $this->assertSame(404, $exception->getStatusCode());
            $this->assertInstanceOf(CloudException::class, $exception);
        }
    }

    public function testRedeemOtherStatusThrowsCloudException(): void
    {
        $this->queue(500, 'server error');
        try {
            $this->client()->redeem('AzUxZC5jb20A', 'SEALED', 'C');
            $this->fail('Expected a CloudException.');
        } catch (CloudException $exception) {
            $this->assertNotInstanceOf(
                NotSupportedException::class,
                $exception
            );
            $this->assertSame(500, $exception->getStatusCode());
            $this->assertSame('server error', $exception->getBody());
        }
    }

    public function testTransportFailurePropagatesAsRuntimeException(): void
    {
        $client = new DidClient(
            self::RESOURCE,
            null,
            self::ENDPOINT,
            function (): array {
                throw new RuntimeException('No response from the cloud.');
            }
        );
        $this->expectException(RuntimeException::class);
        $client->redeem('AzUxZC5jb20A', 'SEALED', 'C');
    }
}
