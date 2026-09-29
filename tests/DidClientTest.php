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
use fiftyone\pipeline\did\FodIdLayout;
use fiftyone\pipeline\did\FodIdParseStatus;
use fiftyone\pipeline\did\NotSupportedException;
use fiftyone\pipeline\did\SignatureCheck;
use fiftyone\pipeline\did\SignatureOutcome;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use RuntimeException;
use SwanCommunity\Owid\Crypto;
use SwanCommunity\Owid\ParseStatus;
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

    /**
     * The four factors cloud release 4.4.38 reports where it used to
     * report a single browser factor, in the order the cloud lists them.
     */
    private const BROWSER_FACTORS = [
        'platformname', 'platformversion', 'browsername', 'browserversion',
    ];

    /**
     * A redeem `factors` object as cloud release 4.4.38 sends it, holding
     * an operating system upgrade (a version mismatch beside a verified
     * name), a different browser (a mismatched name), and one factor the
     * service could not check.
     */
    private const NINE_FACTORS = [
        'transport' => 'verified', 'device' => 'mismatch',
        'browserip' => 'verified', 'connectionip' => 'verified',
        'asn' => 'verified',
        'platformname' => 'verified', 'platformversion' => 'mismatch',
        'browsername' => 'mismatch', 'browserversion' => 'misconfigured',
    ];

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

    /** A canonical Probabilistic payload, header plus a 32 byte match key. */
    private static function payload(): string
    {
        $matchKey = '';
        for ($i = 0; $i < FodIdLayout::MATCH_KEY_LENGTH; $i++) {
            $matchKey .= chr(0x20 + $i);
        }
        return chr(0x05) . pack('V', 0x12345678) . $matchKey;
    }

    /**
     * A 51Did dated as given and signed with the crypto given, so the
     * envelope carries a chosen date rather than the time of signing.
     */
    private function signedAt(
        DateTimeImmutable $date,
        Crypto $crypto,
        ?string $payload = null,
        Version $version = Version::Version3,
        string $domain = self::DOMAIN
    ): FodId {
        return FodId::fromOwid(Envelopes::owid(
            $crypto,
            $domain,
            $date,
            $payload ?? self::payload(),
            $version
        ));
    }

    /**
     * A well formed identifier in the URL-safe form a page sends, for the
     * tests whose subject is what the cloud answers rather than the value.
     */
    private function someId(): string
    {
        return $this->signedAt(self::at(self::T0), $this->keyA)->asBase64Url();
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

    /**
     * A moment as the cloud writes it, UTC with seven fractional digits.
     */
    private static function wire(DateTimeImmutable $at): string
    {
        return $at->setTimezone(new DateTimeZone('UTC'))
            ->format('Y-m-d\TH:i:s.u') . '0Z';
    }

    /**
     * One entry as the cloud's key endpoint answers it where it sends
     * `endsAt`.
     *
     * @return array<string, string>
     */
    private static function entry(
        DateTimeImmutable $startsAt,
        Crypto $crypto,
        DateTimeImmutable $endsAt
    ): array {
        return [
            'startsAt' => self::wire($startsAt),
            'endsAt' => self::wire($endsAt),
            'publicKey' => $crypto->publicKeyPem(),
        ];
    }

    /**
     * The same schedule as the cloud answers it where it publishes only
     * the keys whose period has started, each with its end. A from T0 to
     * T1 and B from T1 to T2, with C not yet published.
     *
     * @return array<int, array<string, string>>
     */
    private function startedSchedule(): array
    {
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        return [
            self::entry($t0, $this->keyA, $t1),
            self::entry($t1, $this->keyB, $t2),
        ];
    }

    /** The moment a recorded key request sent as `datetime`, or null. */
    private static function datetimeOf(array $request): ?int
    {
        $query = parse_url($request['url'], PHP_URL_QUERY);
        if (!is_string($query)) {
            return null;
        }
        parse_str($query, $values);
        return isset($values['datetime'])
            ? self::at($values['datetime'])->getTimestamp()
            : null;
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

    /**
     * The client's own boundary tolerance, read from the implementation so
     * that the selection rule and these tests cannot drift apart and the
     * figure lives in one place.
     */
    private static function tolerance(): int
    {
        return (new ReflectionClass(DidClient::class))
            ->getConstant('BOUNDARY_TOLERANCE_SECONDS');
    }

    /**
     * The shortest gap between fetches made for a date the keys held do
     * not reach or for a failed signature, read from the implementation
     * for the same reason as the tolerance.
     */
    private static function refetchInterval(): int
    {
        return (new ReflectionClass(DidClient::class))
            ->getConstant('REFETCH_INTERVAL_SECONDS');
    }

    /**
     * A creator domain longer than the public cloud's, as a self-hosted
     * container deployed under its own name would sign with.
     */
    private static function longDomain(): string
    {
        return str_repeat('creator-context-', 8) . 'example.com';
    }

    /** A payload with a creator context section longer than today's. */
    private static function longContextPayload(): string
    {
        return self::payload() . "\x00" . str_repeat("\xAB", 200);
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

    public function testPublicKeysReadsEndsAtWherePresent(): void
    {
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        $schedule = $this->schedule();
        $schedule[1]['endsAt'] = self::wire($t2);
        $schedule[2]['endsAt'] = null;
        $this->queueJson(200, $schedule);
        $keys = $this->client()->publicKeys();
        $this->assertCount(3, $keys);
        $this->assertNull($keys[0]->endsAt);
        $this->assertSame(
            $t1->getTimestamp(),
            $keys[1]->startsAt->getTimestamp()
        );
        $this->assertSame(
            $t2->getTimestamp(),
            $keys[1]->endsAt->getTimestamp()
        );
        $this->assertNull($keys[2]->endsAt);
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

    public function testPublicKeysInvalidJsonThrows(): void
    {
        $this->queue(200, 'not json');
        $this->expectException(RuntimeException::class);
        $this->client()->publicKeys();
    }

    public function testPublicKeysJsonObjectThrows(): void
    {
        $this->queue(200, '{"publicKey":"not a list"}');
        $this->expectException(RuntimeException::class);
        $this->client()->publicKeys();
    }

    public function testPublicKeysRejectsAnyMalformedEntry(): void
    {
        $malformed = [
            'not an object',
            ['publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => self::T0],
            ['startsAt' => 123, 'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => 'not a date',
                'publicKey' => $this->keyA->publicKeyPem()],
            // A loose word, an empty string or a space must not be read as
            // the current time, which would put a key that never existed at
            // the head of the schedule.
            ['startsAt' => '', 'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => ' ', 'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => 'now', 'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => 'x', 'publicKey' => $this->keyA->publicKeyPem()],
            // An end is read as strictly as a start, and comes after it.
            ['startsAt' => self::T0, 'endsAt' => self::T0,
                'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => self::T0, 'endsAt' => 123,
                'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => self::T0, 'endsAt' => '',
                'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => self::T0, 'endsAt' => 'now',
                'publicKey' => $this->keyA->publicKeyPem()],
            ['startsAt' => self::T0, 'endsAt' => '2026-08-02T00:00:00Z',
                'publicKey' => $this->keyA->publicKeyPem()],
        ];
        foreach ($malformed as $entry) {
            $schedule = $this->schedule();
            array_splice($schedule, 1, 0, [$entry]);
            $this->queueJson(200, $schedule);
            $client = $this->client();
            try {
                $client->publicKeys();
                $this->fail('Expected a malformed key entry to be rejected.');
            } catch (RuntimeException $exception) {
                $this->assertStringContainsString(
                    'Key list entry 1',
                    $exception->getMessage()
                );
            }
            $this->queueJson(200, $this->schedule());
            $this->assertCount(3, $client->publicKeys());
        }
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

    public function testPublicKeyForAnswersADateBeforeTheSchedule(): void
    {
        // The whole list holds every key published, so no fetch can find
        // a key for a date before its first.
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $before = self::shift(self::at(self::T0), -self::WEEK);
        $this->assertNull($client->publicKeyFor($this->signedAt($before, $this->keyA)));
        $this->assertCount(1, $this->requests);
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

    // ----- Key list end dates -----

    public function testNoRequestForDatesInsideTheNewestKeysPeriod(): void
    {
        // The newest entry carries its end, so every 51Did dated inside
        // its period verifies with the keys held, up to an hour before
        // that end.
        $t2 = self::shift(self::at(self::T0), 2 * self::WEEK);
        $this->now = $t2->getTimestamp() - 20 * 3600;
        $this->queueJson(200, $this->startedSchedule());
        $client = $this->client();
        $client->publicKeys();
        foreach ([19, 15, 10, 5, 1] as $hoursBeforeTheEnd) {
            $at = self::shift($t2, -$hoursBeforeTheEnd * 3600);
            $this->now = $at->getTimestamp();
            $this->assertSame(
                SignatureCheck::Verified,
                $client->verifySignatureDetailed(
                    $this->signedAt($at, $this->keyB)
                )
            );
        }
        $this->assertCount(1, $this->requests);
    }

    public function testOneFetchWhenADateReachesTheEndLessTheTolerance(): void
    {
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        $this->now = $t2->getTimestamp() - 2 * 3600;
        $this->queueJson(200, $this->startedSchedule());
        $client = $this->client();
        $client->publicKeys();
        // C starts at the end of B, and is published once the moment is
        // within the tolerance of that start.
        $at = self::shift($t2, -self::tolerance());
        $this->now = $at->getTimestamp();
        $this->queueJson(200, [
            self::entry($t1, $this->keyB, $t2),
            self::entry($t2, $this->keyC, self::shift($t2, self::WEEK)),
        ]);
        $fodId = $this->signedAt($at, $this->keyC);
        // publicKeyFor makes no signature check, so its fetch can only be
        // the one for a date at the end of the keys held less the
        // tolerance. B is still the key in force at that date.
        $this->assertSame(
            $this->keyB->publicKeyPem(),
            $client->publicKeyFor($fodId)->pem
        );
        $this->assertCount(2, $this->requests);
        // The first fetch held nothing and asked for every key. The second
        // asked for the entries from the newest start held.
        $this->assertNull(self::datetimeOf($this->requests[0]));
        $this->assertSame(
            $t1->getTimestamp(),
            self::datetimeOf($this->requests[1])
        );
        // The 51Did verifies with the newly published key and no further
        // request.
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed($fodId)
        );
        $this->assertCount(2, $this->requests);
        // Merged, with A kept although the answer left it out.
        $keys = $client->publicKeys();
        $this->assertSame(
            [
                $this->keyA->publicKeyPem(),
                $this->keyB->publicKeyPem(),
                $this->keyC->publicKeyPem(),
            ],
            array_map(static fn ($key): string => $key->pem, $keys)
        );
        $this->assertSame(
            self::shift($t2, self::WEEK)->getTimestamp(),
            $keys[2]->endsAt->getTimestamp()
        );
    }

    public function testNoRequestForACurrent51DidWithKeysPublishedAhead(): void
    {
        // No endsAt and keys ahead of their start, so the newest start
        // held, a week ahead, is the end of what the keys cover.
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $t1 = self::shift(self::at(self::T0), self::WEEK);
        foreach ([1, 6, 12, 18, 23] as $hours) {
            $at = self::shift($t1, $hours * 3600);
            $this->now = $at->getTimestamp();
            $this->assertSame(
                SignatureCheck::Verified,
                $client->verifySignatureDetailed(
                    $this->signedAt($at, $this->keyB)
                )
            );
        }
        $this->assertCount(1, $this->requests);
    }

    public function testDatesPastTheEndFetchAtMostOnceAMinute(): void
    {
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        $this->now = $t2->getTimestamp() - 2 * 3600;
        $this->queueJson(200, $this->startedSchedule());
        $client = $this->client();
        $client->publicKeys();
        // Signed with a key the cloud has not published, and dated far
        // enough past the end of B that the tolerance does not reach it.
        $unpublished = Crypto::new();
        $first = self::shift($t2, self::tolerance() + 3600);
        $this->now = $first->getTimestamp();
        $this->queueJson(200, [self::entry($t1, $this->keyB, $t2)]);
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed(
                $this->signedAt($first, $unpublished)
            )
        );
        $this->assertCount(2, $this->requests);
        // A second inside the minute, here with a forged date a month
        // ahead, is answered from the keys held.
        $this->now += 30;
        $forged = $this->signedAt(
            self::shift($t2, 30 * 24 * 3600),
            $unpublished
        );
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed($forged)
        );
        $this->assertNull($client->publicKeyFor($forged));
        $this->assertCount(2, $this->requests);
        // Once the minute has passed, such a date may fetch again.
        $this->now += self::refetchInterval();
        $this->queueJson(200, [self::entry($t1, $this->keyB, $t2)]);
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed($forged)
        );
        $this->assertCount(3, $this->requests);
    }

    public function testALaterAnswerWithAnEndReplacesTheEntryWithout(): void
    {
        $t0 = self::at(self::T0);
        $t2 = self::shift($t0, 2 * self::WEEK);
        $t3 = self::shift($t0, 3 * self::WEEK);
        // Held without ends, with C ahead of its start.
        $this->now = $t2->getTimestamp() - 2 * 3600;
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        // A date within the tolerance of C's start, where the keys held
        // stop, asks for the entries from that start, and the answer
        // carries C's end.
        $at = self::shift($t2, -self::tolerance());
        $this->now = $at->getTimestamp();
        $this->queueJson(200, [self::entry($t2, $this->keyC, $t3)]);
        $this->assertSame(
            $this->keyB->publicKeyPem(),
            $client->publicKeyFor($this->signedAt($at, $this->keyB))->pem
        );
        $this->assertCount(2, $this->requests);
        $this->assertSame(
            $t2->getTimestamp(),
            self::datetimeOf($this->lastRequest())
        );
        $keys = $client->publicKeys();
        $this->assertCount(3, $keys);
        $this->assertNull($keys[0]->endsAt);
        $this->assertNull($keys[1]->endsAt);
        $this->assertSame(
            $t3->getTimestamp(),
            $keys[2]->endsAt->getTimestamp()
        );
        // The keys held now reach C's end, so a date in C's period makes no
        // request, where C's start alone would have been reached.
        $inC = self::shift($t2, 3600);
        $this->now = $inC->getTimestamp();
        $this->assertSame(
            $this->keyC->publicKeyPem(),
            $client->publicKeyFor($this->signedAt($inC, $this->keyC))->pem
        );
        $this->assertCount(2, $this->requests);
    }

    public function testAKeyReplacedMidPeriodIsPickedUpOnTheFirstFailure(): void
    {
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        $replacedAt = self::shift($t1, 3 * 24 * 3600);
        $this->now = $replacedAt->getTimestamp() - 3600;
        $this->queueJson(200, $this->startedSchedule());
        $client = $this->client();
        $client->publicKeys();
        // B is replaced part way through its period. B's entry now ends at
        // the replacement's start, and the replacement runs to T2.
        $replacement = Crypto::new();
        $at = self::shift($replacedAt, 2 * 3600);
        $this->now = $at->getTimestamp();
        $this->queueJson(200, [
            self::entry($t1, $this->keyB, $replacedAt),
            self::entry($replacedAt, $replacement, $t2),
        ]);
        // A genuine 51Did from the replacement fails with B, which the keys
        // held still have in force, so the list is fetched once and the
        // check made again.
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed(
                $this->signedAt($at, $replacement)
            )
        );
        $this->assertCount(2, $this->requests);
        $this->assertSame(
            $t1->getTimestamp(),
            self::datetimeOf($this->lastRequest())
        );
        // One signed with B and dated after the replacement is refused.
        $oldKey = $this->signedAt($at, $this->keyB);
        $this->assertSame(
            SignatureCheck::Invalid,
            $client->verifySignatureDetailed($oldKey)
        );
        $this->assertCount(2, $this->requests);
        // A minute on, the refusal stands against a fresh list, fetched
        // once.
        $this->now += self::refetchInterval();
        $this->queueJson(200, [
            self::entry($t1, $this->keyB, $replacedAt),
            self::entry($replacedAt, $replacement, $t2),
        ]);
        $this->assertSame(
            SignatureCheck::Invalid,
            $client->verifySignatureDetailed($oldKey)
        );
        $this->assertCount(3, $this->requests);
        // One signed with B before the replacement still verifies, and so
        // does one dated inside the tolerance after the replacement starts,
        // where B stays a neighbouring candidate as the cloud's own
        // selection has it.
        $before = self::shift($replacedAt, -2 * 3600);
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed(
                $this->signedAt($before, $this->keyB)
            )
        );
        $justAfter = self::shift($replacedAt, self::tolerance() - 60);
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed(
                $this->signedAt($justAfter, $this->keyB)
            )
        );
        $this->assertCount(3, $this->requests);
    }

    public function testTheFetchAfterAFailureAsksFromTheKeyForTheDate(): void
    {
        // Held without ends, with C ahead of its start, so the newest start
        // held is C's and not the start of B, the key for the date.
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $t1 = self::shift(self::at(self::T0), self::WEEK);
        $t2 = self::shift($t1, self::WEEK);
        $replacedAt = self::shift($t1, 6 * 3600);
        $replacement = Crypto::new();
        $at = self::shift($replacedAt, 2 * 3600);
        $this->now = $at->getTimestamp();
        // Asking from B's start brings B's moved end and its replacement.
        $this->queueJson(200, [
            self::entry($t1, $this->keyB, $replacedAt),
            self::entry($replacedAt, $replacement, $t2),
        ]);
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed(
                $this->signedAt($at, $replacement)
            )
        );
        $this->assertCount(2, $this->requests);
        $this->assertSame(
            $t1->getTimestamp(),
            self::datetimeOf($this->lastRequest())
        );
    }

    public function testOnlyTheDailyRefreshFetchesTheWholeList(): void
    {
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        $t3 = self::shift($t0, 3 * self::WEEK);
        $primedAt = $t2->getTimestamp() - DidClient::KEY_LIST_MAX_AGE_SECONDS
            + 300;
        $this->now = $primedAt;
        $this->queueJson(200, $this->startedSchedule());
        $client = $this->client();
        $client->publicKeys();
        // Just before the list is a day old, a date past the end of B asks
        // for the entries from B's start.
        $this->now = $primedAt + DidClient::KEY_LIST_MAX_AGE_SECONDS - 10;
        $at = self::at('@' . $this->now);
        $this->queueJson(200, [
            self::entry($t1, $this->keyB, $t2),
            self::entry($t2, $this->keyC, $t3),
        ]);
        $fodId = $this->signedAt($at, $this->keyC);
        $this->assertSame(
            $this->keyC->publicKeyPem(),
            $client->publicKeyFor($fodId)->pem
        );
        $this->assertSame(
            $t1->getTimestamp(),
            self::datetimeOf($this->requests[1])
        );
        // That fetch left the age alone, so the whole list is fetched when
        // the day is up, and the minute since that fetch does not hold it
        // back.
        $this->now += 11;
        $this->queueJson(200, [
            self::entry($t0, $this->keyA, $t1),
            self::entry($t1, $this->keyB, $t2),
            self::entry($t2, $this->keyC, $t3),
        ]);
        $client->publicKeyFor($fodId);
        $this->assertCount(3, $this->requests);
        $this->assertNull(self::datetimeOf($this->requests[2]));
        // The whole list resets the age, so a lookup an hour later makes
        // no request.
        $this->now += 3600;
        $client->publicKeyFor($fodId);
        $this->assertCount(3, $this->requests);
    }

    public function testTheDailyRefreshPicksUpAReplacedKeyStillTrusted(): void
    {
        // Held without ends, with C ahead of its start. B is replaced part
        // way through its period after the list was fetched.
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $t0 = self::at(self::T0);
        $t1 = self::shift($t0, self::WEEK);
        $t2 = self::shift($t0, 2 * self::WEEK);
        $replacedAt = self::shift($t1, 6 * 3600);
        $replacement = Crypto::new();
        $at = self::shift($replacedAt, 2 * 3600);
        $oldKey = $this->signedAt($at, $this->keyB);
        // Until the list is a day old, a 51Did signed with B after the
        // replacement still verifies with the keys held.
        $this->now = $at->getTimestamp();
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed($oldKey)
        );
        $this->assertCount(1, $this->requests);
        // The daily fetch of the whole list brings B's moved end and its
        // replacement, and the same 51Did is then refused.
        $this->now = $t1->getTimestamp()
            + DidClient::KEY_LIST_MAX_AGE_SECONDS + 1;
        $this->queueJson(200, [
            self::entry($t0, $this->keyA, $t1),
            self::entry($t1, $this->keyB, $replacedAt),
            self::entry($replacedAt, $replacement, $t2),
        ]);
        $this->assertSame(
            SignatureCheck::Invalid,
            $client->verifySignatureDetailed($oldKey)
        );
        $this->assertCount(2, $this->requests);
        $this->assertNull(self::datetimeOf($this->lastRequest()));
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed(
                $this->signedAt($at, $replacement)
            )
        );
        $this->assertCount(2, $this->requests);
    }

    public function testAFailureOutsideTheKeysHeldMakesNoRequest(): void
    {
        // Just before the first key, which the tolerance makes a candidate
        // although no key held starts by then. With no key for the date
        // there is no replacement to ask for.
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $before = self::shift(self::at(self::T0), -(self::tolerance() - 60));
        $this->assertSame(
            SignatureCheck::Invalid,
            $client->verifySignatureDetailed(
                $this->signedAt($before, $this->keyC)
            )
        );
        $this->assertCount(1, $this->requests);
    }

    public function testAnEmptyListIsFetchedAgainAtMostOnceAMinute(): void
    {
        // An empty answer has no end, so the next lookup fetches again,
        // with no datetime because no start is held, and the one after
        // waits a minute.
        $this->queueJson(200, []);
        $client = $this->client();
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $fodId = $this->signedAt($inside, $this->keyB);
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed($fodId)
        );
        $this->queueJson(200, []);
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed($fodId)
        );
        $this->assertCount(2, $this->requests);
        $this->assertNull(self::datetimeOf($this->lastRequest()));
        $this->now += 30;
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed($fodId)
        );
        $this->assertCount(2, $this->requests);
        // A minute on, the keys now published verify.
        $this->now += self::refetchInterval();
        $this->queueJson(200, $this->schedule());
        $this->assertSame(
            SignatureCheck::Verified,
            $client->verifySignatureDetailed($fodId)
        );
        $this->assertCount(3, $this->requests);
    }

    public function testAFailedFetchAlsoWaitsTheMinute(): void
    {
        // The time of a fetch limited to once a minute is recorded before
        // the request, so a cloud that cannot answer is not asked again on
        // every lookup. The failure itself is raised, as for any key fetch.
        $t2 = self::shift(self::at(self::T0), 2 * self::WEEK);
        $this->now = $t2->getTimestamp() - 2 * 3600;
        $this->queueJson(200, $this->startedSchedule());
        $client = $this->client();
        $client->publicKeys();
        $past = self::shift($t2, self::tolerance() + 3600);
        $this->now = $past->getTimestamp();
        $fodId = $this->signedAt($past, Crypto::new());
        $this->queue(500, 'key service down');
        try {
            $client->verifySignatureDetailed($fodId);
            $this->fail('Expected a CloudException.');
        } catch (CloudException $exception) {
            $this->assertSame(500, $exception->getStatusCode());
        }
        $this->now += 30;
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed($fodId)
        );
        $this->assertCount(2, $this->requests);
    }

    public function testAClockSetBackDoesNotHoldAFetchBack(): void
    {
        $t2 = self::shift(self::at(self::T0), 2 * self::WEEK);
        $this->now = $t2->getTimestamp() - 2 * 3600;
        $this->queueJson(200, $this->startedSchedule());
        $client = $this->client();
        $client->publicKeys();
        $past = $this->signedAt(
            self::shift($t2, self::tolerance() + 3600),
            Crypto::new()
        );
        $this->queueJson(200, $this->startedSchedule());
        $client->publicKeyFor($past);
        $this->assertCount(2, $this->requests);
        // Set back an hour, so the clock reads before that fetch, and the
        // next date past the end still fetches.
        $this->now -= 3600;
        $this->queueJson(200, $this->startedSchedule());
        $client->publicKeyFor($past);
        $this->assertCount(3, $this->requests);
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
        $tolerance = self::tolerance();
        // A minute inside the tolerance, where the earlier key is tried,
        // and an hour outside it, where it is not. The two sit far apart on
        // purpose, because a pair of dates a minute either side of the real
        // figure would tell a reader where that figure falls.
        $justAfter = self::shift($boundary, $tolerance - 60);
        $this->assertTrue($client->verifySignature(
            $this->signedAt($justAfter, $this->keyA)
        ));
        $wellAfter = self::shift($boundary, $tolerance + 3600);
        // The failure is checked once more against a fresh answer.
        $this->queueJson(200, $this->schedule());
        $this->assertFalse($client->verifySignature(
            $this->signedAt($wellAfter, $this->keyA)
        ));
        $this->assertCount(2, $this->requests);
    }

    public function testLaterNeighbourAcceptedWithinToleranceBeforeBoundary(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $boundary = self::shift(self::at(self::T0), self::WEEK);
        $tolerance = self::tolerance();
        // A minute inside the tolerance and an hour outside it, as above.
        $justBefore = self::shift($boundary, -($tolerance - 60));
        $this->assertTrue($client->verifySignature(
            $this->signedAt($justBefore, $this->keyB)
        ));
        $wellBefore = self::shift($boundary, -($tolerance + 3600));
        // The failure is checked once more against a fresh answer.
        $this->queueJson(200, $this->schedule());
        $this->assertFalse($client->verifySignature(
            $this->signedAt($wellBefore, $this->keyB)
        ));
        $this->assertCount(2, $this->requests);
    }

    public function testNoCandidateBeforeTheSchedule(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        // Primed, so the request count below shows that a date nothing
        // covers is answered from the keys held.
        $client->publicKeys();
        $tolerance = self::tolerance();
        // Far enough before the first key that the tolerance does not
        // reach the date, so nothing in the schedule can have signed it.
        $before = self::shift(self::at(self::T0), -($tolerance + 3600));
        $fodId = $this->signedAt($before, $this->keyA);
        $this->assertFalse($client->verifySignature($fodId));
        $this->assertNull($client->publicKeyFor($fodId));
        $this->assertCount(1, $this->requests);
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
        $payload = chr(0b1100_0001)
            . str_repeat("\x00", FodIdLayout::HEADER_LENGTH - 1);
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

    public function testVerifySignatureTrueForALongContextSection(): void
    {
        // The service accepts a context section of a version it does not
        // implement at any length, so an older verifier keeps working when
        // a newer version ships, and this client must do the same.
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $this->assertTrue($this->client()->verifySignature(
            $this->signedAt($inside, $this->keyB, self::longContextPayload())
        ));
    }

    public function testVerifySignatureTrueForALongCreatorDomain(): void
    {
        // The creator domain is a deployment parameter, so a self-hosted
        // container may sign with a longer one and its identifiers must
        // still verify.
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $fodId = $this->signedAt(
            $inside,
            $this->keyB,
            null,
            Version::Version3,
            self::longDomain()
        );
        $this->assertSame(self::longDomain(), $fodId->getDomain());
        $this->assertTrue($this->client()->verifySignature($fodId));
    }

    public function testVerifySignatureFalseForATamperedSignature(): void
    {
        // Structurally sound and cryptographically wrong. The value reads
        // as a 51Did and the offline check then says it does not verify.
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $raw = $this->signedAt($inside, $this->keyB)->asByteArray();
        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\xFF";
        $read = FodId::tryFromByteArray($raw);
        $this->assertTrue($read->ok);
        $this->assertSame(ParseStatus::Parsed, $read->status);
        $this->assertFalse($this->client()->verifySignature($read->fodId));
    }

    public function testKeyEndpointFailureIsRaisedAndNeverAnInvalidSignature(): void
    {
        // A key that cannot be obtained leaves the signature unjudged, so
        // the answer is the failure itself and not false.
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $fodId = $this->signedAt($inside, $this->keyB);
        $this->queue(500, 'key service down');
        try {
            $this->client()->verifySignature($fodId);
            $this->fail('Expected a CloudException.');
        } catch (CloudException $exception) {
            $this->assertSame(500, $exception->getStatusCode());
        }
        $unreachable = new DidClient(
            self::RESOURCE,
            null,
            self::ENDPOINT,
            function (): array {
                throw new RuntimeException('No response from the cloud.');
            }
        );
        $this->expectException(RuntimeException::class);
        $unreachable->verifySignature($fodId);
    }

    public function testVerifySignatureTrueForRandomIdentifier(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $payload = chr((1 << 6) | 0b001) . pack('V', 1)
            . str_repeat("\x42", FodIdLayout::GUID_LENGTH);
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
        $this->assertFalse($this->client()->verify($this->someId()));
    }

    public function testVerifyErrorsThrowsWithTheCloudMessage(): void
    {
        // A value that reads as a 51Did here can still be refused by the
        // cloud, and then the cloud's own message is what the caller sees.
        $this->queueJson(400, ['errors' => [self::NOT_A_51DID]]);
        try {
            $this->client()->verify($this->someId());
            $this->fail('Expected an InvalidArgumentException.');
        } catch (InvalidArgumentException $exception) {
            $this->assertStringContainsString(
                self::NOT_A_51DID,
                $exception->getMessage()
            );
        }
        $this->assertCount(1, $this->requests);
    }

    /**
     * Values that are not a 51Did, each with the status the read reports,
     * so a test can show the reason reached the caller unchanged.
     *
     * @return array<int, array{string, ParseStatus|FodIdParseStatus}>
     */
    private function malformedValues(): array
    {
        // A sound envelope whose payload is one byte short for its type,
        // written as bytes because no FodId can exist for it.
        $short = Envelopes::bytes(
            $this->keyA,
            self::DOMAIN,
            self::at(self::T0),
            substr(self::payload(), 0, FodIdLayout::PAYLOAD_LENGTH - 1)
        );
        $good = $this->signedAt(self::at(self::T0), $this->keyA)->asByteArray();
        return [
            ['not a 51did', ParseStatus::InvalidBase64],
            ['AzUxZC5jb20A', ParseStatus::UnexpectedEnd],
            ['', ParseStatus::MissingInput],
            [base64_encode("\x00"), ParseStatus::AbsentNode],
            [base64_encode($good . "\x00"), ParseStatus::ByteCountMismatch],
            [base64_encode($short), FodIdParseStatus::InvalidTypePayloadLength],
        ];
    }

    public function testVerifyRefusesAMalformedValueBeforeAnyRequest(): void
    {
        foreach ($this->malformedValues() as [$value, $status]) {
            // A key list is queued so that a fetch, were one attempted,
            // would succeed and be counted rather than fail for want of an
            // answer.
            $this->requests = [];
            $this->queueJson(200, $this->schedule());
            try {
                $this->client()->verify($value);
                $this->fail('Expected a malformed value to be refused.');
            } catch (InvalidArgumentException $exception) {
                $this->assertStringContainsString(
                    $status->value,
                    $exception->getMessage()
                );
                $this->assertStringNotContainsString(
                    'far longer',
                    $exception->getMessage()
                );
            }
            // Neither a key fetch nor the verify call reached the transport.
            $this->assertCount(0, $this->requests);
        }
    }

    public function testRedeemRefusesAMalformedValueBeforeAnyRequest(): void
    {
        foreach ($this->malformedValues() as [$value, $status]) {
            $this->requests = [];
            $this->queueJson(200, $this->schedule());
            try {
                $this->client()->redeem($value, 'SEALED', 'C');
                $this->fail('Expected a malformed value to be refused.');
            } catch (InvalidArgumentException $exception) {
                $this->assertStringContainsString(
                    $status->value,
                    $exception->getMessage()
                );
            }
            $this->assertCount(0, $this->requests);
        }
    }

    public function testAWellFormedStringIsSentAsGiven(): void
    {
        // The read is a check and not a rewrite. The cloud receives the
        // value in whichever alphabet the caller was handed.
        $fodId = $this->signedAt(self::at(self::T0), $this->keyA);
        foreach ([$fodId->asBase64(), $fodId->asBase64Url()] as $given) {
            $this->queueJson(200, ['valid' => true]);
            $this->assertTrue($this->client()->verify($given));
            $this->assertSame(
                self::ENDPOINT . 'id/verify/' . self::RESOURCE
                    . '?51did=' . rawurlencode($given)
                    . '&owid=' . rawurlencode($given),
                $this->lastRequest()['url']
            );
        }
    }

    public function testVerifyAcceptsPaddedAndUnpaddedValues(): void
    {
        // A long domain and a long context section change nothing about
        // which forms the cloud is sent.
        $fodId = $this->signedAt(
            self::at(self::T0),
            $this->keyA,
            self::longContextPayload(),
            Version::Version3,
            self::longDomain()
        );
        $padded = $fodId->asBase64();
        $unpadded = $fodId->asBase64Url();
        $this->assertSame(rtrim(strtr($padded, '+/', '-_'), '='), $unpadded);
        $this->queueJson(200, ['valid' => true]);
        $this->queueJson(200, ['valid' => true]);
        $client = $this->client();
        $this->assertTrue($client->verify($padded));
        $this->assertTrue($client->verify($unpadded));
        $this->assertCount(2, $this->requests);
    }

    public function testVerifyRefusesAnAbsurdlyLongValueBeforeTransport(): void
    {
        // The guard is client policy and fires before the value is read, so
        // the message names the length and not a parse status, even for a
        // value that would also fail to read.
        foreach ([str_repeat('A', 8192), str_repeat('!', 8192)] as $value) {
            try {
                $this->client()->verify($value);
                $this->fail('Expected an InvalidArgumentException.');
            } catch (InvalidArgumentException $exception) {
                $this->assertStringContainsString(
                    'far longer',
                    $exception->getMessage()
                );
                $this->assertStringNotContainsString(
                    'not a 51Did',
                    $exception->getMessage()
                );
            }
        }
        // Neither a key fetch nor the verify call reached the transport.
        $this->assertCount(0, $this->requests);
    }

    public function testVerifyOtherStatusThrowsCloudException(): void
    {
        $this->queue(500, 'boom');
        $this->expectException(CloudException::class);
        $this->client()->verify($this->someId());
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
        $this->client(null)->redeem($this->someId(), 'SEALED', '');
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
            'factors' => self::NINE_FACTORS,
            'verifiedAt' => '2026-08-07T09:15:32Z',
            'secondsSinceVerified' => 2,
        ]);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Mismatch, $result->context);
        $this->assertSame(SignatureOutcome::Verified, $result->signature);
        $this->assertSame(FactorOutcome::Verified, $result->factors['transport']);
        $this->assertSame(FactorOutcome::Mismatch, $result->factors['device']);
        $this->assertCount(9, $result->factors);
        $this->assertSame(
            '2026-08-07T09:15:32Z',
            $result->verifiedAt->format('Y-m-d\TH:i:s\Z')
        );
        $this->assertSame(2, $result->secondsSinceVerified);
        $this->assertSame(200, $result->statusCode);
        $this->assertSame('mismatch', $result->rawContext);
        $this->assertSame(
            self::NINE_FACTORS,
            $result->toArray()['factors']
        );
    }

    /**
     * Cloud release 4.4.38 split the browser factor into four. Each of the
     * four is read under its own name with its own outcome, so a version
     * mismatch beside a verified name (an upgrade) is told apart from a
     * mismatched name (a different operating system or browser), and a
     * misconfigured factor stays misconfigured rather than reading as a
     * mismatch.
     */
    public function testRedeemReadsTheFourBrowserFactors(): void
    {
        $this->queueJson(200, [
            'signature' => 'verified',
            'context' => 'mismatch',
            'factors' => self::NINE_FACTORS,
            'verifiedAt' => '2026-08-07T09:15:32Z',
            'secondsSinceVerified' => 2,
        ]);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(
            [
                'transport', 'device', 'browserip', 'connectionip', 'asn',
                'platformname', 'platformversion', 'browsername',
                'browserversion',
            ],
            array_keys($result->factors)
        );
        $this->assertSame(
            FactorOutcome::Verified,
            $result->factors['platformname']
        );
        $this->assertSame(
            FactorOutcome::Mismatch,
            $result->factors['platformversion']
        );
        $this->assertSame(
            FactorOutcome::Mismatch,
            $result->factors['browsername']
        );
        $this->assertSame(
            FactorOutcome::Misconfigured,
            $result->factors['browserversion']
        );
        $this->assertArrayNotHasKey('browser', $result->factors);
    }

    /**
     * A factor the creating service recorded no value for reads as
     * {@see FactorOutcome::NotRecorded}, which is its own outcome and
     * neither a mismatch nor misconfigured, so the three sit side by side
     * in one answer without being confused for each other.
     */
    public function testRedeemReadsANotRecordedFactorAsItsOwnOutcome(): void
    {
        $factors = [
            'transport' => 'notrecorded', 'device' => 'verified',
            'browserip' => 'mismatch', 'connectionip' => 'verified',
            'asn' => 'misconfigured',
            'platformname' => 'verified',
            'platformversion' => 'notrecorded',
            'browsername' => 'verified', 'browserversion' => 'verified',
        ];
        $this->queueJson(200, [
            'signature' => 'verified',
            'context' => 'mismatch',
            'factors' => $factors,
        ]);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(
            FactorOutcome::NotRecorded,
            $result->factors['transport']
        );
        $this->assertSame(
            FactorOutcome::NotRecorded,
            $result->factors['platformversion']
        );
        $this->assertSame(
            FactorOutcome::Mismatch,
            $result->factors['browserip']
        );
        $this->assertSame(
            FactorOutcome::Misconfigured,
            $result->factors['asn']
        );
        $this->assertSame(
            FactorOutcome::Verified,
            $result->factors['device']
        );
        $this->assertNotSame(
            FactorOutcome::Mismatch,
            $result->factors['transport'],
            'a factor with no recorded value is not a mismatch'
        );
        $this->assertNotSame(
            FactorOutcome::Misconfigured,
            $result->factors['transport'],
            'a factor with no recorded value is not misconfigured'
        );
        $this->assertSame($factors, $result->toArray()['factors']);
    }

    /**
     * A factor value the package does not know still reads as a mismatch,
     * so adding notrecorded has not turned an unexpected word into a pass
     * or into an outcome that says nothing was checked.
     */
    public function testRedeemReadsAnUnknownFactorValueAsAMismatch(): void
    {
        $this->queueJson(200, [
            'signature' => 'verified',
            'context' => 'mismatch',
            'factors' => ['transport' => 'somethingnewer'],
        ]);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(
            FactorOutcome::Mismatch,
            $result->factors['transport']
        );
    }

    /** Every outcome carries the cloud's own word for itself. */
    public function testTheFactorOutcomesAreTheWordsTheCloudWrites(): void
    {
        $this->assertSame(
            ['verified', 'mismatch', 'misconfigured', 'notrecorded'],
            array_map(
                static fn (FactorOutcome $o): string => $o->value,
                FactorOutcome::cases()
            )
        );
    }

    /**
     * A body carrying only the single browser factor that releases before
     * 4.4.38 sent does not populate any of the four that replaced it, so
     * an old answer is never read as a verdict on the new factors.
     */
    public function testRedeemWithOnlyTheOldBrowserFactorPopulatesNoneOfTheFour(): void
    {
        $this->queueJson(200, [
            'signature' => 'verified',
            'context' => 'mismatch',
            'factors' => ['transport' => 'verified', 'device' => 'verified',
                'browserip' => 'verified', 'connectionip' => 'verified',
                'asn' => 'verified', 'browser' => 'mismatch'],
            'verifiedAt' => '2026-08-07T09:15:32Z',
            'secondsSinceVerified' => 2,
        ]);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertCount(6, $result->factors);
        foreach (self::BROWSER_FACTORS as $name) {
            $this->assertArrayNotHasKey($name, $result->factors, $name);
        }
    }

    public function testRedeemedWithoutFactors(): void
    {
        $body = ['signature' => 'invalid', 'context' => 'verified',
            'verifiedAt' => '2026-08-07T09:15:32Z', 'secondsSinceVerified' => 0];
        $this->queueJson(200, $body);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
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
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Expired, $result->context);
        $this->assertSame(SignatureOutcome::Unknown, $result->signature);
        $this->assertSame(14, $result->secondsSinceVerified);
        $this->assertNotNull($result->verifiedAt);
        $this->assertArrayNotHasKey('signature', $result->toArray());
    }

    public function testRedeemReplayed(): void
    {
        $this->queueJson(200, ['context' => 'replayed']);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Replayed, $result->context);
        $this->assertNull($result->verifiedAt);
        $this->assertNull($result->secondsSinceVerified);
        $this->assertSame(['context' => 'replayed'], $result->toArray());
    }

    public function testRedeemUnreadable(): void
    {
        $this->queueJson(200, ['context' => 'unreadable']);
        $result = $this->client()->redeem($this->someId(), 'not-base64url!!', 'C');
        $this->assertSame(ContextOutcome::Unreadable, $result->context);
        $this->assertSame(200, $result->statusCode);
    }

    public function testRedeemUnconfirmedIs503(): void
    {
        $this->queueJson(503, ['context' => 'unconfirmed']);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Unconfirmed, $result->context);
        $this->assertSame(503, $result->statusCode);
    }

    public function testRedeemUnknownContextFailsClosedAndKeepsTheRaw(): void
    {
        $this->queueJson(200, ['context' => 'somethingnew']);
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Unreadable, $result->context);
        $this->assertSame('somethingnew', $result->rawContext);
    }

    public function testRedeemNonJsonBodyFailsClosed(): void
    {
        $this->queue(200, '<html>proxy</html>');
        $result = $this->client()->redeem($this->someId(), 'SEALED', 'C');
        $this->assertSame(ContextOutcome::Unreadable, $result->context);
        $this->assertSame('', $result->rawContext);
        $this->assertSame('<html>proxy</html>', $result->raw);
    }

    public function testRedeem400ThrowsWithTheCloudErrors(): void
    {
        $this->queueJson(400, ['errors' => [self::NOT_A_51DID]]);
        try {
            $this->client()->redeem($this->someId(), 'SEALED', 'C');
            $this->fail('Expected an InvalidArgumentException.');
        } catch (InvalidArgumentException $exception) {
            $this->assertStringContainsString(
                self::NOT_A_51DID,
                $exception->getMessage()
            );
        }
    }

    public function testRedeemRefusesAnAbsurdlyLongValueBeforeTransport(): void
    {
        try {
            $this->client()->redeem(str_repeat('A', 8192), 'SEALED', 'C');
            $this->fail('Expected an InvalidArgumentException.');
        } catch (InvalidArgumentException $exception) {
            $this->assertStringContainsString(
                'far longer',
                $exception->getMessage()
            );
        }
        // Neither a key fetch nor the redeem call reached the transport.
        $this->assertCount(0, $this->requests);
    }

    public function testRedeem404ThrowsNotSupported(): void
    {
        $this->queue(404, '');
        try {
            $this->client()->redeem($this->someId(), 'SEALED', 'C');
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
            $this->client()->redeem($this->someId(), 'SEALED', 'C');
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
        $client->redeem($this->someId(), 'SEALED', 'C');
    }

    // ----- Detailed offline verification -----

    // The five outcomes of verifySignatureDetailed, which say which of
    // the things verifySignature collapses into false actually happened.
    // The .NET, Java and Python packages report the same five.

    public function testDetailedVerifiedWithTheKeyInForce(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $this->assertSame(
            SignatureCheck::Verified,
            $this->client()->verifySignatureDetailed(
                $this->signedAt($inside, $this->keyB)
            )
        );
    }

    public function testDetailedInvalidWithTheWrongKey(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $this->assertSame(
            SignatureCheck::Invalid,
            $this->client()->verifySignatureDetailed(
                $this->signedAt($inside, $this->keyC)
            )
        );
    }

    public function testDetailedUnsupportedVersionForVersion2(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $fodId = $this->signedAt(
            $inside, $this->keyB, null, Version::Version2
        );
        $this->assertSame(
            SignatureCheck::UnsupportedVersion,
            $this->client()->verifySignatureDetailed($fodId)
        );
        // Refused before any key is fetched, as verifySignature is.
        $this->assertCount(0, $this->requests);
    }

    public function testDetailedInvalidLengthForShortPayload(): void
    {
        $this->queueJson(200, $this->schedule());
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        // A Reserved type header-only payload parses as a FodId but is
        // shorter than the base for a 32 byte match key.
        $payload = chr(0b1100_0001)
            . str_repeat("\x00", FodIdLayout::HEADER_LENGTH - 1);
        $fodId = $this->signedAt($inside, $this->keyB, $payload);
        $this->assertSame(
            SignatureCheck::InvalidLength,
            $this->client()->verifySignatureDetailed($fodId)
        );
        $this->assertCount(0, $this->requests);
    }

    public function testDetailedNoKeyForDateBeforeTheSchedule(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $before = self::shift(
            self::at(self::T0), -(self::tolerance() + 3600)
        );
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $client->verifySignatureDetailed(
                $this->signedAt($before, $this->keyA)
            )
        );
        $this->assertCount(1, $this->requests);
    }

    // A date nothing covers must never be reported as forged, because
    // the signature was not examined at all. This is the distinction
    // verifySignature cannot express, and the reason this method exists.
    public function testNoKeyForDateIsNotReportedAsInvalid(): void
    {
        $this->queueJson(200, $this->schedule());
        $client = $this->client();
        $client->publicKeys();
        $before = self::shift(
            self::at(self::T0), -(self::tolerance() + 3600)
        );
        $outcome = $client->verifySignatureDetailed(
            $this->signedAt($before, $this->keyA)
        );
        $this->assertNotSame(SignatureCheck::Invalid, $outcome);
        $this->assertSame(SignatureCheck::NoKeyForDate, $outcome);
        $this->assertCount(1, $this->requests);
    }

    // An endpoint that publishes no keys at all is the other way to have
    // no key for the date, and it is not a forgery either.
    public function testDetailedNoKeyForDateWhenNothingIsPublished(): void
    {
        $this->queueJson(200, []);
        $this->queueJson(200, []);
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        $this->assertSame(
            SignatureCheck::NoKeyForDate,
            $this->client()->verifySignatureDetailed(
                $this->signedAt($inside, $this->keyB)
            )
        );
    }

    // verifySignature is true for exactly the Verified outcome and false
    // for every other, so the two can never disagree.
    public function testVerifySignatureAgreesWithTheDetailedOutcome(): void
    {
        $inside = self::shift(self::at(self::T0), self::WEEK + 3600);
        foreach ([$this->keyB, $this->keyC] as $key) {
            // An answer for the first fetch, and one for the check a
            // failure makes once more on the second call.
            $this->responses = [];
            $this->queueJson(200, $this->schedule());
            $this->queueJson(200, $this->schedule());
            $client = $this->client();
            $fodId = $this->signedAt($inside, $key);
            $outcome = $client->verifySignatureDetailed($fodId);
            $this->assertSame(
                $outcome === SignatureCheck::Verified,
                $client->verifySignature($fodId)
            );
        }
    }

    // Every case is distinct, so a caller can tell them apart, and the
    // backing string is the cross language name of the outcome.
    public function testTheFiveOutcomesAreDistinct(): void
    {
        $cases = SignatureCheck::cases();
        $this->assertCount(5, $cases);
        $values = array_map(
            static fn (SignatureCheck $c): string => $c->value,
            $cases
        );
        $this->assertSame($values, array_unique($values));
        foreach ($cases as $case) {
            $this->assertSame($case->name, $case->value);
        }
    }
}
