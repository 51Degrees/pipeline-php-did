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

namespace fiftyone\pipeline\did;

use Closure;
use Composer\InstalledVersions;
use DateTimeImmutable;
use InvalidArgumentException;
use JsonException;
use RuntimeException;
use SwanCommunity\Owid\Version;
use Throwable;

/**
 * Client for every manipulation of a 51Did a server needs against the
 * 51Degrees cloud, so server code never hand-writes HTTP or key handling.
 *
 * 1. Fetches the signing public keys, holds them, and picks the key in
 *    force when a given 51Did was created ({@see DidClient::publicKeys()}
 *    and {@see DidClient::publicKeyFor()}).
 * 2. Verifies a 51Did's signature offline against that key
 *    ({@see DidClient::verifySignature()}).
 * 3. Verifies a 51Did's signature through the cloud's verify endpoint
 *    ({@see DidClient::verify()}).
 * 4. Redeems a sealed creator context result on the server, with the
 *    licence key, and returns a typed {@see RedeemResult}
 *    ({@see DidClient::redeem()}).
 *
 * Creating a 51Did is not part of this client. Creation is the cloud `json`
 * endpoint, and a page creates from the browser because the identifier
 * describes the browser's own connection. The verify-context and
 * verify-full endpoints are browser calls for the same reason.
 *
 * Credentials never appear in a URL. The key list and verify calls are
 * GETs with the resource key in the route (`id/key/{resource}` and
 * `id/verify/{resource}`). Redeem is a POST to `id/redeem` whose form body
 * carries the resource key beside the licence key, because a query string
 * is written to access logs and the cloud's POST route takes the resource
 * key from the form rather than the path.
 *
 * The cloud publishes a key only once its period has started or is about
 * to, and each entry carries `endsAt`, the next key's start. The client
 * verifies offline until a 51Did is dated within the boundary tolerance
 * of the newest entry's end, or of its start where the cloud sent no end,
 * and then fetches the entries from the newest start held, at most once
 * a minute. A key may be replaced before its `endsAt`, and the client
 * picks up the replacement on the first signature that fails with the
 * keys held, or at the next daily fetch of the whole list.
 *
 * The key list cache is per instance. PHP runs one request per process
 * state, so under a long-running application server the cache lives for
 * the life of the instance, while under the built-in `php -S` server each
 * request starts afresh and fetches the keys again.
 */
final class DidClient
{
    /** The cloud API base used when no endpoint is given or set. */
    public const DEFAULT_ENDPOINT = 'https://cloud.51degrees.com/api/v4/';

    /**
     * The environment variable read for the API base when the constructor
     * argument is absent, the same one the cloud request engine honours.
     */
    public const ENDPOINT_VARIABLE = 'FOD_CLOUD_API_URL';

    /** The Composer package name, sent in the User-Agent. */
    public const PACKAGE_NAME = '51degrees/fiftyone.pipeline.did';

    /**
     * How old the key list may be before the whole list is fetched again.
     * This bounds how long a key replaced before its scheduled end can
     * still be trusted offline.
     */
    public const KEY_LIST_MAX_AGE_SECONDS = 24 * 60 * 60;

    private const BOUNDARY_TOLERANCE_SECONDS = 15 * 60;

    /**
     * The shortest gap between fetches made because the keys held end too
     * soon for a date, or because a signature failed with them, so that a
     * date nothing is published for yet, or a forged one, cannot make
     * every lookup call the cloud.
     */
    private const REFETCH_INTERVAL_SECONDS = 60;

    /**
     * The longest encoded identifier the client sends. This is a guard
     * against obviously malformed input rather than the size of a 51Did,
     * so that a hostile value is refused before it is decoded, before a
     * key is fetched and before the cloud is called. The figure is
     * arbitrary and generous on purpose, and says nothing about how long
     * an identifier is.
     */
    private const MAXIMUM_ENCODED_LENGTH = 4096;

    /** Seconds the default transport waits for the cloud. */
    private const TIMEOUT_SECONDS = 30;

    private string $resourceKey;
    private ?string $licenceKey;
    private string $endpoint;
    private Closure $transport;
    private Closure $clock;

    /** @var PublicKey[]|null The keys held, oldest start first. */
    private ?array $keys = null;

    /** When the whole list was last fetched, which sets its age. */
    private int $keysFetchedAt = 0;

    /** When a fetch limited to once a minute last started, or null. */
    private ?int $refetchedAt = null;

    /**
     * @param string $resourceKey The page's resource key, public by nature.
     * @param string|null $licenceKey The account's licence key, server side
     *     only, needed to redeem where the account holds licence keys.
     * @param string|null $endpoint The API base including `/api/v4/`. When
     *     null the `FOD_CLOUD_API_URL` environment variable is read, then
     *     {@see DidClient::DEFAULT_ENDPOINT}. A value with or without a
     *     trailing slash is normalised to end in exactly one.
     * @param callable|null $transport An HTTP transport for tests, called as
     *     `$transport(string $method, string $url, string[] $headers,
     *     string $body): array{status: int, body: string}` and throwing a
     *     {@see RuntimeException} on a transport failure. The default uses
     *     `file_get_contents` with a stream context.
     * @param callable|null $clock A clock for tests returning the current
     *     Unix timestamp. The default is `time()`.
     *
     * @throws InvalidArgumentException when the resource key is empty.
     */
    public function __construct(
        string $resourceKey,
        ?string $licenceKey = null,
        ?string $endpoint = null,
        ?callable $transport = null,
        ?callable $clock = null
    ) {
        if (trim($resourceKey) === '') {
            throw new InvalidArgumentException(
                'A resource key is required.'
            );
        }
        $this->resourceKey = $resourceKey;
        $this->licenceKey = ($licenceKey === null || $licenceKey === '')
            ? null
            : $licenceKey;
        $base = $endpoint;
        if ($base === null || $base === '') {
            $fromEnvironment = getenv(self::ENDPOINT_VARIABLE);
            $base = ($fromEnvironment === false || $fromEnvironment === '')
                ? self::DEFAULT_ENDPOINT
                : $fromEnvironment;
        }
        $this->endpoint = rtrim($base, '/') . '/';
        $this->transport = $transport === null
            ? Closure::fromCallable([self::class, 'defaultTransport'])
            : Closure::fromCallable($transport);
        $this->clock = $clock === null
            ? static fn (): int => time()
            : Closure::fromCallable($clock);
    }

    /** The API base, ending in one slash. */
    public function getEndpoint(): string
    {
        return $this->endpoint;
    }

    /** The resource key the client was built with. */
    public function getResourceKey(): string
    {
        return $this->resourceKey;
    }

    /**
     * Whether the client was given a licence key. A licence key is
     * needed only by {@see DidClient::redeem()}, so a client without
     * one still reads keys and verifies signatures.
     */
    public function hasLicenceKey(): bool
    {
        return $this->licenceKey !== null;
    }

    /**
     * The signing public keys held, oldest start first, fetched on first
     * use and then answered from the cache. The cloud publishes a key only
     * once its period has started or is about to, so the newest entry is
     * normally the key in force. Each later fetch is merged in without
     * dropping older entries, because 51Dids made long ago verify against
     * them.
     *
     * @return PublicKey[]
     *
     * @throws CloudException when the key endpoint answers other than 200.
     * @throws RuntimeException when the cloud cannot be reached, the answer
     *     is not a key list, or any entry in the list is malformed.
     */
    public function publicKeys(): array
    {
        if ($this->keys === null) {
            $this->fetchKeys(null);
        }
        return $this->keys;
    }

    /**
     * The key in force when the identifier was created, being the entry
     * whose start is latest on or before the identifier's date, or null when
     * there is no such entry or that entry had ended by then.
     *
     * The whole list is fetched again before answering when it is more
     * than a day old. The entries from the newest start held are fetched
     * first, at most once a minute, when the date is within the boundary
     * tolerance of the end of the keys held, being the newest entry's end
     * or, where the cloud sent none, its start. Otherwise the answer comes
     * from the keys held.
     *
     * @throws CloudException when the key endpoint answers other than 200.
     * @throws RuntimeException when the cloud cannot be reached.
     */
    public function publicKeyFor(FodId $fodId): ?PublicKey
    {
        $at = $fodId->getDate();
        $this->fetchFor($at);
        return self::inForceAt($this->keys, $at);
    }

    /**
     * Verifies the identifier's signature offline against the published
     * keys, mirroring the check the cloud's verify endpoint makes.
     *
     * 1. The envelope version must be 3.
     * 2. The payload must be at least the base length for its type, being
     *    the 5 header bytes plus a 32 byte match key, or 16 for a Random
     *    identifier. Anything beyond the base is a creator context section
     *    and is accepted, since the signature covers the whole payload.
     * 3. The candidate keys are the entry in force at the identifier's
     *    date, plus the neighbouring entry either side of a nearby key
     *    boundary where those differ. They are tried in that order and
     *    the first that verifies answers true.
     *    Every earlier key is never tried, because one leaked key from any
     *    past period could then sign identifiers dated today.
     * 4. When none verifies, this call fetched nothing, and a key held
     *    starts on or before the date, the entries from the newest such
     *    key's start are fetched, at most once a minute, and the
     *    candidates tried once more, because that key may have been
     *    replaced before its scheduled end.
     * 5. No candidate, meaning no key held was in force within the
     *    boundary tolerance of the date, answers false.
     *    {@see DidClient::verifySignatureDetailed()} says which of the
     *    five cases it was, and {@see DidClient::publicKeyFor()}
     *    returning null says the same for this one case.
     *
     * @throws CloudException when the key endpoint answers other than 200.
     * @throws RuntimeException when the cloud cannot be reached.
     * @throws \SwanCommunity\Owid\OwidException when a published key is not
     *     a valid public key.
     */
    public function verifySignature(FodId $fodId): bool
    {
        return $this->verifySignatureDetailed($fodId)
            === SignatureCheck::Verified;
    }

    /**
     * The same check as {@see DidClient::verifySignature()}, answering
     * which of the five things happened rather than only whether the
     * identifier is genuine.
     *
     * Only {@see SignatureCheck::Verified} says the signature was
     * examined against a key and matched, and only
     * {@see SignatureCheck::Invalid} says it was examined and did not.
     * The other three say the check never happened, because the
     * envelope version is not one this package issues, or the payload
     * is too short to hold a complete identifier, or the published
     * schedule covers no key for the identifier's date. A caller that
     * treats those three as forged reports its own outage as an
     * attack, which is why they are told apart here.
     *
     * The outcome names are the same in every 51Did package, so they
     * can be logged or carried between services.
     *
     * @throws CloudException when the key endpoint answers other than 200.
     * @throws RuntimeException when the cloud cannot be reached.
     * @throws \SwanCommunity\Owid\OwidException when a published key is
     *     not a valid public key.
     */
    public function verifySignatureDetailed(FodId $fodId): SignatureCheck
    {
        if ($fodId->getVersion() !== Version::Version3) {
            return SignatureCheck::UnsupportedVersion;
        }
        $payload = $fodId->getPayload();
        if (strlen($payload) < FodIdLayout::HEADER_LENGTH) {
            return SignatureCheck::InvalidLength;
        }
        $isRandom = IdType::fromFlags(ord($payload[FodIdLayout::FLAGS_OFFSET]))
            === IdType::Random;
        $baseLength = FodIdLayout::HEADER_LENGTH + ($isRandom
            ? FodIdLayout::GUID_LENGTH
            : FodIdLayout::MATCH_KEY_LENGTH);
        if (strlen($payload) < $baseLength) {
            return SignatureCheck::InvalidLength;
        }
        $at = $fodId->getDate();
        $fetched = $this->fetchFor($at);
        $check = self::checkWith($this->keys, $fodId, $at);
        if ($check === SignatureCheck::Invalid && !$fetched) {
            // The key held for the date may have been replaced before its
            // scheduled end, and the entries from its start carry the
            // replacement. A list fetched for this call cannot be better.
            $held = self::newestStartedBy($this->keys, $at);
            if ($held !== null && $this->refetch($held->startsAt)) {
                $check = self::checkWith($this->keys, $fodId, $at);
            }
        }
        return $check;
    }

    /**
     * Verifies the identifier's signature through the cloud's verify
     * endpoint, which needs no licence key and counts as one use. A string
     * is read first with {@see FodId::tryFromBase64()} and refused when it
     * is not a 51Did, so a malformed value costs no use, and is otherwise
     * sent as given, in either base64 alphabet. A {@see FodId} is sent in
     * the URL-safe form. The identifier goes under both parameter names,
     * `51did` and `owid`, so the request works with hosts that read either
     * one. Hosts that recognise both prefer `51did` and keep `owid` as a
     * compatibility alias.
     *
     * @return bool True for `{ "valid": true }`, false for
     *     `{ "valid": false }`.
     *
     * @throws InvalidArgumentException when a string value is far longer
     *     than any identifier or is not a 51Did, either of which is refused
     *     before the request with the message naming which, or when the
     *     cloud answered 400, carrying the cloud's message.
     * @throws CloudException for any other status.
     * @throws RuntimeException when the cloud cannot be reached.
     */
    public function verify(FodId|string $fodId): bool
    {
        $value = self::wireForm($fodId);
        $response = $this->request(
            'GET',
            'id/verify/' . rawurlencode($this->resourceKey),
            ['51did' => $value, 'owid' => $value]
        );
        $status = $response['status'];
        $json = json_decode($response['body'], true);
        if (is_array($json) && array_key_exists('valid', $json)
            && ($status === 200 || $status === 400)
        ) {
            return $json['valid'] === true;
        }
        if ($status === 400) {
            throw new InvalidArgumentException(
                self::errorsText($json, $response['body'])
            );
        }
        throw new CloudException(
            $status,
            $response['body'],
            "The verify endpoint answered {$status}: "
            . self::excerpt($response['body'])
        );
    }

    /**
     * Redeems a sealed creator context result against the identifier, on
     * the server, with the licence key. Sends `POST {endpoint}id/redeem`
     * with a form body of `resource`, `51did`, `result`, `challenge` and
     * `license` (omitted when the client holds no licence key). Counts as
     * one use, the second of the two a browser-based context check costs.
     *
     * @param FodId|string $fodId The identifier the server knows
     *     independently, as a {@see FodId} or a string in either alphabet.
     * @param string $result The sealed result exactly as the verify endpoint
     *     returned it to the browser.
     * @param string $challenge The single-use challenge given to the verify
     *     endpoint, or an empty string where none was.
     *
     * @return RedeemResult For a 200, and for a 503 where the context is
     *     {@see ContextOutcome::Unconfirmed} and the caller may retry.
     *
     * @throws InvalidArgumentException when a string value is far longer
     *     than any identifier or is not a 51Did, either of which is refused
     *     before the request with the message naming which, or when the
     *     cloud answered 400, carrying the cloud's message.
     * @throws NotSupportedException when the host does not offer the
     *     creator context (404).
     * @throws CloudException for any other status.
     * @throws RuntimeException when the cloud cannot be reached.
     */
    public function redeem(
        FodId|string $fodId,
        string $result,
        string $challenge
    ): RedeemResult {
        $form = [
            'resource' => $this->resourceKey,
            '51did' => self::wireForm($fodId),
            'result' => $result,
            'challenge' => $challenge,
        ];
        if ($this->licenceKey !== null) {
            $form['license'] = $this->licenceKey;
        }
        $response = $this->request('POST', 'id/redeem', [], $form);
        $status = $response['status'];
        $body = $response['body'];
        if ($status === 200 || $status === 503) {
            return RedeemResult::fromResponse($status, $body);
        }
        if ($status === 400) {
            throw new InvalidArgumentException(
                self::errorsText(json_decode($body, true), $body)
            );
        }
        if ($status === 404) {
            throw new NotSupportedException(
                $status,
                $body,
                'The host does not offer the creator context.'
            );
        }
        throw new CloudException(
            $status,
            $body,
            "The redeem endpoint answered {$status}: " . self::excerpt($body)
        );
    }

    /**
     * Fetches first where the keys held cannot answer for the moment, and
     * says whether it did. The whole list is fetched when none is held yet
     * or it is more than a day old. The entries from the newest start held
     * are fetched, at most once a minute, when the moment is within the
     * boundary tolerance of the end of the keys held, or the last answer
     * held no keys at all. Otherwise no request is made.
     */
    private function fetchFor(DateTimeImmutable $at): bool
    {
        if ($this->keys === null
            || ($this->clock)() - $this->keysFetchedAt
                > self::KEY_LIST_MAX_AGE_SECONDS
        ) {
            $this->fetchKeys(null);
            return true;
        }
        $end = self::heldUntil($this->keys);
        if ($end === null
            || $at->getTimestamp() + self::BOUNDARY_TOLERANCE_SECONDS >= $end
        ) {
            return $this->refetch(self::newest($this->keys)?->startsAt);
        }
        return false;
    }

    /**
     * Fetches the entries from the start given, or the whole list where
     * there is none, unless a fetch made here started less than a minute
     * ago, and says whether it fetched. The time is recorded before the
     * request, so a failed fetch holds the next one back too.
     */
    private function refetch(?DateTimeImmutable $since): bool
    {
        $now = ($this->clock)();
        if ($this->refetchedAt !== null) {
            $elapsed = $now - $this->refetchedAt;
            // A clock set back is no reason to stop fetching, so only a
            // recent fetch in the past holds the next one back.
            if ($elapsed >= 0 && $elapsed < self::REFETCH_INTERVAL_SECONDS) {
                return false;
            }
        }
        $this->refetchedAt = $now;
        $this->fetchKeys($since);
        return true;
    }

    /**
     * Fetches the key list from `GET {endpoint}id/key/{resource}` and merges
     * it into the keys held. A start given goes as `datetime`, so the answer
     * holds the entry with that start and any later ones. Without one the
     * whole list is fetched, which also resets the list's age. Each entry's
     * start is `startsAt`, or the compatibility field `created` when
     * `startsAt` is absent, and its end is `endsAt` where present.
     * `weekStart` is ignored.
     *
     * @throws CloudException when the endpoint answers other than 200.
     * @throws RuntimeException when the answer is not a JSON array or any
     *     entry is malformed.
     */
    private function fetchKeys(?DateTimeImmutable $since): void
    {
        $query = [];
        if ($since !== null) {
            $query['datetime'] = gmdate(
                'Y-m-d\TH:i:s\Z',
                $since->getTimestamp()
            );
        }
        $response = $this->request(
            'GET',
            'id/key/' . rawurlencode($this->resourceKey),
            $query
        );
        if ($response['status'] !== 200) {
            throw new CloudException(
                $response['status'],
                $response['body'],
                "The key endpoint answered {$response['status']}: "
                . self::excerpt($response['body'])
            );
        }
        try {
            $json = json_decode(
                $response['body'],
                false,
                512,
                JSON_THROW_ON_ERROR
            );
        } catch (JsonException $exception) {
            throw new RuntimeException(
                'The key endpoint did not answer with a key list: '
                . self::excerpt($response['body']),
                0,
                $exception
            );
        }
        if (!is_array($json)) {
            throw new RuntimeException(
                'The key endpoint did not answer with a key list: '
                . self::excerpt($response['body'])
            );
        }
        $keys = [];
        foreach ($json as $index => $entry) {
            if (!is_object($entry)) {
                throw new RuntimeException(
                    "Key list entry {$index} is not an object."
                );
            }
            $start = $entry->startsAt ?? $entry->created ?? null;
            if (!is_string($start)) {
                throw new RuntimeException(
                    "Key list entry {$index} has no string startsAt or "
                    . 'created.'
                );
            }
            $pem = $entry->publicKey ?? null;
            if (!is_string($pem)) {
                throw new RuntimeException(
                    "Key list entry {$index} has no string publicKey."
                );
            }
            $startsAt = self::parseMoment($start);
            if ($startsAt === null) {
                throw new RuntimeException(
                    "Key list entry {$index} has an invalid start: {$start}"
                );
            }
            $end = $entry->endsAt ?? null;
            $endsAt = null;
            if ($end !== null) {
                if (!is_string($end)) {
                    throw new RuntimeException(
                        "Key list entry {$index} has an endsAt that is not "
                        . 'a string.'
                    );
                }
                $endsAt = self::parseMoment($end);
                if ($endsAt === null) {
                    throw new RuntimeException(
                        "Key list entry {$index} has an invalid endsAt: {$end}"
                    );
                }
                if ($endsAt <= $startsAt) {
                    throw new RuntimeException(
                        "Key list entry {$index} does not end after it "
                        . 'starts.'
                    );
                }
            }
            $keys[] = new PublicKey($startsAt, $pem, $endsAt);
        }
        $this->keys = self::merge($this->keys ?? [], $keys);
        if ($since === null) {
            $this->keysFetchedAt = ($this->clock)();
        }
    }

    /**
     * The keys held with an answer merged in by start, oldest first. An
     * entry in the answer replaces the held entry with the same start,
     * because a later answer may carry an end the earlier one did not, or
     * an end moved earlier where the key was replaced. Held entries the
     * answer leaves out are kept, because 51Dids made long ago verify
     * against them.
     *
     * @param PublicKey[] $held
     * @param PublicKey[] $answer
     * @return PublicKey[]
     */
    private static function merge(array $held, array $answer): array
    {
        $byStart = [];
        foreach (array_merge($held, $answer) as $key) {
            $byStart[$key->startsAt->getTimestamp()] = $key;
        }
        ksort($byStart);
        return array_values($byStart);
    }

    /**
     * Reads a key's start or end from the ISO 8601 form the cloud writes,
     * being a date, a `T`, a time with optional fractional seconds, and
     * then `Z` or a numeric offset. Anything else is refused, because the
     * date constructor turns an empty string, a space, `now` and other
     * loose words into the current time, which would put a key that never
     * existed at the head of the schedule.
     *
     * @return DateTimeImmutable|null Null when the value is not that form.
     */
    private static function parseMoment(string $value): ?DateTimeImmutable
    {
        $iso = '/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?'
            . '(Z|[+-]\\d{2}:?\\d{2})$/';
        if (preg_match($iso, $value) !== 1) {
            return null;
        }
        try {
            return new DateTimeImmutable($value);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * The entry in force at the moment, being the newest whose start has
     * passed, or null when the moment precedes every entry or that entry
     * had ended by then.
     *
     * @param PublicKey[] $keys
     */
    private static function inForceAt(
        array $keys,
        DateTimeImmutable $at
    ): ?PublicKey {
        $best = self::newestStartedBy($keys, $at);
        if ($best !== null && $best->endsAt !== null
            && $best->endsAt->getTimestamp() <= $at->getTimestamp()
        ) {
            return null;
        }
        return $best;
    }

    /**
     * The newest entry whose start is on or before the moment, whether or
     * not it has ended, or null when the moment precedes every entry.
     *
     * @param PublicKey[] $keys
     */
    private static function newestStartedBy(
        array $keys,
        DateTimeImmutable $at
    ): ?PublicKey {
        $moment = $at->getTimestamp();
        $best = null;
        foreach ($keys as $key) {
            $start = $key->startsAt->getTimestamp();
            if ($start > $moment) {
                continue;
            }
            if ($best === null || $start > $best->startsAt->getTimestamp()) {
                $best = $key;
            }
        }
        return $best;
    }

    /**
     * The entries that may have signed something created at the moment,
     * best first. The entry in force, then the neighbouring entry either
     * side of a nearby key boundary, each added only where it differs
     * from those already chosen.
     *
     * @param PublicKey[] $keys
     * @return PublicKey[]
     */
    private static function candidatesFor(
        array $keys,
        DateTimeImmutable $at
    ): array {
        if ($keys === []) {
            return [];
        }
        $moment = $at->getTimestamp();
        $tolerance = self::BOUNDARY_TOLERANCE_SECONDS;
        $candidates = [];
        foreach ([
            self::inForceAt($keys, $at),
            self::inForceAt($keys, $at->setTimestamp($moment - $tolerance)),
            self::inForceAt($keys, $at->setTimestamp($moment + $tolerance)),
        ] as $candidate) {
            if ($candidate !== null
                && !in_array($candidate, $candidates, true)
            ) {
                $candidates[] = $candidate;
            }
        }
        return $candidates;
    }

    /**
     * The outcome of trying the candidate keys for the moment from the
     * list given.
     *
     * @param PublicKey[] $keys
     */
    private static function checkWith(
        array $keys,
        FodId $fodId,
        DateTimeImmutable $at
    ): SignatureCheck {
        $candidates = self::candidatesFor($keys, $at);
        if ($candidates === []) {
            return SignatureCheck::NoKeyForDate;
        }
        foreach ($candidates as $key) {
            if ($fodId->verify($key->pem)) {
                return SignatureCheck::Verified;
            }
        }
        return SignatureCheck::Invalid;
    }

    /**
     * @param PublicKey[] $keys
     * @return PublicKey|null The entry with the latest start, or null.
     */
    private static function newest(array $keys): ?PublicKey
    {
        $newest = null;
        foreach ($keys as $key) {
            if ($newest === null
                || $key->startsAt->getTimestamp()
                    > $newest->startsAt->getTimestamp()
            ) {
                $newest = $key;
            }
        }
        return $newest;
    }

    /**
     * Where the keys held stop, as a Unix timestamp, being the newest
     * entry's end, or its start where the cloud sent no end. Null when no
     * keys are held.
     *
     * @param PublicKey[] $keys
     */
    private static function heldUntil(array $keys): ?int
    {
        $newest = self::newest($keys);
        if ($newest === null) {
            return null;
        }
        return ($newest->endsAt ?? $newest->startsAt)->getTimestamp();
    }

    /**
     * The identifier as sent on the wire. A {@see FodId} goes in the
     * URL-safe form, which needs no encoding, and has already been read so
     * there is nothing to check. A string is checked here and sent as
     * given, in whichever alphabet it arrived, so the cloud sees exactly
     * what the caller was handed.
     *
     * Two things are refused before any key fetch or call, in this order.
     * A value longer than {@see DidClient::MAXIMUM_ENCODED_LENGTH} is
     * refused before it is even read, because the figure is client policy
     * for obviously hostile input and not a property of the format. Then a
     * string that {@see FodId::tryFromBase64()} does not read as a 51Did is
     * refused with the status named, so a malformed value costs no use and
     * the caller learns the specific reason rather than a generic one.
     */
    private static function wireForm(FodId|string $fodId): string
    {
        $value = $fodId instanceof FodId ? $fodId->asBase64Url() : $fodId;
        if (strlen($value) > self::MAXIMUM_ENCODED_LENGTH) {
            throw new InvalidArgumentException(
                'The value is far longer than any identifier, so it was '
                . 'refused without calling the cloud.'
            );
        }
        if (is_string($fodId)) {
            $read = FodId::tryFromBase64($fodId);
            if (!$read->ok) {
                throw new InvalidArgumentException(
                    'The value is not a 51Did (' . $read->status->value
                    . '), so it was refused without calling the cloud.'
                );
            }
        }
        return $value;
    }

    /**
     * Sends one request to the cloud through the transport.
     *
     * @param array<string, string> $query
     * @param array<string, string>|null $form A form body to POST, or null.
     * @return array{status: int, body: string}
     *
     * @throws RuntimeException when the transport fails or answers in the
     *     wrong shape.
     */
    private function request(
        string $method,
        string $path,
        array $query = [],
        ?array $form = null
    ): array {
        $url = $this->endpoint . $path;
        if ($query !== []) {
            $url .= '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }
        $headers = [
            'User-Agent: ' . self::userAgent(),
            'Accept: application/json',
        ];
        $body = '';
        if ($form !== null) {
            $body = http_build_query($form, '', '&', PHP_QUERY_RFC3986);
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
            $headers[] = 'Content-Length: ' . strlen($body);
        }
        $response = ($this->transport)($method, $url, $headers, $body);
        if (!is_array($response)
            || !isset($response['status'], $response['body'])
            || !is_int($response['status'])
            || !is_string($response['body'])
        ) {
            throw new RuntimeException(
                'The transport must answer with status and body.'
            );
        }
        return ['status' => $response['status'], 'body' => $response['body']];
    }

    /**
     * The default transport, `file_get_contents` with a stream context.
     * `ignore_errors` keeps the body of an error response, so the caller
     * sees what the service said rather than a bare warning.
     *
     * @param string[] $headers
     * @return array{status: int, body: string}
     *
     * @throws RuntimeException when no response arrives.
     */
    private static function defaultTransport(
        string $method,
        string $url,
        array $headers,
        string $body
    ): array {
        $options = [
            'method' => $method,
            'header' => implode("\r\n", $headers) . "\r\n",
            'ignore_errors' => true,
            'timeout' => self::TIMEOUT_SECONDS,
        ];
        if ($body !== '') {
            $options['content'] = $body;
        }
        $context = stream_context_create(['http' => $options]);
        // The @ keeps a connection failure from printing a warning, since
        // the false return is reported as an exception below.
        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            throw new RuntimeException("No response from {$url}.");
        }
        $status = 0;
        // PHP sets $http_response_header in the calling scope with the
        // response headers, the status line first. A redirect leaves more
        // than one status line, and the last is the answer.
        foreach ($http_response_header ?? [] as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $match)) {
                $status = (int) $match[1];
            }
        }
        return ['status' => $status, 'body' => $response];
    }

    /**
     * The User-Agent naming the package and its installed version. The
     * version comes from Composer's record of what is installed, so a
     * development checkout reports its branch rather than a number.
     */
    private static function userAgent(): string
    {
        $version = 'unknown';
        if (class_exists(InstalledVersions::class)) {
            try {
                $installed = InstalledVersions::getPrettyVersion(
                    self::PACKAGE_NAME
                );
                if (is_string($installed) && $installed !== '') {
                    $version = $installed;
                }
            } catch (Throwable $exception) {
                // Not installed through Composer, so the version is unknown.
            }
        }
        return self::PACKAGE_NAME . '/' . $version;
    }

    /**
     * The cloud's `errors` text from a 400 body, or the body itself where
     * there is none.
     *
     * @param mixed $json
     */
    private static function errorsText($json, string $body): string
    {
        if (is_array($json) && isset($json['errors'])
            && is_array($json['errors'])
        ) {
            $messages = [];
            foreach ($json['errors'] as $error) {
                if (is_string($error)) {
                    $messages[] = $error;
                }
            }
            if ($messages !== []) {
                return implode(' ', $messages);
            }
        }
        return self::excerpt($body);
    }

    /** The start of a body for a message, so a page of HTML stays short. */
    private static function excerpt(string $body): string
    {
        $trimmed = trim($body);
        return strlen($trimmed) > 200
            ? substr($trimmed, 0, 200) . '...'
            : $trimmed;
    }
}
