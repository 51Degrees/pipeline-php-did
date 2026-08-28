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
 * 1. Fetches the signing public keys once, caches them, and picks the key
 *    in force when a given 51Did was created ({@see DidClient::publicKeys()}
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

    /** How old the cached key list may be before it is fetched again. */
    public const KEY_LIST_MAX_AGE_SECONDS = 24 * 60 * 60;

    /**
     * How far either side of a key boundary a neighbouring key is also
     * tried, matching the short tolerance the cloud applies. Internal to
     * the selection rule rather than a published figure.
     */
    private const BOUNDARY_TOLERANCE_SECONDS = 15 * 60;

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

    /** @var PublicKey[]|null */
    private ?array $keys = null;
    private int $keysFetchedAt = 0;

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
     * The signing public keys the cloud publishes, fetched on first use and
     * then answered from the cache. Keys are published up to three months
     * ahead of their start, so the list holds entries that are not yet in
     * force.
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
            $this->fetchKeys();
        }
        return $this->keys;
    }

    /**
     * The key in force when the identifier was created, being the entry
     * whose start is latest on or before the identifier's date, or null when
     * the date precedes the whole schedule.
     *
     * The list is fetched again, once, before answering when there is no
     * entry on or before the date, when the date is later than the newest
     * start held, or when the list is more than a day old. Otherwise the
     * answer comes from the cache.
     *
     * @throws CloudException when the key endpoint answers other than 200.
     * @throws RuntimeException when the cloud cannot be reached.
     */
    public function publicKeyFor(FodId $fodId): ?PublicKey
    {
        $at = $fodId->getDate();
        return self::inForceAt($this->keysCovering($at), $at);
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
     *    date, plus the entry in force a small tolerance earlier and the
     *    entry in force the same tolerance later where those differ, so an
     *    identifier dated close to a key boundary still verifies. They are
     *    tried in that order and the first that verifies answers true.
     *    Every earlier key is never tried, because one leaked key from any
     *    past period could then sign identifiers dated today.
     * 4. No candidate, meaning the date precedes the whole schedule,
     *    answers false. {@see DidClient::publicKeyFor()} returning null says
     *    which case that was.
     *
     * @throws CloudException when the key endpoint answers other than 200.
     * @throws RuntimeException when the cloud cannot be reached.
     * @throws \SwanCommunity\Owid\OwidException when a published key is not
     *     a valid public key.
     */
    public function verifySignature(FodId $fodId): bool
    {
        if ($fodId->getVersion() !== Version::Version3) {
            return false;
        }
        $payload = $fodId->getPayload();
        if (strlen($payload) < FodId::HEADER_LENGTH) {
            return false;
        }
        $isRandom = IdType::fromFlags(ord($payload[FodId::FLAGS_OFFSET]))
            === IdType::Random;
        $baseLength = FodId::HEADER_LENGTH
            + ($isRandom ? FodId::GUID_LENGTH : FodId::HASH_LENGTH);
        if (strlen($payload) < $baseLength) {
            return false;
        }
        $at = $fodId->getDate();
        $keys = $this->keysCovering($at);
        foreach (self::candidatesFor($keys, $at) as $key) {
            if ($fodId->verify($key->pem)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verifies the identifier's signature through the cloud's verify
     * endpoint, which needs no licence key and counts as one use. A string
     * is sent as given, in either base64 alphabet, and a {@see FodId} is
     * sent in the URL-safe form. The identifier goes under both parameter
     * names, `51did` and `owid`, so the request works with hosts that read
     * either one. Hosts that recognise both prefer `51did` and keep `owid`
     * as a compatibility alias.
     *
     * @return bool True for `{ "valid": true }`, false for
     *     `{ "valid": false }`.
     *
     * @throws InvalidArgumentException when a value is far longer than any
     *     identifier and is refused before the request, or the cloud could
     *     not parse it, carrying the cloud's message in the latter case.
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
     * @throws InvalidArgumentException when a value is far longer than any
     *     identifier and is refused before the request, or the cloud
     *     answered 400 because it was malformed, carrying the cloud's
     *     message in the latter case.
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
     * The key list to select from for the given moment, applying the
     * refetch rule of {@see DidClient::publicKeyFor()} once.
     *
     * @return PublicKey[]
     */
    private function keysCovering(DateTimeImmutable $at): array
    {
        if ($this->keys === null) {
            $this->fetchKeys();
            return $this->keys;
        }
        $now = ($this->clock)();
        $stale = ($now - $this->keysFetchedAt) > self::KEY_LIST_MAX_AGE_SECONDS;
        $newest = self::newestStart($this->keys);
        $refetch = $stale
            || self::inForceAt($this->keys, $at) === null
            || ($newest !== null && $at->getTimestamp() > $newest);
        if ($refetch) {
            $this->fetchKeys();
        }
        return $this->keys;
    }

    /**
     * Fetches the key list from `GET {endpoint}id/key/{resource}`. Each
     * entry's start is `startsAt`, or the compatibility field `created`
     * when `startsAt` is absent. `weekStart` is ignored.
     *
     * @throws CloudException when the endpoint answers other than 200.
     * @throws RuntimeException when the answer is not a JSON array or any
     *     entry is malformed.
     */
    private function fetchKeys(): void
    {
        $response = $this->request(
            'GET',
            'id/key/' . rawurlencode($this->resourceKey)
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
            $startsAt = self::parseStart($start);
            if ($startsAt === null) {
                throw new RuntimeException(
                    "Key list entry {$index} has an invalid start: {$start}"
                );
            }
            $keys[] = new PublicKey($startsAt, $pem);
        }
        $this->keys = $keys;
        $this->keysFetchedAt = ($this->clock)();
    }

    /**
     * Reads the moment a key comes into force from the ISO 8601 form the
     * cloud writes, being a date, a `T`, a time with optional fractional
     * seconds, and then `Z` or a numeric offset. Anything else is refused,
     * because the date constructor turns an empty string, a space, `now`
     * and other loose words into the current time, which would put a key
     * that never existed at the head of the schedule.
     *
     * @return DateTimeImmutable|null Null when the value is not that form.
     */
    private static function parseStart(string $value): ?DateTimeImmutable
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
     * passed, or null when the moment precedes every entry.
     *
     * @param PublicKey[] $keys
     */
    private static function inForceAt(
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
     * best first. The entry in force, then the entry in force a tolerance
     * earlier (the previous key, just after a boundary), then the entry in
     * force a tolerance later (the next key, just before a boundary), each
     * added only where it differs from those already chosen.
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
     * @param PublicKey[] $keys
     * @return int|null The newest start as a Unix timestamp, or null.
     */
    private static function newestStart(array $keys): ?int
    {
        $newest = null;
        foreach ($keys as $key) {
            $start = $key->startsAt->getTimestamp();
            if ($newest === null || $start > $newest) {
                $newest = $start;
            }
        }
        return $newest;
    }

    /**
     * The identifier as sent on the wire. A {@see FodId} goes in the
     * URL-safe form, which needs no encoding. A string is sent as given, so
     * the cloud judges it, which is what gives the caller the cloud's own
     * message for a value that does not parse. Only a value far longer
     * than any identifier is refused here, by
     * {@see DidClient::MAXIMUM_ENCODED_LENGTH}, so that obviously malformed
     * input costs neither a key fetch nor a call.
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
