<?php

/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

declare(strict_types=1);

namespace SwanCommunity\Owid;

use DateTimeZone;
use DateTimeImmutable;
use Exception;

/**
 * Fetches the signing public key of a creator from the well known end point
 * on the domain the OWID carries, asking for the key that was in force on the
 * date the OWID carries.
 *
 * The end point is /owid/api/v{n}/public-key?date={minutes}&format=spki,
 * where the version in the path is the version byte of the OWID being checked
 * rather than a constant, and the minutes are counted from 2020-01-01 in the
 * same way the OWID stores the date. Creators rotate weekly, so without the
 * date only identifiers signed since the most recent rotation can be verified.
 * A creator that ignores the parameter answers with its current key, and
 * where its own statement of that key's span puts the identifier's date
 * outside it the key is reported as unavailable rather than the signature as
 * not matching, so every identifier it signed under an earlier key goes
 * unverified, which is why a creator that rotates its key has to honour the
 * date.
 *
 * Only the HTTP stream wrapper PHP ships with is used, so the library keeps
 * its promise of no external dependency. This class is the one place in the
 * library that reaches the network, nothing else loads it, and every method
 * takes a transport of the caller's own for a host where remote stream access
 * is turned off or another client is wanted.
 *
 * The Java port answers the same question with PublicKeyFetch, the Rust port
 * with Owid::verify_status and the Go port with SignatureStatusFromDomain.
 */
final class PublicKeyFetch
{
    /** How long to wait for the connection and then for the response, in seconds. */
    public const TIMEOUT_SECONDS = 10.0;

    /**
     * The most keys held before the cache is emptied and filled again, across
     * every creator. A bound is needed because a verifier sees identifiers
     * from many domains and many weeks, and an unbounded store would grow for
     * as long as the process runs.
     */
    public const MAXIMUM_CACHED_KEYS = 1024;

    /**
     * How far a creator's clock may run ahead of or behind this one's, in
     * minutes.
     *
     * It is used in two places. A creator that does not state the end of the
     * span of the key it answers with reads a date later than its own now as
     * now, so within this window of now this process cannot tell whether the
     * creator read the minute as its past or as its present, and nothing
     * learned from such an answer is held or served. And a creator's signing
     * machines may not agree with the creator's own schedule to the minute,
     * so an identifier dated within this window of an edge of the span the
     * creator stated for a key that does not verify under that key is
     * checked against the key for the minute just beyond that edge before it
     * is reported as not matching.
     */
    public const CLOCK_DRIFT_ALLOWANCE_MINUTES = 15;

    /**
     * The most bytes accepted from a response. A public key PEM is a few
     * hundred bytes, so a body beyond this is not a key and is not held.
     */
    public const MAXIMUM_RESPONSE_BYTES = 65536;

    /**
     * The schemes that make an HTTP request. A caller chooses the scheme, and
     * one that reads something other than a creator, such as file, is refused
     * rather than opened.
     */
    private const ACCEPTED_SCHEMES = ['http', 'https'];

    /**
     * The last minute there is, being the largest value the date field of
     * an OWID can hold. A span stated with a start and no end runs to it.
     */
    private const LAST_MINUTE = 0xFFFFFFFF;

    /**
     * Keys already fetched, by the creator's key end point, which is the key
     * URL without its date. Each end point holds the keys the creator has
     * answered with, each with the span of minutes the creator has confirmed
     * it for, as the earliest and latest minute.
     *
     * The specification asks implementations to cache so that verifying many
     * identifiers does not mean repeating requests to another processor. The
     * key URL carries the date of the identifier being verified, in minutes,
     * and a creator's key changes on the order of a week. Keyed by end point and span rather than by the whole URL, an
     * identifier dated between two minutes the creator has already answered
     * for is verified without a request. A key is in force from the start of
     * its period until the next key starts, so a key the creator confirms at
     * two minutes was in force at every minute between them.
     * Where the creator stated the span in its answer the span is explicit
     * and complete, and an identifier dated anywhere inside it is verified
     * without a request. Where the creator stated the start and no end the
     * key is open ended, in force until further notice as far as the creator
     * has said, whatever the cache holds it for. Otherwise the span grows as
     * the creator confirms the same key for more minutes.
     * @var array<string, array<int, array{pem: string, first: int, last: int, explicit: bool, openEnded: bool}>>
     */
    private static array $cache = [];

    /** How many keys are held across every end point. */
    private static int $heldKeys = 0;

    private function __construct()
    {
    }

    /**
     * Returns the URL of the public key end point for the OWID, using the
     * scheme provided, which is normally https.
     *
     * The date the OWID carries is sent as the date parameter, counted in
     * whole minutes from 2020-01-01, so that a creator which rotates its key
     * returns the key that was in force when this OWID was signed. The
     * parameter is left out where the date cannot be counted, which no OWID
     * this library reads can be, because the wire format cannot hold such a
     * date.
     *
     * @throws OwidException when the scheme is missing, or the domain the
     *                       OWID carries is not a domain name this library
     *                       will put in a URL.
     */
    public static function publicKeyUrl(Owid $owid, string $scheme): string
    {
        if (trim($scheme) === '') {
            throw new OwidException('the scheme is missing');
        }
        self::checkDomain($owid->domain);
        $minutes = Io::minutesSinceBase($owid->date);
        $query = $minutes >= 0
            ? 'date=' . $minutes . '&format=spki'
            : 'format=spki';
        return $scheme . '://' . $owid->domain
            . Endpoints::publicKeyPath($owid->version) . '?' . $query;
    }

    /**
     * Returns the public key PEM of the creator of the OWID, for the date the
     * OWID carries.
     *
     * A transport is a callable taking the URL and the timeout in seconds and
     * returning the response code and the body as a two element array. It
     * throws an Exception where no response could be obtained at all.
     *
     * @throws PublicKeyFetchException when the key could not be obtained,
     *                                 with the status to report for the
     *                                 identifier.
     *
     * @throws OwidException           when the scheme or the domain is not
     *                                 usable.
     */
    public static function publicKeyPem(
        Owid $owid,
        string $scheme,
        ?callable $transport = null
    ): string {
        return self::publicKeyPemAtUrl(
            self::publicKeyUrl($owid, $scheme),
            $owid->domain,
            $transport
        );
    }

    /**
     * Says whether the signature on the OWID is genuine, fetching the key
     * that was in force when the OWID was signed from the creator domain.
     *
     * A key that cannot be fetched is SignatureStatus::KeyUnavailable and one
     * that arrives in a form this library cannot read is
     * SignatureStatus::InvalidKey. Neither is SignatureStatus::SignatureInvalid,
     * because an outage or a badly served key leaves the signature unjudged,
     * and reporting either as invalid would read as an attack.
     */
    public static function signatureStatus(
        Owid $owid,
        string $scheme,
        ?callable $transport = null
    ): SignatureStatus {
        try {
            $url = self::publicKeyUrl($owid, $scheme);
        } catch (OwidException $refused) {
            return SignatureStatus::KeyUnavailable;
        }
        return self::signatureStatusAtUrl($owid, $url, $transport);
    }

    /**
     * Returns true only when the signature verifies under the key the creator
     * served for the date the OWID carries. Every other outcome, a signature
     * that does not match included, is false, so ask signatureStatus where the
     * difference changes what the caller does.
     */
    public static function verify(
        Owid $owid,
        string $scheme,
        ?callable $transport = null
    ): bool {
        return self::signatureStatus($owid, $scheme, $transport)
            === SignatureStatus::SignatureValid;
    }

    /**
     * Empties the cache of keys already fetched, so that the next
     * verification of any identifier asks the creator again. This is how a
     * long running process drops a key it has learned it should no longer
     * trust, after a creator rotates its key following a compromise, and how
     * a test starts from a known state.
     */
    public static function clearCache(): void
    {
        self::$cache = [];
        self::$heldKeys = 0;
    }

    /**
     * How many keys the cache holds, for the tests.
     *
     * @internal
     */
    public static function cachedKeyCount(): int
    {
        return self::$heldKeys;
    }

    /**
     * The work signatureStatus does once the URL is known, kept apart so that
     * the tests drive the real fetch against a key end point the tests can
     * stand up locally rather than against a near copy of the fetch.
     *
     * The signature is checked under the key the end point serves for the
     * OWID's own date, and then under the neighbouring key where the date is
     * within the clock drift allowance of an edge of the span the creator
     * stated. A key the creator says was not in force at the OWID's date
     * proves nothing about the identifier, so where nothing verifies under
     * such a key the answer is that the key is unavailable and not that the
     * signature does not match.
     *
     * @internal
     */
    public static function signatureStatusAtUrl(
        Owid $owid,
        string $url,
        ?callable $transport = null
    ): SignatureStatus {
        try {
            $answer = self::keyAtUrl($url, $owid->domain, $transport);
        } catch (PublicKeyFetchException $failed) {
            return $failed->status();
        } catch (OwidException $refused) {
            return SignatureStatus::KeyUnavailable;
        }
        $status = $owid->signatureStatus($answer['pem']);
        if ($status !== SignatureStatus::SignatureInvalid) {
            return $status;
        }
        $minute = Io::minutesSinceBase($owid->date);
        if ($minute < 0) {
            return SignatureStatus::SignatureInvalid;
        }
        if (self::neighbourVerifies($owid, $minute, $url, $answer, $transport)) {
            return SignatureStatus::SignatureValid;
        }
        return $answer['known'] && !self::covers($answer, $minute)
            ? SignatureStatus::KeyUnavailable
            : SignatureStatus::SignatureInvalid;
    }

    /**
     * Whether a key neighbouring the one the OWID's own minute selected
     * verifies the signature instead.
     *
     * A creator's signing machines may not agree with its own schedule to the
     * minute, so an identifier dated just after a key started may have been
     * signed with the key before it, and one dated just before may have been
     * signed with the key after. Where the signature does not verify under
     * the key selected and the OWID's minute is within the clock drift
     * allowance of an edge of the span the creator stated for that key, the
     * key for the minute just beyond that edge is asked for and tried. A key
     * already held for that minute is not asked for again, and a neighbour
     * that turns out to be the same key is not tried again. A creator that
     * stated no span has one key and no schedule, so there is no neighbour
     * to try. This costs at most two more requests, and only for a signature
     * that has already failed.
     *
     * @param array{pem: string, first: int, last: int, known: bool} $tried
     */
    private static function neighbourVerifies(
        Owid $owid,
        int $minute,
        string $url,
        array $tried,
        ?callable $transport
    ): bool {
        if (!$tried['known']) {
            return false;
        }
        $beyond = [];
        if ($tried['first'] > 0 && self::nearEdge($minute, $tried['first'])) {
            $beyond[] = $tried['first'] - 1;
        }
        if ($tried['last'] < self::LAST_MINUTE && self::nearEdge($minute, $tried['last'])) {
            $beyond[] = $tried['last'] + 1;
        }
        foreach ($beyond as $at) {
            try {
                $neighbour = self::keyAtUrl(
                    self::endPointOf($url) . '?date=' . $at . '&format=spki',
                    $owid->domain,
                    $transport
                );
            } catch (OwidException $unobtainable) {
                // A neighbour that cannot be obtained leaves the failure under
                // the selected key standing.
                continue;
            }
            if ($neighbour['pem'] === $tried['pem']) {
                continue;
            }
            if ($owid->signatureStatus($neighbour['pem']) === SignatureStatus::SignatureValid) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the minute is no further from the edge minute than the clocks
     * of a creator's signing machines are allowed to differ from its
     * schedule.
     */
    private static function nearEdge(int $minute, int $edge): bool
    {
        return abs($minute - $edge) <= self::CLOCK_DRIFT_ALLOWANCE_MINUTES;
    }

    /**
     * Whether the minute lies within the span the answer states.
     *
     * @param array{pem: string, first: int, last: int, known: bool} $answer
     */
    private static function covers(array $answer, int $minute): bool
    {
        return $answer['known'] && $answer['first'] <= $minute && $minute <= $answer['last'];
    }

    /**
     * The PEM of the key the URL asks for. See keyAtUrl.
     * @internal
     *
     * @throws PublicKeyFetchException when the key could not be obtained.
     */
    public static function publicKeyPemAtUrl(
        string $url,
        string $domain,
        ?callable $transport = null
    ): string {
        return self::keyAtUrl($url, $domain, $transport)['pem'];
    }

    /**
     * Fetches the key the URL asks for, with the span the creator stated for
     * it. Answered from the cache where a held key is known to cover the
     * minute the URL names, and otherwise by asking the creator, whose answer
     * states the moments the key is valid from and to and has the whole span
     * held. The span returned is the creator's own statement, whatever the
     * cache holds the key for. A span stated with a start and no end runs to
     * the last minute there is, and a creator that stated no span has none.
     *
     * @return array{pem: string, first: int, last: int, known: bool}
     * @throws PublicKeyFetchException when the key could not be obtained, or
     *                                 the answer is not the JSON form the
     *                                 specification requires.
     */
    private static function keyAtUrl(string $url, string $domain, ?callable $transport): array
    {
        $endPoint = self::endPointOf($url);
        $held = self::heldFor($endPoint, $url);
        if ($held !== null) {
            return $held;
        }
        [$pem, $start, $end] = self::parseAnswer(self::read($url, $domain, $transport), $domain);
        return self::hold($endPoint, $url, $pem, $start, $end);
    }

    /**
     * Reads a public key answer, returning the PEM and the span in minutes
     * since the base date. The end is the minute the next key starts. Either
     * is null where the answer does not state it. An answer that is not the
     * JSON form the specification requires, the PEM alone among the other
     * forms, or that fails the checks a creator applies before sending it, is
     * reported as a key that cannot be read.
     *
     * @return array{0: string, 1: ?int, 2: ?int}
     * @throws PublicKeyFetchException
     */
    private static function parseAnswer(string $body, string $domain): array
    {
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new PublicKeyFetchException(
                'domain ' . self::quoted($domain) . ' did not answer with the JSON form the '
                    . 'specification requires for the public key',
                SignatureStatus::InvalidKey,
                $domain
            );
        }
        try {
            [$pem, $validFrom, $validTo] = Endpoints::validatePublicKeyAnswer($decoded, null);
        } catch (OwidException $failed) {
            throw new PublicKeyFetchException(
                'domain ' . self::quoted($domain) . ' answered with a public key answer that is '
                    . 'not valid: ' . $failed->getMessage(),
                SignatureStatus::InvalidKey,
                $domain,
                0,
                $failed
            );
        }
        return [$pem, self::minutesOrNull($validFrom), self::minutesOrNull($validTo)];
    }

    /** The moment as minutes since the base date, or null. */
    private static function minutesOrNull(?DateTimeImmutable $moment): ?int
    {
        if ($moment === null) {
            return null;
        }
        $minutes = Io::minutesSinceBase($moment);
        return $minutes < 0 ? null : $minutes;
    }

    /**
     * The key URL without its query, which names the scheme, the creator and
     * the version, and so the key end point being asked.
     */
    private static function endPointOf(string $url): string
    {
        $query = strpos($url, '?');
        return $query === false ? $url : substr($url, 0, $query);
    }

    /**
     * The minute the URL asks about, or null where it names none, and whether
     * it lies within the clock drift allowance of now or later, which is a
     * minute a creator that does not state its spans may have read as its
     * present rather than as the minute named.
     *
     * @return array{0: ?int, 1: bool}
     */
    private static function minuteAndRecency(string $url): array
    {
        $now = Io::minutesSinceBase(new DateTimeImmutable('now', new DateTimeZone('UTC')));
        $parameters = [];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $parameters);
        $date = $parameters['date'] ?? null;
        if (is_string($date) && $date !== '' && ctype_digit($date)) {
            $minute = (int) $date;
            return [$minute, $minute > $now - self::CLOCK_DRIFT_ALLOWANCE_MINUTES];
        }
        return [null, false];
    }

    /**
     * The key held for the end point that is known to cover the minute the
     * URL asks about, with the span the creator stated for it, or null where
     * none is. A minute within the drift allowance of now is only served
     * where the creator itself stated the span, because a span confirmed
     * minute by minute says nothing certain about such a minute.
     *
     * @return ?array{pem: string, first: int, last: int, known: bool}
     */
    private static function heldFor(string $endPoint, string $url): ?array
    {
        [$minute, $recent] = self::minuteAndRecency($url);
        if ($minute === null) {
            return null;
        }
        foreach (self::$cache[$endPoint] ?? [] as $key) {
            if ($key['first'] <= $minute && $minute <= $key['last'] && ($key['explicit'] || !$recent)) {
                return self::statedFor($key);
            }
        }
        return null;
    }

    /**
     * The span the creator stated for a held key, which is the whole held
     * span where the creator stated it, runs to the last minute there is
     * where the creator stated a start and no end, and is nothing where the
     * creator stated no span.
     *
     * @param array{pem: string, first: int, last: int, explicit: bool, openEnded: bool} $key
     * @return array{pem: string, first: int, last: int, known: bool}
     */
    private static function statedFor(array $key): array
    {
        if ($key['explicit']) {
            return ['pem' => $key['pem'], 'first' => $key['first'], 'last' => $key['last'], 'known' => true];
        }
        if ($key['openEnded']) {
            return ['pem' => $key['pem'], 'first' => $key['first'], 'last' => self::LAST_MINUTE, 'known' => true];
        }
        return ['pem' => $key['pem'], 'first' => 0, 'last' => 0, 'known' => false];
    }

    /**
     * The span the creator stated in its answer. See statedFor.
     *
     * @return array{pem: string, first: int, last: int, known: bool}
     */
    private static function stated(string $pem, ?int $start, ?int $end): array
    {
        if ($start === null) {
            return ['pem' => $pem, 'first' => 0, 'last' => 0, 'known' => false];
        }
        if ($end !== null && $end > $start) {
            return ['pem' => $pem, 'first' => $start, 'last' => $end - 1, 'known' => true];
        }
        return ['pem' => $pem, 'first' => $start, 'last' => self::LAST_MINUTE, 'known' => true];
    }

    /**
     * Records the creator's answer to the URL, being the key and, where the
     * creator stated it, the span the key covers as the minute it came into
     * force and the minute the next key starts. Returns the key with the span
     * the creator stated for it.
     *
     * With both the start and the end the whole span is held as the creator's
     * own statement. With the start alone the key is held from the start up
     * to the drift allowance behind now, because no later key can have
     * started before then, and is marked open ended because the creator has
     * said it is in force until further notice. With neither the minute asked
     * about is held on its own, as long as it is not within the drift
     * allowance of now. A key already held for the end point has its span
     * widened to take in the new one. A key not held before is added,
     * emptying the cache first when it is full, because the cache must not
     * grow on the input of whoever presents the identifiers.
     *
     * @return array{pem: string, first: int, last: int, known: bool}
     */
    private static function hold(string $endPoint, string $url, string $pem, ?int $start, ?int $end): array
    {
        $stated = self::stated($pem, $start, $end);
        [$minute, $recent] = self::minuteAndRecency($url);
        $explicit = false;
        $openEnded = false;
        if ($start !== null && $end !== null && $end > $start) {
            $first = $start;
            $last = $end - 1;
            $explicit = true;
        } elseif ($start !== null) {
            $now = Io::minutesSinceBase(new DateTimeImmutable('now', new DateTimeZone('UTC')));
            $first = $start;
            $last = max($start, $now - self::CLOCK_DRIFT_ALLOWANCE_MINUTES);
            $openEnded = true;
        } elseif ($minute !== null && !$recent) {
            $first = $minute;
            $last = $minute;
        } else {
            return $stated;
        }
        foreach (self::$cache[$endPoint] ?? [] as $index => $key) {
            if ($key['pem'] === $pem) {
                if (self::widen($endPoint, $index, $first, $last)) {
                    $held = &self::$cache[$endPoint][$index];
                    $held['explicit'] = $key['explicit'] || $explicit;
                    $held['openEnded'] = !$held['explicit'] && ($key['openEnded'] || $openEnded);
                    unset($held);
                }
                // Where the span was not widened the creator has answered
                // with another key inside it before, which it does not do
                // unless it went back to a key it had left, and nothing more
                // is held about this key.
                return $stated;
            }
        }
        foreach (self::$cache[$endPoint] ?? [] as $other) {
            if ($other['last'] >= $first && $other['first'] <= $last) {
                return $stated;
            }
        }
        if (self::$heldKeys >= self::MAXIMUM_CACHED_KEYS) {
            self::$cache = [];
            self::$heldKeys = 0;
        }
        self::$cache[$endPoint][] = [
            'pem' => $pem,
            'first' => $first,
            'last' => $last,
            'explicit' => $explicit,
            'openEnded' => $openEnded,
        ];
        self::$heldKeys++;
        return $stated;
    }

    /**
     * Widens the span of the held key at the index to take in the span given,
     * and says whether it did. The span is not widened across a minute the
     * creator has answered with another key for, because that would mean the
     * creator had gone back to a key it had left, and the minutes between the
     * two spans are then not this key's to claim.
     */
    private static function widen(string $endPoint, int $index, int $first, int $last): bool
    {
        $key = self::$cache[$endPoint][$index];
        $first = min($first, $key['first']);
        $last = max($last, $key['last']);
        foreach (self::$cache[$endPoint] as $otherIndex => $other) {
            if ($otherIndex !== $index && $other['last'] >= $first && $other['first'] <= $last) {
                return false;
            }
        }
        self::$cache[$endPoint][$index]['first'] = $first;
        self::$cache[$endPoint][$index]['last'] = $last;
        return true;
    }

    /**
     * Performs the request and returns the body as text.
     *
     * @throws PublicKeyFetchException
     */
    private static function read(string $url, string $domain, ?callable $transport): string
    {
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, self::ACCEPTED_SCHEMES, true)) {
            // A scheme the caller chose that does not make an HTTP request,
            // such as file. Refused before anything is opened, because every
            // route into this class promises to ask a creator and nothing
            // else.
            throw new PublicKeyFetchException(
                'the scheme used for domain ' . self::quoted($domain)
                    . ' does not make an HTTP request',
                SignatureStatus::KeyUnavailable,
                $domain
            );
        }
        try {
            $answer = ($transport ?? self::streamTransport(...))($url, self::TIMEOUT_SECONDS);
        } catch (Exception $failed) {
            // A refused connection, a name that does not resolve and a
            // timeout all arrive here, and all of them mean the signature was
            // never examined.
            throw new PublicKeyFetchException(
                'the public key could not be fetched from domain '
                    . self::quoted($domain),
                SignatureStatus::KeyUnavailable,
                $domain,
                0,
                $failed
            );
        }
        if (
            !is_array($answer) || count($answer) !== 2
            || !is_int($answer[0]) || !is_string($answer[1])
        ) {
            throw new PublicKeyFetchException(
                'the transport did not return a response code and a body '
                    . 'for domain ' . self::quoted($domain),
                SignatureStatus::KeyUnavailable,
                $domain
            );
        }
        [$code, $body] = $answer;
        if ($code !== 200) {
            throw new PublicKeyFetchException(
                'domain ' . self::quoted($domain) . " returned code '" . $code
                    . "' for the public key",
                SignatureStatus::KeyUnavailable,
                $domain,
                $code
            );
        }
        if (strlen($body) > self::MAXIMUM_RESPONSE_BYTES) {
            throw new PublicKeyFetchException(
                'domain ' . self::quoted($domain)
                    . ' returned more than a key for the public key',
                SignatureStatus::KeyUnavailable,
                $domain,
                $code
            );
        }
        return $body;
    }

    /**
     * The transport used unless the caller supplies one, being the HTTP
     * stream wrapper. A refusal carrying a response code is returned as that
     * code, and only the failure to obtain any response at all is thrown.
     *
     * @return array{0: int, 1: string}
     *
     * @throws Exception when no response could be obtained.
     */
    private static function streamTransport(string $url, float $timeout): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "Accept: application/json\r\n",
                'timeout' => $timeout,
                'ignore_errors' => true,
                // Never followed. The wrapper would otherwise reopen
                // whatever Location names, any host and plain http
                // included, and a creator whose domain answered 302
                // would have that other place's key trusted as its
                // own. With ignore_errors the 3xx comes back as the
                // response code and is read as the key being
                // unavailable, which is what it is.
                'follow_location' => 0,
            ],
        ]);
        $http_response_header = [];
        $body = @file_get_contents(
            $url,
            false,
            $context,
            0,
            self::MAXIMUM_RESPONSE_BYTES + 1
        );
        if ($body === false) {
            $reason = error_get_last();
            throw new Exception(
                $reason['message'] ?? 'no response was obtained'
            );
        }
        return [self::responseCode($http_response_header), $body];
    }

    /**
     * The code of the last response in the headers the stream wrapper
     * collected, which is the one after any redirect, or 0 where there is no
     * status line at all.
     *
     * @param array<int, string> $headers
     */
    private static function responseCode(array $headers): int
    {
        $code = 0;
        foreach ($headers as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $found) === 1) {
                $code = (int) $found[1];
            }
        }
        return $code;
    }

    /**
     * Refuses a domain that would change the shape of the URL rather than
     * name a host in it.
     *
     * The domain arrives inside an OWID, which came from outside, so the text
     * is not the library's own. Letters, digits, dots and hyphens are all a
     * domain name needs, and anything else could add a query, a fragment, a
     * port, credentials or a path and send the request somewhere other than
     * the creator.
     *
     * @throws OwidException
     */
    private static function checkDomain(string $domain): void
    {
        if ($domain === '') {
            throw new OwidException('the OWID carries no domain');
        }
        // \z rather than $, because $ also matches before a final line
        // feed and would let "51d.es\n" through into the URL.
        if (preg_match('/^[A-Za-z0-9.-]+\z/', $domain) !== 1) {
            // The domain is not repeated back, because the text arrived from
            // outside and a refusal is often logged.
            throw new OwidException(
                'the domain in the OWID is not a domain name this library '
                    . 'will request a key from'
            );
        }
    }

    /** The value in single quotes, for a message. */
    private static function quoted(string $value): string
    {
        return "'" . $value . "'";
    }
}
