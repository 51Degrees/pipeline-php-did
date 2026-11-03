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

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;

/**
 * Helpers for hosting the well known end points required by the OWID
 * specification. These are framework agnostic. They return the path and body
 * so that any HTTP server can serve them.
 *
 * The mandatory end point is the public key end point at
 * /owid/api/v{version}/public-key returning the public key as a JSON object
 * that states the encoding of the key, the key, and the moments it is valid
 * from and to. The only encoding defined is spki, which a request without a
 * format parameter receives, and a request for any other value is answered
 * 400 rather than in an encoding the caller did not ask for.
 *
 * A creator that rotates its signing key answers the optional date parameter
 * of the public key end point with publicKeyResponseAt, which chooses from
 * the published schedule the way the specification requires.
 */
final class Endpoints
{
    /**
     * The one encoding of the key this library reads and writes, a Subject
     * Public Key Info PEM. It is the value of the format field of every
     * answer and the value taken when a request names no format.
     */
    public const SPKI_FORMAT = 'spki';

    /**
     * Returns the path of the public key end point for the version provided.
     * For example /owid/api/v3/public-key.
     */
    public static function publicKeyPath(Version $version): string
    {
        return '/owid/api/v' . $version->asByte() . '/public-key';
    }

    /**
     * Returns the JSON body for the public key end point of a creator with one
     * key and no schedule. The key is stated as publicKey in the spki
     * encoding and both validFrom and validTo are null, because the creator
     * knows nothing about when the key started or will stop.
     *
     * The format is the value of the request's format parameter, or null
     * where the request carried none, which is read as spki. A host answers
     * 400 for the refusal of any other value, the way publicKeyResponseAt
     * answers it.
     *
     * @throws OwidException when the format is not spki, or the key cannot
     *                       be read.
     */
    public static function publicKeyResponse(Creator $creator, mixed $format = null): string
    {
        if (!self::formatIsSpki($format)) {
            throw OwidException::invalidKeyFormat(is_string($format) ? $format : gettype($format));
        }
        return self::publicKeyAnswer($creator->crypto()->subjectPublicKeyInfo(), null, null, null);
    }

    /**
     * Whether the format a request asked for is the one this library serves,
     * which a request that named none is read as asking for.
     */
    private static function formatIsSpki(mixed $format): bool
    {
        return $format === null || $format === '' || $format === self::SPKI_FORMAT;
    }

    /**
     * Returns the JSON body of the public key end point for the key and the
     * span it covers, checked with validatePublicKeyAnswer first so that a
     * creator never sends an answer it would itself refuse. The moment asked
     * about, where known, is checked against the span as well. The answer
     * states the format as spki, the one encoding this library writes.
     *
     * @throws OwidException when the answer would not be valid.
     */
    public static function publicKeyAnswer(
        string $publicKeyPem,
        ?DateTimeInterface $validFrom,
        ?DateTimeInterface $validTo,
        ?DateTimeInterface $asked
    ): string {
        $answer = [
            'format' => self::SPKI_FORMAT,
            'publicKey' => $publicKeyPem,
            'validFrom' => self::momentText($validFrom),
            'validTo' => self::momentText($validTo),
        ];
        self::validatePublicKeyAnswer($answer, $asked);
        $body = json_encode($answer);
        if ($body === false) {
            throw new OwidException('the public key answer could not be written as JSON');
        }
        return $body;
    }

    /**
     * Checks a public key answer the way both the creator that sends it and
     * the client that reads it must, returning the key and the moments it is
     * valid from and to.
     *
     * The format, where stated, must be the one this library reads, the key
     * must be a public key in it, a key valid to a moment must be valid from
     * an earlier one, and where the moment asked about is known the key must
     * have come into force by then and, if it has an end, not have ended. A
     * creator that fails this check has a fault in its schedule or its store,
     * and answering with a server error shows it up rather than passing it
     * on.
     *
     * @return array{0: string, 1: ?DateTimeImmutable, 2: ?DateTimeImmutable}
     * @throws OwidException where the answer is not valid.
     */
    public static function validatePublicKeyAnswer(mixed $answer, ?DateTimeInterface $asked): array
    {
        if (!is_array($answer)) {
            throw new OwidException('the public key answer is not a JSON object');
        }
        if (($answer['format'] ?? self::SPKI_FORMAT) !== self::SPKI_FORMAT) {
            throw new OwidException('the public key answer states a format this library does not read');
        }
        $pem = $answer['publicKey'] ?? null;
        if (!is_string($pem) || trim($pem) === '') {
            throw new OwidException('the public key answer holds no key');
        }
        try {
            Crypto::newVerifyOnly($pem);
        } catch (OwidException $failed) {
            throw new OwidException('the public key answer holds a key that cannot be read', 0, $failed);
        }
        $validFrom = self::momentOf($answer['validFrom'] ?? null, 'validFrom');
        $validTo = self::momentOf($answer['validTo'] ?? null, 'validTo');
        if ($validTo !== null) {
            if ($validFrom === null) {
                throw new OwidException('the public key answer states when the key ends but not when it started');
            }
            if ($validTo <= $validFrom) {
                throw new OwidException('the public key answer states a key that ends before it starts');
            }
        }
        if ($asked !== null) {
            $moment = DateTimeImmutable::createFromInterface($asked);
            if ($validFrom !== null && $validFrom > $moment) {
                throw new OwidException(
                    'the public key answer states a key that had not started at the moment asked about'
                );
            }
            if ($validTo !== null && $validTo <= $moment) {
                throw new OwidException(
                    'the public key answer states a key that had ended at the moment asked about'
                );
            }
        }
        return [$pem, $validFrom, $validTo];
    }

    /** The moment as an RFC 3339 string in UTC, or null. */
    private static function momentText(?DateTimeInterface $moment): ?string
    {
        if ($moment === null) {
            return null;
        }
        return DateTimeImmutable::createFromInterface($moment)
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('Y-m-d\TH:i:s\Z');
    }

    /**
     * The field's value as a UTC moment, or null where it is null.
     *
     * @throws OwidException where it is anything else.
     */
    private static function momentOf(mixed $value, string $field): ?DateTimeImmutable
    {
        if ($value === null) {
            return null;
        }
        if (!is_string($value) || preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/', $value) !== 1) {
            throw new OwidException("the public key answer's $field is not a moment");
        }
        $moment = DateTimeImmutable::createFromFormat(DATE_ATOM, preg_replace('/\.\d+/', '', $value));
        if ($moment === false) {
            throw new OwidException("the public key answer's $field is not a moment");
        }
        return $moment->setTimezone(new DateTimeZone('UTC'));
    }

    /**
     * Returns the status code and text body for the public key end point of
     * a creator that rotates its key, chosen from the schedule the way the
     * specification requires.
     *
     * The format parameter is the encoding the caller asks for the key in,
     * or null where the request carried none, which is read as spki. The
     * date parameter is the OWID's own date, counted in whole minutes since
     * 2020-01-01, and the key served is the one in force then, being the
     * latest key whose start is at or before it. A request without a date,
     * or with a date later than the moment of the request, is served the key
     * in force at that moment, so a caller cannot ask for a key whose period
     * has not begun. The answer is 200 with the JSON body from
     * publicKeyAnswer, stating the format, the key and the moments it is
     * valid from and to, 404 with an empty body where no key is in force at
     * the date, and 400 with an empty body where the format is not spki or
     * the date is not a count of minutes. The moment of the request is now,
     * and a test may supply it.
     *
     * @return array{0: int, 1: string} the status code and the body
     * @throws OwidException when the answer would fail
     *                       validatePublicKeyAnswer, which is a fault in the
     *                       schedule.
     */
    public static function publicKeyResponseAt(
        PublicKeySchedule $schedule,
        mixed $format,
        mixed $date,
        ?DateTimeImmutable $now = null
    ): array {
        if (!self::formatIsSpki($format)) {
            // An encoding this library does not write is refused rather than
            // answered in one the caller did not ask for.
            return [400, ''];
        }
        $moment = $now ?? new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $asked = $moment;
        if (is_int($date)) {
            // A framework that has already parsed the query hands an int.
            $date = (string) $date;
        }
        if ($date !== null && $date !== '') {
            // Anything that is not a string of digits is refused, which
            // covers an array from ?date[]=1, a bool, and a float, rather
            // than letting the type system throw a 500 out of a 400.
            if (!is_string($date)
                || preg_match('/^[0-9]{1,10}\z/', $date) !== 1
                || (int) $date > 0xFFFFFFFF) {
                return [400, ''];
            }
            $asked = Io::baseDate()->modify('+' . $date . ' minutes');
            if ($asked === false || $asked > $moment) {
                $asked = $moment;
            }
        }
        $key = $schedule->keyInForce($asked);
        if ($key === null) {
            return [404, ''];
        }
        return [200, self::publicKeyAnswer(
            $key->publicKeyPem,
            $key->startsAt,
            $schedule->nextStartAfter($key),
            $asked
        )];
    }
}
