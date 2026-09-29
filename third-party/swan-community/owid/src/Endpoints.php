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
use DateTimeZone;

/**
 * Helpers for hosting the well known end points required by the OWID
 * specification. These are framework agnostic. They return the path and body
 * so that any HTTP server can serve them.
 *
 * The mandatory end points are the creator end point at
 * /owid/api/v{version}/creator returning JSON with the domain, common name,
 * and public key of the creator, and the public key end point at
 * /owid/api/v{version}/public-key returning the public key as PEM text where
 * the format query parameter must be spki or pkcs.
 *
 * A creator that rotates its signing key answers the optional date parameter
 * of the public key end point with publicKeyResponseAt, which chooses from
 * the published schedule the way the specification requires.
 */
final class Endpoints
{
    /**
     * Returns the path of the creator end point for the version provided. For
     * example /owid/api/v3/creator.
     */
    public static function creatorPath(Version $version): string
    {
        return '/owid/api/v' . $version->asByte() . '/creator';
    }

    /**
     * Returns the path of the public key end point for the version provided.
     * For example /owid/api/v3/public-key.
     */
    public static function publicKeyPath(Version $version): string
    {
        return '/owid/api/v' . $version->asByte() . '/public-key';
    }

    /**
     * Returns the JSON body for the creator end point. The fields match the
     * names required by the specification.
     *
     * @throws OwidException when the public key can not be exported or the
     *                       JSON can not be produced.
     */
    public static function creatorResponse(
        Creator $creator,
        string $name,
        string $contractUrl = ''
    ): string {
        $body = [
            'domain' => $creator->domain(),
            'name' => $name,
            'publicKeySPKI' => $creator->crypto()->subjectPublicKeyInfo(),
            'contractURL' => $contractUrl,
        ];
        $json = json_encode($body, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw OwidException::key(json_last_error_msg());
        }
        return $json;
    }

    /**
     * Returns the text body for the public key end point. The specification
     * allows the key to be requested in SPKI or PKCS form. This implementation
     * returns the SPKI PEM for both values because the importers in every
     * implementation accept it.
     *
     * @throws OwidException when the format is not spki or pkcs, or the public
     *                       key can not be exported.
     */
    public static function publicKeyResponse(Creator $creator, string $format): string
    {
        if ($format === 'spki' || $format === 'pkcs') {
            return $creator->crypto()->subjectPublicKeyInfo();
        }
        throw OwidException::invalidKeyFormat($format);
    }

    /**
     * Returns the status code and text body for the public key end point of
     * a creator that rotates its key, chosen from the schedule the way the
     * specification requires.
     *
     * The date parameter is the OWID's own date, counted in whole minutes
     * since 2020-01-01, and the key served is the one in force then, being
     * the latest key whose start is at or before it. A request without a
     * date, or with a date later than the moment of the request, is served
     * the key in force at that moment, so a caller cannot ask for a key whose
     * period has not begun. The answer is 200 with the PEM, 404 with an empty
     * body where no key is in force at the date, and 400 with an empty body
     * where the date is not a count of minutes. The moment of the request is
     * now, and a test may supply it.
     *
     * @return array{0: int, 1: string} the status code and the body
     *
     * @throws OwidException when the format is not spki or pkcs.
     */
    public static function publicKeyResponseAt(
        PublicKeySchedule $schedule,
        string $format,
        mixed $date,
        ?DateTimeImmutable $now = null
    ): array {
        if ($format !== 'spki' && $format !== 'pkcs') {
            throw OwidException::invalidKeyFormat($format);
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
        return [200, $key->publicKeyPem];
    }
}
