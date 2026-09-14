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
 * One signing public key together with the moment the key came into force.
 * The key stays in force until the next key in the schedule starts. Both
 * values are read only.
 */
final class DatedPublicKey
{
    private function __construct(
        /** The moment from which this key signs, in UTC. */
        public readonly DateTimeImmutable $startsAt,
        /**
         * The public key in Subject Public Key Info PEM form, as the public
         * key end point serves the key.
         */
        public readonly string $publicKeyPem
    ) {
    }

    /**
     * Creates a key from its start and its PEM. The start is held in UTC,
     * whatever zone it arrived in.
     *
     * @throws OwidException when the PEM is empty.
     */
    public static function of(DateTimeInterface $startsAt, string $publicKeyPem): self
    {
        if (trim($publicKeyPem) === '') {
            throw new OwidException('public key PEM is empty');
        }
        $moment = DateTimeImmutable::createFromInterface($startsAt)
            ->setTimezone(new DateTimeZone('UTC'));
        return new self($moment, $publicKeyPem);
    }
}
