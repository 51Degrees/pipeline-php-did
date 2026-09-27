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

use DateTimeImmutable;

/**
 * One entry of the 51Did signing key schedule as the cloud publishes it.
 * A key is in force from {@see PublicKey::$startsAt} until
 * {@see PublicKey::$endsAt}, the next key's start, or until the next key
 * starts where the cloud sent no end. The spacing between entries is
 * whatever the schedule was built with rather than a fixed period.
 */
final class PublicKey
{
    /** When the key comes into force, UTC. */
    public readonly DateTimeImmutable $startsAt;

    /** The public key in Subject Public Key Info (SPKI) PEM form. */
    public readonly string $pem;

    /**
     * When the key stops being in force, or null where the cloud sent no
     * end. This is the scheduled end, because a key may be replaced before
     * it, and the cloud then moves the end to the replacement's start.
     */
    public readonly ?DateTimeImmutable $endsAt;

    public function __construct(
        DateTimeImmutable $startsAt,
        string $pem,
        ?DateTimeImmutable $endsAt = null
    ) {
        $this->startsAt = $startsAt;
        $this->pem = $pem;
        $this->endsAt = $endsAt;
    }
}
