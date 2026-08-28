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

/**
 * The creator context verdict a redemption reports, mapped from the
 * `context` string the cloud sends.
 *
 * Every cryptographic failure comes back as the one word `unreadable`, by
 * design, so nothing here distinguishes them either. A string this build
 * does not know maps to {@see ContextOutcome::Unreadable} (fail closed) and
 * the raw value is kept on {@see RedeemResult::$rawContext}.
 */
enum ContextOutcome: string
{
    /**
     * The identifier is being presented from the browser and connection it
     * was created on.
     */
    case Verified = 'verified';

    /** At least one factor differs. {@see RedeemResult::$factors} says which. */
    case Mismatch = 'mismatch';

    /** The identifier carries no creator context, so there was nothing to check. */
    case NoContext = 'nocontext';

    /**
     * The context could not be judged, for example a section version the
     * service does not implement.
     */
    case NotCheckable = 'notcheckable';

    /** The sealed result was redeemed outside the service's freshness window. */
    case Expired = 'expired';

    /** The sealed result was already redeemed on this instance. */
    case Replayed = 'replayed';

    /**
     * The sealed result could not be read for this identifier under a secret
     * the service holds.
     */
    case Unreadable = 'unreadable';

    /** First use could not be confirmed (503). The caller may retry. */
    case Unconfirmed = 'unconfirmed';

    /**
     * Maps the cloud's `context` string, answering
     * {@see ContextOutcome::Unreadable} for anything not known.
     */
    public static function fromCloud(?string $value): self
    {
        return self::tryFrom((string) $value) ?? self::Unreadable;
    }
}
