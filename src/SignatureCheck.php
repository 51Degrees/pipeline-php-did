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
 * Why an offline signature check answered as it did.
 *
 * {@see DidClient::verifySignature()} answers only true or false, which is
 * enough when a caller just gates on the result. This says which of the
 * five things happened, so a caller can tell a forged identifier from one
 * this package could not check at all, and log the difference. Only
 * {@see SignatureCheck::Verified} means the signature was examined against
 * a key and matched.
 *
 * The backing string is the cross language name of the outcome, the same in
 * every 51Did package, so it can be logged or carried between services. An
 * outcome never carries the identifier that produced it, so logging a
 * failure never logs whatever an untrusted sender chose to put in it.
 */
enum SignatureCheck: string
{
    /**
     * A candidate key verified the signature. The only outcome that says
     * the identifier is genuine.
     */
    case Verified = 'Verified';

    /**
     * Every candidate key was tried and none verified the signature, so
     * the identifier does not match any key that could have signed it on
     * its own date. This is the outcome that says forged.
     */
    case Invalid = 'Invalid';

    /**
     * The published schedule holds no key covering the identifier's date,
     * either because the date precedes the whole schedule or because the
     * endpoint published no keys at all. The signature was never
     * examined, so this must not be read as forged.
     */
    case NoKeyForDate = 'NoKeyForDate';

    /**
     * The envelope is not version 3. Nothing was ever issued under an
     * earlier version, so the signature was not examined.
     */
    case UnsupportedVersion = 'UnsupportedVersion';

    /**
     * The payload is shorter than the base length its type requires, so
     * there is no complete identifier to check. A payload longer than the
     * base carries a creator context section and is accepted.
     */
    case InvalidLength = 'InvalidLength';
}
