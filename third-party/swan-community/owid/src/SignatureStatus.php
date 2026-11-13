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

/**
 * The outcome of asking whether an OWID signature is genuine.
 *
 * Only two of these say anything about the signature itself. The rest say the
 * question could not be answered, which is a different thing and must never be
 * reported as a forgery. A key that cannot be fetched, a key that cannot be
 * decoded, or a provider that fails leaves the signature unjudged, and a
 * caller acting on "invalid" would reject good identifiers during an outage.
 *
 * On 30 August 2026 the key end points served PEM that a strict parser
 * rejects, and every offline verification against it failed while the keys and
 * the identifiers were both fine. Reported as InvalidKey that reads as the
 * operational fault it was, whereas reported as SignatureInvalid it would have
 * read as an attack.
 */
enum SignatureStatus: string
{
    /** The signature is genuine for this data and this key. */
    case SignatureValid = 'SignatureValid';

    /**
     * The signature is the right length and does not match. The only status
     * that means the identifier should be distrusted.
     */
    case SignatureInvalid = 'SignatureInvalid';

    /**
     * A signature field of the wrong length reached this surface directly.
     * Truncation in raw external input is a parse failure instead, because
     * there the envelope never formed.
     */
    case InvalidSignatureLength = 'InvalidSignatureLength';

    /**
     * No key could be obtained, or none covers the date the identifier
     * carries, so the signature was never examined.
     *
     * Unreachable in this library, which never fetches a key. Obtaining the
     * creator public key over the network is the caller's job, so a caller
     * that cannot obtain one reports this itself.
     */
    case KeyUnavailable = 'KeyUnavailable';

    /**
     * Key material arrived but cannot be decoded, imported, or used as the
     * type required. The fault is in the key rather than the identifier.
     */
    case InvalidKey = 'InvalidKey';

    /**
     * The work required is more than this runtime can hold. Unreachable in
     * this library, where verification works on data already held in memory.
     */
    case ImplementationCapacityExceeded = 'ImplementationCapacityExceeded';

    /**
     * The check could not be completed for a reason that is not the
     * identifier's fault, such as the cryptographic provider failing on inputs
     * that were both valid.
     *
     * Unreachable here, and so untested. The two ways to reach it are openssl
     * reporting an error rather than a verdict, which valid key material and a
     * well formed signature do not produce, and fields that cannot be written
     * into the data a signature covers, which no OWID a caller can hold has,
     * because every one is either read or created, both routes bound every
     * field, and the marker for an absent node is never handed out. It is kept
     * because a caller of Crypto supplies its own data, and because a provider
     * failure must have somewhere to go other than SignatureInvalid.
     */
    case VerificationError = 'VerificationError';
}
