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
 * The byte offsets and lengths of the 51Did payload, for this package and
 * its tests only.
 *
 * The layout itself is published at
 * https://github.com/51Degrees/specifications/blob/main/did-specification/identifier-layout.md
 * which is the authority for what each byte holds, and
 * https://github.com/51Degrees/specifications/blob/main/did-specification/package-surface.md
 * lists what every 51Did package offers a caller.
 *
 * A caller reads a 51Did through the named accessors on {@see FodId},
 * being {@see FodId::getType()}, {@see FodId::getUsage()},
 * {@see FodId::isUsageFromConsent()}, {@see FodId::getLicenseId()} and
 * {@see FodId::getMatchKey()}, because every bit now has a name and
 * masking the bits by hand is how the usage gets read the wrong way
 * round. See {@see Usage} for why.
 *
 * @internal This class is not part of the published surface of the
 *           package and may change in any release.
 */
final class FodIdLayout
{
    /** Byte offset of the Flags field within the payload. */
    public const FLAGS_OFFSET = 0;
    /** Byte offset of the License Id field within the payload. */
    public const LICENSE_ID_OFFSET = 1;
    /** Byte length of the License Id field. */
    public const LICENSE_ID_LENGTH = 4;
    /** Byte offset of the match key field within the payload. */
    public const MATCH_KEY_OFFSET = 5;
    /** Byte length of the match key field (SHA-256). */
    public const MATCH_KEY_LENGTH = 32;
    /** Byte length of the header (Flags + License Id) common to every type. */
    public const HEADER_LENGTH = self::MATCH_KEY_OFFSET;
    /** Byte length of the GUID match key carried by Random identifiers. */
    public const GUID_LENGTH = 16;
    /** Minimum byte length of a Random 51Did payload. */
    public const RANDOM_PAYLOAD_LENGTH = self::HEADER_LENGTH + self::GUID_LENGTH;
    /**
     * Minimum byte length of a Probabilistic or HashedEmail 51Did payload
     * (Flags + License Id + match key). Random payloads are shorter, see
     * {@see FodIdLayout::RANDOM_PAYLOAD_LENGTH}.
     */
    public const PAYLOAD_LENGTH = self::MATCH_KEY_OFFSET
        + self::MATCH_KEY_LENGTH;

    /** Constants only, so there is nothing to build. */
    private function __construct()
    {
    }
}
