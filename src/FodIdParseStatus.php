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
 * The two ways a structurally valid OWID can still fail to be a 51Did.
 *
 * Reading a 51Did is two steps. The OWID library reads the envelope and
 * reports one of its own {@see \SwanCommunity\Owid\ParseStatus} values,
 * which this package passes on unchanged, so a caller sees the library's
 * specific reason and never a generic one. Only when the envelope is sound
 * does this package look inside the payload, and these are the two things
 * the payload can get wrong. Together with the library's statuses they are
 * the whole vocabulary a {@see FodIdParseResult} can carry.
 *
 * The backing string is the cross language name of the status, the same in
 * every 51Did package, so it can be logged or carried between services. A
 * status never carries the input that produced it, so logging a failure
 * never logs whatever an untrusted sender chose to put in it.
 */
enum FodIdParseStatus: string
{
    /**
     * The payload holds fewer than the {@see FodId::HEADER_LENGTH} bytes of
     * flags and licence id that every identifier type shares, so the type
     * cannot even be read.
     */
    case PayloadTooShort = 'PayloadTooShort';

    /**
     * The header was read and named a type whose match key the payload is
     * too short to hold, being {@see FodId::GUID_LENGTH} bytes after the
     * header for a Random identifier and {@see FodId::MATCH_KEY_LENGTH}
     * bytes for a Probabilistic or HashedEmail one. A Reserved identifier
     * takes whatever follows the header, so it never reports this.
     */
    case InvalidTypePayloadLength = 'InvalidTypePayloadLength';
}
