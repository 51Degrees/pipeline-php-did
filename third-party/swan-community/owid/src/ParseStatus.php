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
 * Why reading an OWID succeeded or failed.
 *
 * Malformed data arriving from outside is expected rather than exceptional.
 * An OWID is read from whatever a caller was handed, which on a public end
 * point means anything at all, so every one of these outcomes is an ordinary
 * result. Raising for them would cost the construction and unwinding of an
 * exception for each bad input, and whoever is sending the data chooses how
 * often that happens.
 *
 * These names are the cross language vocabulary, so a failure means the same
 * thing whichever language read the bytes. The backing string is that shared
 * name and is stable, so it can be logged or carried between services.
 *
 * A status never carries the input that produced it, because logging a parse
 * failure must not log whatever an untrusted sender chose to put in it.
 */
enum ParseStatus: string
{
    /**
     * The bytes form a structurally valid OWID. This says nothing about the
     * signature, which is a separate question with a separate answer in
     * SignatureStatus.
     */
    case Parsed = 'Parsed';

    /**
     * The bytes are the marker for a node that is absent, a single zero byte,
     * rather than an OWID. Version 0 is supported and meaningful, so this is
     * not an unknown version, and the marker is not malformed either. It
     * simply is not an identifier.
     *
     * No OWID is handed back, because the marker carries no domain, date,
     * payload or signature and nothing mistakable for an identifier may reach
     * calling code. The result still reports the one byte as consumed, so a
     * caller walking a run of frames advances past the absent node and reads
     * the next one, which is the distinction this status exists to make, as an
     * absent node is not a malformed frame.
     */
    case AbsentNode = 'AbsentNode';

    /**
     * Nothing was supplied to read, whether that is a null, an empty string or
     * a buffer of no bytes. Kept apart from UnexpectedEnd, which is data that
     * arrived and stopped part way through a field.
     */
    case MissingInput = 'MissingInput';

    /**
     * The input arrived in a form this surface cannot read, such as the array
     * PHP builds when a query string repeats a parameter with brackets.
     */
    case InvalidInputType = 'InvalidInputType';

    /** The string is not valid base 64, so there are no bytes to read. */
    case InvalidBase64 = 'InvalidBase64';

    /**
     * The first byte names a version this implementation does not know. The
     * marker for an absent node is not this, because version 0 is supported
     * and meaningful, and is reported as AbsentNode.
     */
    case UnsupportedVersion = 'UnsupportedVersion';

    /**
     * The data stopped in the middle of a field, before the payload length
     * was even read. Distinct from ByteCountMismatch, which is a declaration
     * that disagrees with the bytes that follow it.
     */
    case UnexpectedEnd = 'UnexpectedEnd';

    /**
     * The creator domain has no terminator within the greatest number of
     * characters a domain name can hold, so whatever the field holds runs
     * past the bound.
     */
    case InvalidDomainEncoding = 'InvalidDomainEncoding';

    /**
     * The declared payload byte count disagrees with the bytes actually
     * present, whichever way they fall short. Checked before anything is
     * sized by the declaration, so a sender cannot make a reader allocate by
     * claiming a large payload it did not send.
     */
    case ByteCountMismatch = 'ByteCountMismatch';

    /**
     * The envelope is structurally consistent but larger than this runtime
     * can hold. Not the data being wrong, and deliberately kept apart from
     * it, because the same bytes may be readable elsewhere.
     *
     * Unreachable on a 64 bit runtime, where every value the four byte length
     * field can hold fits in an integer, and unreachable in practice on a 32
     * bit one as well, because a declaration past the integer range could
     * only agree with the bytes present if a string larger than a 32 bit PHP
     * build can hold had already been read. The status exists so that a
     * future change to that arithmetic has somewhere honest to report to.
     */
    case ImplementationCapacityExceeded = 'ImplementationCapacityExceeded';

    /**
     * Malformed in a way none of the above describes. A fallback for the
     * genuinely unclassified, not a substitute for naming a failure that is
     * already understood.
     *
     * Unreachable from the surfaces as they stand, and so untested, because
     * every way an envelope can be wrong is already named. The two places that
     * report it are guards a correct reader never reaches, being a date the
     * runtime's calendar cannot express, which the four byte minute count
     * cannot produce, and bytes left after the payload and signature, which
     * the byte count check has already made impossible. The second is not dead
     * code: changing that check to accept a longer buffer makes four tests
     * fail on this status, so it does catch an arithmetic mistake in the check
     * above it.
     */
    case MalformedEnvelope = 'MalformedEnvelope';
}
