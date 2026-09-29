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
 * What reading an OWID produced, and why.
 *
 * The same three facts are always reported. Whether it worked, which ordinary
 * caller logic can test with `if ($result->ok)`. The OWID, which is present
 * only on success. A named reason, which is ParseStatus::Parsed on success and
 * the specific problem otherwise.
 *
 * One reason is neither a success nor a fault. The marker for an absent node
 * is well formed and is not an OWID, so it reports ParseStatus::AbsentNode
 * with no value and with its one byte counted as consumed, which lets a caller
 * walking a run of frames step over it and read the next one.
 *
 * The fields are read only, so a result cannot be changed into saying
 * something the parse did not find.
 */
final class ParseResult
{
    /**
     * Built by the parser alone, so a result always describes a parse that
     * actually happened.
     */
    private function __construct(
        /** True when the bytes were a complete, structurally valid OWID. */
        public readonly bool $ok,
        /** The OWID on success, and null on failure. */
        public readonly ?Owid $owid,
        /** Parsed on success, and the specific reason otherwise. */
        public readonly ParseStatus $status,
        /**
         * The number of bytes accounted for, counted from the offset the read
         * started at, and zero when nothing could be accounted for. A caller
         * reading several OWIDs from one buffer adds this to its offset to
         * reach the next. An absent node counts its one marker byte, so the
         * same arithmetic steps over it.
         */
        public readonly int $consumed
    ) {
    }

    /**
     * A successful read of the OWID given, which occupied the number of bytes
     * given.
     *
     * @internal Used by the parser in Owid.
     */
    public static function parsed(Owid $owid, int $consumed): self
    {
        return new self(true, $owid, ParseStatus::Parsed, $consumed);
    }

    /**
     * A read that did not produce an OWID, for the reason given.
     *
     * @internal Used by the parser in Owid.
     */
    public static function failed(ParseStatus $status): self
    {
        return new self(false, null, $status, 0);
    }

    /**
     * A read that found the marker for an absent node, which occupied the
     * number of bytes given.
     *
     * Neither a value nor a fault, so ok is false, because there is no OWID,
     * while the bytes are still counted, because the frame was understood.
     *
     * @internal Used by the parser in Owid.
     */
    public static function absentNode(int $consumed): self
    {
        return new self(false, null, ParseStatus::AbsentNode, $consumed);
    }
}
