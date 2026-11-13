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
 * The byte version of an OWID. Always the first byte of the serialized form.
 *
 * Versions 1 and 2 were deprecated during development of the specification
 * because they used an insecure algorithm or an insufficiently precise time
 * indicator. They remain readable for compatibility with data created by
 * earlier implementations.
 */
enum Version: int
{
    /** Marker used to indicate an optional OWID that is not present. */
    case Empty = 0;

    /**
     * Deprecated. Stored the date as a two byte big endian count of hours
     * elapsed since the base date.
     */
    case Version1 = 1;

    /**
     * Deprecated. Stored the date as a four byte little endian count of
     * minutes elapsed since the base date.
     */
    case Version2 = 2;

    /** The current version. The wire format is identical to version 2. */
    case Version3 = 3;

    /**
     * Returns the default version used for new OWIDs.
     */
    public static function default(): self
    {
        return self::Version3;
    }

    /**
     * Returns the version as the byte written to the serialized form.
     */
    public function asByte(): int
    {
        return $this->value;
    }

    // A byte that names no version is reported by the parser as the
    // UnsupportedVersion status rather than raised, so the enum's own
    // tryFrom is all the reader needs and there is no throwing lookup here.
}
