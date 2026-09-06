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
 * The usage a 51Did was created for, carried in bits 0-2 of the flags
 * byte and read with {@see FodId::getUsage()}. It decides where the
 * identifier may go: one
 * created for {@see Usage::NonMarketing} must never be passed to a demand
 * source, and one created for {@see Usage::Standard} or
 * {@see Usage::Personalized} may be passed only to a recipient that has
 * accepted the applicable terms.
 *
 * The three usages are cumulative rather than exclusive in the byte.
 * Non-marketing sets bit 0, standard sets bits 0 and 1, and personalized
 * sets bits 0, 1 and 2, so every marketing identifier also carries the
 * non-marketing bit. A caller who masked the byte for that bit alone would
 * read every marketing identifier as non-marketing, which is the wrong way
 * round for a data protection decision. {@see Usage::fromFlags()} answers
 * with the highest usage granted, so that mistake cannot be made.
 *
 * The case names are the cross language names of the usage, the same in
 * every 51Did package, and {@see Usage::idUsage()} gives the cloud's
 * `id.usage` value.
 */
enum Usage: int
{
    /**
     * No usage bit is set. The cloud never issues such an identifier, so
     * this is an identifier from somewhere else or a damaged one, and it
     * should be treated as though it may not be passed on.
     */
    case None = 0;

    /** Created for use that is not marketing. Must not be passed to a demand source. */
    case NonMarketing = 1;

    /** Created for standard marketing, being targeting unrelated to browsing history. */
    case Standard = 2;

    /** Created for personalized marketing, being targeting related to browsing history. */
    case Personalized = 3;

    /** Decodes the usage from bits 0-2 of a flags byte, as the highest usage granted. */
    public static function fromFlags(int $flags): self
    {
        if (($flags & 0b100) !== 0) {
            return self::Personalized;
        }
        if (($flags & 0b010) !== 0) {
            return self::Standard;
        }
        if (($flags & 0b001) !== 0) {
            return self::NonMarketing;
        }
        return self::None;
    }

    /** The cloud's `id.usage` value for this usage, or null for {@see Usage::None}. */
    public function idUsage(): ?string
    {
        return match ($this) {
            self::None => null,
            self::NonMarketing => 'non-marketing',
            self::Standard => 'standard',
            self::Personalized => 'personalized',
        };
    }
}
