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

use SwanCommunity\Owid\ParseStatus;

/**
 * What reading a 51Did produced, and why.
 *
 * The same three facts are always reported, exactly as the OWID library
 * reports them for an envelope. Whether it worked, which ordinary caller
 * logic tests with `if ($result->ok)`. The 51Did, which is present only on
 * success and is never a half read one. A named reason, which is
 * {@see ParseStatus::Parsed} on success and the specific problem otherwise.
 *
 * The reason is one of two kinds and a caller can tell them apart by type.
 * A {@see ParseStatus} came from the OWID library and means the envelope
 * itself could not be read, and it is the library's own value with nothing
 * mapped or renamed. A {@see FodIdParseStatus} means the envelope was sound
 * and the payload inside it does not fit a 51Did. Both are string backed
 * with the cross language name of the status, so `$result->status->value`
 * is safe to log whichever kind it is.
 *
 * A successful result says nothing about the signature. A parsed 51Did is
 * not necessarily genuine, and {@see FodId::verify()},
 * {@see FodId::signatureStatus()} or {@see DidClient::verifySignature()}
 * answer that separately.
 *
 * The fields are read only, so a result cannot be changed into saying
 * something the read did not find.
 */
final class FodIdParseResult
{
    /**
     * Built by the reader in {@see FodId} alone, so a result always
     * describes a read that actually happened.
     */
    private function __construct(
        /** True when the value was a 51Did in a structurally valid OWID. */
        public readonly bool $ok,
        /** The 51Did on success, and null on failure. */
        public readonly ?FodId $fodId,
        /**
         * {@see ParseStatus::Parsed} on success. Otherwise the OWID
         * library's reason, unchanged, or one of the two reasons of this
         * package.
         */
        public readonly ParseStatus|FodIdParseStatus $status
    ) {
    }

    /**
     * A successful read of the 51Did given.
     *
     * @internal Used by the reader in FodId.
     */
    public static function parsed(FodId $fodId): self
    {
        return new self(true, $fodId, ParseStatus::Parsed);
    }

    /**
     * A read that did not produce a 51Did, for the reason given.
     *
     * @internal Used by the reader in FodId.
     */
    public static function failed(ParseStatus|FodIdParseStatus $status): self
    {
        return new self(false, null, $status);
    }
}
