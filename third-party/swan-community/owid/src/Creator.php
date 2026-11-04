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
 * Needed to create new OWIDs.
 *
 * A creator binds the domain that hosts the well known end points to the
 * crypto instance holding the signing key.
 */
final class Creator
{
    private string $domain;
    private Crypto $crypto;

    /**
     * Creates a new creator for the domain using the crypto instance for
     * signing. The domain is bounded here, at the earliest point the caller
     * can be told, so a creator configured with a domain longer than a
     * domain name can hold is refused when the domain is supplied rather
     * than when an OWID is later serialized. The check comes before the
     * crypto instance is looked at, so nothing is signed with a domain this
     * same library would then refuse to read.
     *
     * @throws OwidException when the domain is empty or whitespace, is
     *                       longer than a domain name can hold, or the
     *                       crypto instance can not sign.
     */
    public function __construct(string $domain, Crypto $crypto)
    {
        if (trim($domain) === '') {
            throw OwidException::invalidDomain($domain);
        }
        if (strlen($domain) > OwidException::MAXIMUM_DOMAIN_LENGTH) {
            throw OwidException::domainTooLong();
        }
        if (!$crypto->canSign()) {
            throw OwidException::keyMissing('generate a signature');
        }
        $this->domain = $domain;
        $this->crypto = $crypto;
    }

    /**
     * Creates a new creator from the domain and the private key PEM provided.
     *
     * @throws OwidException when the domain is empty or whitespace, is
     *                       longer than a domain name can hold, or the
     *                       private key PEM is not valid.
     */
    public static function fromConfiguration(string $domain, string $privatePem): self
    {
        $crypto = Crypto::newSignOnly($privatePem);
        return new self($domain, $crypto);
    }

    /**
     * Domain associated with the OWID creator. Contains well known end points
     * to provide public keys and other information needed to conform to the
     * OWID specification.
     */
    public function domain(): string
    {
        return $this->domain;
    }

    /**
     * Used to sign OWIDs from this creator.
     */
    public function crypto(): Crypto
    {
        return $this->crypto;
    }

    /**
     * Creates and signs a new OWID for this creator carrying the payload
     * given. The signature covers the OWID's own bytes and nothing else.
     *
     * This is the only way to make an OWID, and it makes a finished one. The
     * creator owns the version, the domain, the date and the signature, so a
     * caller supplies the payload and nothing else and there is no moment at
     * which an unsigned OWID exists. Signing an OWID that already exists is
     * not offered, because there is nothing outside to sign and re-signing one
     * would replace a signature its fields were read with.
     *
     * A PHP string is a byte array, so the payload may be text or raw bytes
     * and there is one method rather than a pair.
     *
     * @throws OwidException when the fields can not be encoded or the signing
     *                       operation fails.
     */
    public function create(string $payload): Owid
    {
        return Owid::createSignedBy($this, $payload);
    }
}
