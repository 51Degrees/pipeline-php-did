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

use Countable;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;

/**
 * The signing public keys a creator has published, held so that the key
 * which was in force at any date can be found.
 *
 * Creators rotate weekly, so the key that is current when an identifier is
 * checked is not the key that signed the identifier unless the check happens
 * in the same week. Verifying anything older than a few days means choosing
 * the right key out of the schedule, and this class holds the rule for that
 * choice in one place so every caller makes the same choice.
 *
 * The rule is the one the cloud itself applies, being the latest key whose
 * start is at or before the date asked about. Keys are generated in batches,
 * often many weeks ahead of the weeks the keys cover, so the moment key
 * material was generated says nothing about which key signed anything and is
 * not held here at all. Selecting on a generation moment picks a key that has
 * not started yet and reports a genuine identifier as not matching, which is
 * what the .NET port did before that port was fixed.
 *
 * A date the schedule does not reach, being one earlier than the first start,
 * has no key. That answer is reported as SignatureStatus::KeyUnavailable
 * rather than as a signature that does not match, because with no key the
 * signature was never examined.
 */
final class PublicKeySchedule implements Countable
{
    /**
     * @param array<int, DatedPublicKey> $keys oldest start first
     */
    private function __construct(private readonly array $keys)
    {
    }

    /**
     * Creates a schedule over the keys provided. The keys may arrive in any
     * order and are held oldest start first.
     *
     * Where two keys share a start, the one supplied first wins, which is how
     * the 51Degrees cloud and the .NET port settle it. A creator does not
     * publish two keys for one start, so the case is settled rather than left
     * to chance.
     *
     * @param iterable<mixed> $keys the published keys
     *
     * @throws OwidException when a key in the collection is missing.
     */
    public static function of(iterable $keys): self
    {
        $ordered = [];
        foreach ($keys as $key) {
            if (!$key instanceof DatedPublicKey) {
                throw new OwidException('a key in the schedule is missing');
            }
            $ordered[] = $key;
        }
        // The sort is stable, so keys sharing a start keep the order they
        // were supplied in and the first supplied stays first.
        usort(
            $ordered,
            static fn (DatedPublicKey $left, DatedPublicKey $right): int =>
                $left->startsAt <=> $right->startsAt
        );
        return new self($ordered);
    }

    /**
     * The keys held, oldest start first. The array is a copy, so the schedule
     * cannot be changed through it.
     *
     * @return array<int, DatedPublicKey>
     */
    public function keys(): array
    {
        return $this->keys;
    }

    /**
     * The number of keys held.
     */
    public function count(): int
    {
        return count($this->keys);
    }

    /**
     * Returns the key that was in force at the date given, being the latest
     * key whose start is at or before that date, or null where the schedule
     * begins after the date.
     */
    public function keyInForce(?DateTimeInterface $date): ?DatedPublicKey
    {
        if ($date === null) {
            return null;
        }
        $moment = DateTimeImmutable::createFromInterface($date);
        for ($index = count($this->keys) - 1; $index >= 0; $index--) {
            $key = $this->keys[$index];
            if ($key->startsAt <= $moment) {
                // Keys sharing a start sit in the order supplied, and the
                // first supplied is the answer.
                while (
                    $index > 0
                    && $this->keys[$index - 1]->startsAt == $key->startsAt
                ) {
                    $index--;
                    $key = $this->keys[$index];
                }
                return $key;
            }
        }
        return null;
    }

    /**
     * Returns the key with the latest start, or null where the schedule holds
     * no keys.
     *
     * This is not the key in force now. A creator publishes its schedule
     * ahead of time, so the last key by start is usually one whose period has
     * not begun and which has signed nothing yet. The key in force now is
     * current(). Serving the last key where the current one was meant is the
     * same fault as selecting by the generation moment, being a key from a
     * period that has not started, and it is the fault the .NET port carried
     * in its answer to a request that named no date.
     */
    public function last(): ?DatedPublicKey
    {
        if ($this->keys === []) {
            return null;
        }
        return $this->keys[count($this->keys) - 1];
    }

    /**
     * Returns the key in force now, being the latest key whose start is at or
     * before the current moment, or null where no key has started. This is
     * what a creator serves for a request that names no date.
     */
    public function current(): ?DatedPublicKey
    {
        return $this->keyInForce(new DateTimeImmutable('now', new DateTimeZone('UTC')));
    }

    /**
     * Returns the key that signed the OWID, being the key in force at the
     * date the OWID carries, or null where the schedule does not reach back
     * to that date.
     */
    public function keyFor(?Owid $owid): ?DatedPublicKey
    {
        if ($owid === null) {
            return null;
        }
        return $this->keyInForce($owid->date);
    }

    /**
     * Says whether the signature on the OWID is genuine, using the key that
     * was in force when the OWID was signed. The answer is
     * SignatureStatus::KeyUnavailable where the schedule holds no key for the
     * date, because the signature was never examined.
     *
     * @param array<int, Owid> $others the other OWIDs that were signed
     *                                 together with this one, in the same
     *                                 order as when signed
     */
    public function signatureStatus(?Owid $owid, array $others = []): SignatureStatus
    {
        if ($owid === null) {
            return SignatureStatus::KeyUnavailable;
        }
        $key = $this->keyFor($owid);
        if ($key === null) {
            return SignatureStatus::KeyUnavailable;
        }
        return $owid->signatureStatus($key->publicKeyPem, $others);
    }

    /**
     * Returns true only when the signature verifies under the key in force
     * when the OWID was signed.
     *
     * @param array<int, Owid> $others
     */
    public function verify(?Owid $owid, array $others = []): bool
    {
        return $this->signatureStatus($owid, $others) === SignatureStatus::SignatureValid;
    }
}
