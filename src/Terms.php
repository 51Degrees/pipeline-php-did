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
 * The terms document a 51Did was created under, carried in the byte after
 * the match key and read with {@see FodId::getTerms()}. Carrying the terms
 * in the identifier means they travel with it rather than alongside it, so
 * a receiver can tell which document was in force when the identifier was
 * made without depending on whatever else arrived with it.
 *
 * The byte is an index into a table in the specification and is not a
 * version number, so that a later document can live at any address rather
 * than only at one composed from a number. An index is never reused or
 * repointed once published, because an identifier issued under it has to
 * stay readable years later and repointing it would rewrite what a past
 * identifier says it agreed to.
 *
 * The usage and the terms answer different questions and a receiver needs
 * both, as the usage says where an identifier may go whilst this says
 * under which document it was created.
 *
 * Each case is backed by the Terms index the payload carries, and
 * {@see Terms::$ADDRESSES} maps a case to its address, so the whole of the
 * definition of which index is which document is in this one file. A new
 * terms document is one new case and one new row, and nothing else in the
 * package changes.
 *
 * {@see Terms::Unknown} stands for every index this release does not name
 * and so has no index of its own, which is why it is backed by -1. A Terms
 * index read from a payload is one byte, so it is 0 to 255 and can never be
 * negative, and that is what makes -1 safe as the value not in the table.
 *
 * This enum is not part of the published surface. The package turns the
 * index into the address that {@see FodId::getTerms()} answers with, so a
 * caller never handles the byte, and the names here are the ones the
 * specification gives so that every package describes one document the
 * same way.
 *
 * @internal
 */
enum Terms: int
{
    /**
     * The terms are not stated in the identifier, being an index of zero
     * or a payload that ends at the match key. This does not mean
     * the identifier is unrestricted, only that the answer has to come
     * from somewhere else, being the Terms Document Locator in an OpenRTB
     * request or whatever the surrounding protocol provides. Carrying the
     * terms here does not remove the need to carry that locator where a
     * protocol has one, and where the two disagree a receiver should take
     * this value as the one that describes the identifier, since it is
     * inside the signature and the accompanying data is not.
     *
     * An identifier created for non-marketing carries this, because the
     * Model Terms govern marketing use, and such an identifier is barred
     * from a demand source by its usage rather than by its terms.
     */
    case NotStated = 0;

    /** Index 1, the Model Terms for Marketing version 2. */
    case ModelTermsForMarketing2 = 1;

    /**
     * An index added after this release, so terms are stated that this
     * package cannot name. It is not {@see Terms::NotStated}, and reading
     * the two as the same would take an identifier created under terms for
     * one created under none. A caller meeting this should treat the
     * identifier as covered by terms it cannot yet read, and either update
     * the package or refuse the identifier. It answers with no address, as
     * {@see Terms::NotStated} does, because no package may build an
     * address from an index it does not know, and the index itself is not
     * published.
     */
    case Unknown = -1;

    /**
     * The terms table from the specification, which is the whole of the
     * definition of which index is which document. It is published at
     * https://github.com/51Degrees/specifications/blob/main/did-specification/identifier-layout.md#terms
     * and this is the only place in the shipped code that carries it. The
     * tests write the address out again on purpose, so that a test never
     * compares the reader with itself.
     *
     * One row per terms document, keyed by the case's own index so the
     * number is written once. {@see Terms::NotStated} and
     * {@see Terms::Unknown} have no row, because neither names a document,
     * and a lookup that finds no row is the answer for both.
     *
     * Each address names an exact version rather than a landing page,
     * because a receiver has to know the document in force when the
     * identifier was made and an address whose contents can be edited
     * cannot prove that. A later version is a new index and a new release,
     * which is the cost of a receiver being able to trust what it reads.
     */
    private const ADDRESSES = [
        self::ModelTermsForMarketing2->value => 'https://m4ow.uk/mtm/2.txt',
    ];

    /**
     * Names the terms an index stands for, answering {@see Terms::Unknown}
     * for an index this release does not know rather than
     * {@see Terms::NotStated}, so that an identifier created under terms
     * never reads as one created under none.
     */
    public static function fromIndex(int $index): self
    {
        return self::tryFrom($index) ?? self::Unknown;
    }

    /**
     * The address of the terms document, or null where there is none to
     * give. A package never fetches the address and never builds one from
     * the index, so the receiver decides what to do with it.
     */
    public function url(): ?string
    {
        return self::ADDRESSES[$this->value] ?? null;
    }
}
