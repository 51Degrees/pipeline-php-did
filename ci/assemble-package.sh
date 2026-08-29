#!/usr/bin/env bash
#
# Assemble the tree that is published for a tagged release.
#
# During development the OWID library is a git submodule consumed
# through a Composer "path" repository. That works in a checkout and
# cannot work for a consumer, because Packagist serves GitHub's archive
# of the tag and a git archive writes a submodule as an empty directory,
# so the published package would have no OWID source and a requirement
# on a package that is not on Packagist.
#
# This script builds the tree that is published instead. It copies the
# OWID source into the package, carries the Apache-2.0 licence text and
# a notice recording where the copy came from, and writes a composer.json
# with no path repository and no unresolvable requirement. The OWID
# source is not modified and it keeps its SwanCommunity namespace, so the
# copy is byte for byte what the upstream library ships.
#
# Usage:
#
#   ci/assemble-package.sh <output directory>
#
# Run it from a checkout whose submodules have been initialised, for
# example with "git submodule update --init". The output directory is
# emptied first.

set -euo pipefail

fail() {
    echo "assemble-package: $1" >&2
    exit 1
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

[ $# -eq 1 ] || fail "usage: ci/assemble-package.sh <output directory>"
out="$1"

[ -f owid-php/src/Owid.php ] || fail \
    "the owid-php submodule is empty, run 'git submodule update --init'"

owid_commit="$(git -C owid-php rev-parse HEAD)" || fail \
    "cannot read the commit of the owid-php submodule"
owid_url="$(git -C owid-php config --get remote.origin.url || true)"
[ -n "$owid_url" ] || owid_url="https://github.com/51Degrees/owid-php"

rm -rf "$out"
mkdir -p "$out"

# Everything the package needs at runtime, plus the tests and examples so
# a consumer can see the package exercised. The development-only files
# are deliberately left out, being .gitmodules and .gitignore, which
# describe a submodule the published tree does not have, and .github,
# which builds this repository rather than the package.
for path in LICENSE readme.md phpunit.xml src tests examples; do
    [ -e "$path" ] || fail "expected '$path' in the checkout"
    cp -R "$path" "$out/"
done

# The OWID source sits under a path that names the Composer package it
# came from, so the boundary between our code and code we did not write
# is visible in the tree, the Apache-2.0 licence text sits beside exactly
# the files it covers, and the directory can be deleted in one step if
# the library is ever published to Packagist and required normally.
owid_out="$out/third-party/swan-community/owid"
mkdir -p "$owid_out"
cp -R owid-php/src "$owid_out/src"
cp owid-php/LICENSE "$owid_out/LICENSE"

cat > "$owid_out/NOTICE.md" <<NOTICE
# swan-community/owid

The files under \`src\` beside this notice are a copy of the OWID (Open
Web Id) library for PHP, taken unchanged from
$owid_url
at commit $owid_commit.

They are copied into published releases of
\`51degrees/fiftyone.pipeline.did\` because the library is not on
Packagist. Nothing in the copy has been edited, it keeps the
\`SwanCommunity\Owid\` namespace of the original, and it is not
maintained here, so any defect or change belongs upstream.

The copy is licensed under the Apache License, Version 2.0, whose text is
in the \`LICENSE\` file beside this notice and whose terms are repeated in
the header of every copied file. The rest of the package is licensed
under the European Union Public Licence v1.2, whose text is in the
\`LICENSE\` file at the root of the package.
NOTICE

php ci/rewrite-composer-json.php \
    composer.json \
    owid-php/composer.json \
    "$out/composer.json" \
    third-party/swan-community/owid/src

echo "assemble-package: wrote the package to $out"
echo "assemble-package: OWID copied from $owid_url at $owid_commit"
