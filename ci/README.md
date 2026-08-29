# Publishing this package

## Why the published tree is not the tree on main

The OWID envelope library is not on Packagist, so main takes it from the
`owid-php` git submodule through a Composer `path` repository. That is
right for development and cannot reach a consumer, for two reasons.

1. Packagist serves GitHub's archive of the tag, and `git archive`
   writes a submodule as an empty directory, so a consumer installing a
   tag of main would get `owid-php/` with nothing in it.
2. Composer reads the `repositories` block of the root project only, so
   the `path` repository is ignored in a package a consumer requires and
   `swan-community/owid` cannot be resolved at all.

The publish workflow therefore assembles the tree it publishes. It
copies the OWID source into `third-party/swan-community/owid/src`,
carries the Apache-2.0 licence text and a notice recording the commit
the copy came from, and writes a `composer.json` with no `path`
repository, no requirement on `swan-community/owid`, the PHP extensions
that library needs, and a second autoload entry for its namespace. The
copied files are not edited and keep their `SwanCommunity\Owid`
namespace, so nothing has to be maintained in the copy.

The OWID source therefore exists only in published tags and never on
main, which is what allows the library to move upstream later without
this repository having to give it up first.

## Releasing

Push a source tag from the commit to release.

```bash
git tag release/1.0.0
git push origin release/1.0.0
```

The workflow assembles the package, checks it the way a consumer sees it
(`composer validate --strict`, `composer install --no-dev`, the example
that builds and parses a 51Did, then the unit tests), commits the
assembled tree with the source commit as its parent, and pushes the tag
`1.0.0`. Bare version tags match the other 51Degrees PHP packages, and
Packagist ignores the `release/` tag because it is not a version number.

To rehearse without publishing, run the Publish workflow by hand with a
version and `dryrun` ticked. Everything runs and nothing is pushed, and
the assembled package is attached to the run as an artifact.

To rehearse locally, from a checkout with the submodule initialised:

```bash
git submodule update --init
ci/assemble-package.sh /tmp/package
cd /tmp/package
composer validate --strict
composer install --no-dev
php examples/fodid_example.php
```

## Still to be done once, by a person

The package has to be submitted to Packagist under the 51Degrees account
at https://packagist.org/packages/submit, giving the repository URL
https://github.com/51Degrees/pipeline-php-did. Submitting also asks
Packagist to install its GitHub hook, which is what makes later tags
appear without anyone doing anything. Nothing in this repository can do
that step, because it needs the account.

## What differs from the other 51Degrees PHP packages

`pipeline-php-core` publishes through the shared `common-ci` workflows,
which decide the next version number, run the whole nightly pipeline and
tag the head of the branch. Tagging the head of the branch is exactly
what cannot work here, because the head of main has no OWID source in
it. This workflow is therefore self-contained and driven by a tag. If
this repository is onboarded to `common-ci` later, the assembly belongs
in `ci/publish-package.ps1`, which runs before the tag is written.
