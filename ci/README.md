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

## Setting up, once, by a person

Two things have to be done once, in this order, and neither can be done
from this repository. Do both before anyone tags a real release.

### 1. Put the package on Packagist

Sign in to Packagist with the 51Degrees account first. A personal
account publishes the package under the wrong owner and it cannot be
moved afterwards without asking Packagist.

1. Go to https://packagist.org/packages/submit
2. Paste https://github.com/51Degrees/pipeline-php-did into the
   repository URL box, press Check, then Submit.
3. Submitting also asks GitHub to install the Packagist hook on the
   repository, and that hook is what makes later tags appear on
   Packagist on their own. There is nothing else to set up for it.

Check afterwards that

- https://packagist.org/packages/51degrees/fiftyone.pipeline.did loads
  and names the 51Degrees account as the maintainer,
- the repository Settings, then Webhooks, lists a Packagist hook with a
  green tick against its last delivery, and
- the package page says there are no released versions, which is right
  at this point because no version tag exists yet.

### 2. Run the workflow as a dry run

The Publish workflow has never run on GitHub, because running it for
real publishes. The dry run is its first execution, so read it as a test
of the workflow as much as of the package.

1. On GitHub open Actions, choose Publish in the list on the left, then
   press Run workflow.
2. Leave the branch as main, which is where releases are cut from. Put
   the version you mean to release first, for example 1.0.0, in the
   version box. Tick dryrun.
3. Press Run workflow.

A good result looks like this.

- Every step green.
- "Check the package the way a consumer sees it" ends with the unit
  tests passing and the example printing `Verifies  : true`.
- "Check that the published tag archives with the OWID source" prints
  the file list of the archive, which includes
  `third-party/swan-community/owid/src/Owid.php`.
- "Push the published tag" is skipped and no new tag appears in the
  repository.
- An artifact named `package-<version>` is attached to the run.

Download that artifact and check inside it before anyone tags for real.

- `composer.json` has no `repositories` block and no requirement on
  `swan-community/owid`.
- `composer.json` autoloads `SwanCommunity\Owid\` from
  `third-party/swan-community/owid/src/`, and states the licence as
  `EUPL-1.2`.
- `third-party/swan-community/owid/src` holds the seven OWID PHP files,
  with `LICENSE` and `NOTICE.md` beside them, and `NOTICE.md` names the
  upstream repository and the commit the copy came from.
- `src`, `tests`, `examples`, `readme.md`, `phpunit.xml` and the root
  `LICENSE` are all there, and there is no `owid-php` directory.

Only when both of those are right, tag a real release.

```bash
git tag release/1.0.0
git push origin release/1.0.0
```

## What differs from the other 51Degrees PHP packages

`pipeline-php-core` publishes through the shared `common-ci` workflows,
which decide the next version number, run the whole nightly pipeline and
tag the head of the branch. Tagging the head of the branch is exactly
what cannot work here, because the head of main has no OWID source in
it. This workflow is therefore self-contained and driven by a tag. If
this repository is onboarded to `common-ci` later, the assembly belongs
in `ci/publish-package.ps1`, which runs before the tag is written.
