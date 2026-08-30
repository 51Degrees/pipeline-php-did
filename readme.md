# 51Degrees Pipeline 51Did (PHP)

Strongly typed PHP reader for the 51Did (51Degrees Identifier) returned by the
51Degrees Cloud service. Mirrors the .NET `FiftyOne.Did` package. Composer
package `51degrees/fiftyone.pipeline.did`, namespace `fiftyone\pipeline\did`.

## Terminology

- The **51Did** (51Degrees Identifier) is the identifier as a whole.
- The **envelope** is the data model that carries it: a signed OWID holding the
  version, domain, date, payload and signature. It changes byte-for-byte every
  time the cloud issues one.
- The **value** is the stable, comparable part of the payload after the Flags
  and License Id: a 32-byte SHA-256 for Probabilistic and HashedEmail
  identifiers, or 16 GUID bytes for Random.

**Comparing two 51Dids means comparing their values, never their envelopes.**

## Payload layout

| Offset | Length | Field      | Type                                            |
|-------:|-------:|------------|-------------------------------------------------|
|      0 |      1 | Flags      | uint8: bits 0-2 usage, bits 6-7 identifier type |
|      1 |      4 | LicenseId  | uint32 (little-endian)                          |
|      5 |  16/32 | Value      | SHA-256 (Probabilistic, HashedEmail) or GUID (Random) |

| Bits 7-6 | `IdType`        | Value length | Minimum payload |
|---------:|-----------------|-------------:|----------------:|
|     `00` | `Probabilistic` |           32 |              37 |
|     `01` | `Random`        |           16 |              21 |
|     `10` | `HashedEmail`   |           32 |              37 |
|     `11` | `Reserved`      |    remainder |               5 |

Identifiers issued before the type tag existed have bits 6-7 zeroed and decode
as `Probabilistic`.

## Requirements & OWID dependency

PHP **>= 8.1**, because the OWID library requires it and 7.4 is end of life.
`FodId` builds on the OWID envelope library
([SWAN-community/owid-php](https://github.com/SWAN-community/owid-php), package
`swan-community/owid`), taken from the `51Degrees/owid-php` fork. `Owid` is
`final`, so `FodId` **composes** it rather than subclassing.

That library is not on Packagist, so it reaches you one of two ways.

- **Installing the package.** A published release carries a copy of the OWID
  source under `third-party/swan-community/owid`, unchanged, under its own
  Apache-2.0 licence and autoloaded under its `SwanCommunity\Owid` namespace,
  so there is nothing extra to install and no custom repository to configure.
- **Working in this repository.** main keeps the library as the `owid-php` git
  submodule and consumes it through a Composer `path` repository, because the
  library is maintained upstream and not here.

[How a release is assembled](https://github.com/51Degrees/pipeline-php-did/blob/main/ci/README.md)
covers how the published tree is built and why the two arrangements
differ.

## Install

```bash
composer require 51degrees/fiftyone.pipeline.did
```

## Build from a checkout

```bash
git submodule update --init   # fetches owid-php into ./owid-php
composer install
```

## Usage

```php
use fiftyone\pipeline\did\FodId;
use fiftyone\pipeline\did\IdType;

$fodId = FodId::fromBase64($base64FromCloudService);

$flags     = $fodId->getFlags();
$type      = $fodId->getType();        // IdType::Probabilistic / Random / HashedEmail
$licenseId = $fodId->getLicenseId();
$value     = $fodId->getHash();        // SHA-256 or GUID bytes, see type

// Delegated OWID-level fields and operations.
$domain   = $fodId->getDomain();
$verified = $fodId->verify($publicKeyPem);
$base64   = $fodId->asBase64();
```

## Comparing two 51Dids

```php
$a = FodId::fromBase64($idprobglobalA);
$b = FodId::fromBase64($idprobglobalB);

// The envelope (date, signature, base64) differs across reissues.
// The value inside the payload is stable - this is what you compare:
$sameValue = $a->getHash() === $b->getHash();
```

## Non-goals

- **No signature verification on construction.** Call `verify($publicKeyPem)`
  when needed.
- **No creation of new 51Dids.** This is a parser; new 51Dids are issued by the
  51Degrees cloud / on-premise hashing engines.

## Tests

```bash
composer install
vendor/bin/phpunit
```
