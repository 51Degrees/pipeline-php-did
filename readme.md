# 51Degrees Pipeline 51Did (PHP)

Strongly typed PHP reader for the 51Did (51Degrees Identifier) returned by the
51Degrees Cloud service, and a client for the cloud's 51Did endpoints so a
server never hand-writes HTTP or key handling. Mirrors the .NET `FiftyOne.Did`
package. Composer package `51degrees/fiftyone.pipeline.did`, namespace
`fiftyone\pipeline\did`.

## Terminology

- The **51Did** (51Degrees Identifier) is the identifier as a whole.
- The **envelope** is the data model that carries it: a signed OWID holding the
  version, domain, date, payload and signature. It changes byte-for-byte every
  time the cloud issues one.
- The **match key** is the stable, comparable part of the payload after the
  Flags and License Id, a 32-byte SHA-256 for Probabilistic and HashedEmail
  identifiers, or 16 GUID bytes for Random. Two 51Dids for the same inputs
  share the same match key even though their envelopes differ. The name
  follows the Model Terms for Marketing, which call that part of a 51Did the
  match key.

**Comparing two 51Dids means comparing their match keys, never their
envelopes.**

## Payload layout

| Offset | Length | Field      | Type                                            |
|-------:|-------:|------------|-------------------------------------------------|
|      0 |      1 | Flags      | uint8: bits 0-2 usage, bits 6-7 identifier type |
|      1 |      4 | LicenseId  | uint32 (little-endian)                          |
|      5 |  16/32 | Match key  | SHA-256 (Probabilistic, HashedEmail) or GUID (Random) |

| Bits 7-6 | `IdType`        | Match key length | Minimum payload |
|---------:|-----------------|-----------------:|----------------:|
|     `00` | `Probabilistic` |           32 |              37 |
|     `01` | `Random`        |           16 |              21 |
|     `10` | `HashedEmail`   |           32 |              37 |
|     `11` | `Reserved`      |    remainder |               5 |

Identifiers issued before the type tag existed have bits 6-7 zeroed and decode
as `Probabilistic`.

The minimum payload is the only length rule this package applies. There is
no upper bound here, because anything after the match key is a creator
context section whose lengths belong to the cloud, and an older reader has
to keep accepting an identifier a newer cloud issues.

On an identifier carrying a creator context the four LicenseId bytes hold an
encrypted value that only 51Degrees can turn back into a licence identifier,
so `getLicenseId()` is the field's raw value and identifies nothing outside
51Degrees. Such an identifier also carries a context section after the
match key, which the reader keeps in the payload and does not interpret.

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

// A value from outside may be anything at all, so reading answers rather
// than raising. Either base64 alphabet is accepted, standard as the cloud
// issues it or URL-safe as a page puts it in a link, with or without
// padding, and surrounding whitespace such as a trailing newline is
// ignored. A null, an empty string or an array is reported, not raised.
$result = FodId::tryFromBase64($_GET['51did'] ?? null);
if (!$result->ok) {
    // $result->status names the reason and is safe to log.
    return;
}
$fodId = $result->fodId;

$flags     = $fodId->getFlags();
$type      = $fodId->getType();        // IdType::Probabilistic / Random / HashedEmail
$licenseId = $fodId->getLicenseId();
$matchKey  = $fodId->getMatchKey();    // SHA-256 or GUID bytes, see type

// Delegated OWID-level fields and operations. Reading never verifies.
$domain   = $fodId->getDomain();
$verified = $fodId->verify($publicKeyPem);
$status   = $fodId->signatureStatus($publicKeyPem); // SignatureStatus
$base64   = $fodId->asBase64();
$urlSafe  = $fodId->asBase64Url();    // for a URL, no padding
$minutes  = $fodId->getDateMinutes(); // minutes since 2020-01-01T00:00:00Z
```

`FodId::fromBase64()`, `FodId::fromByteArray()`, `FodId::fromOwid()` and the
constructor remain and raise for the same inputs the `try` factories
report, so code written against them keeps working. `getHash()` remains as
a deprecated alias of `getMatchKey()` answering the same bytes, and will be
removed in a future release.

## Reading versus verifying

Reading a 51Did and verifying one are separate questions with separate
answers. Reading asks whether the bytes are a 51Did at all, and a successful
read says nothing about the signature. A parsed 51Did is not necessarily
genuine. Verifying asks whether the signature is genuine for a key, and only
makes sense once there is a 51Did to ask about.

### Reading

Every read through `tryFromBase64()`, `tryFromByteArray()` or
`tryFromOwid()` reports the same three facts in a `FodIdParseResult`.

1. `$result->ok`, whether the value was a 51Did.
2. `$result->fodId`, the `FodId` on success and `null` otherwise, never a
   half read one.
3. `$result->status`, `ParseStatus::Parsed` on success and the specific
   reason otherwise.

Reading is two steps and the status says which step failed. The OWID
library reads the envelope first, and when the envelope cannot be read the
result carries the library's own `SwanCommunity\Owid\ParseStatus` exactly
as reported, with nothing mapped down to a generic value. Only when the
envelope is sound does this package look inside the payload, and the two
things the payload can get wrong are this package's own
`FodIdParseStatus`.

| Status | From | Meaning |
| --- | --- | --- |
| `Parsed` | OWID | A 51Did in a sound envelope. Says nothing about the signature |
| `MissingInput` | OWID | Nothing was given, being null, an empty string or whitespace only |
| `InvalidInputType` | OWID | Not a string, for example the array PHP builds when a query parameter repeats with brackets |
| `InvalidBase64` | OWID | The text is not base64, so there are no bytes to read |
| `UnsupportedVersion` | OWID | The first byte names an envelope version the library does not know |
| `UnexpectedEnd` | OWID | The bytes stop part way through a field, before the payload length was read |
| `InvalidDomainEncoding` | OWID | The creator domain has no terminator within the length a domain name can hold |
| `ByteCountMismatch` | OWID | The declared payload length disagrees with the bytes present, whichever way they fall short |
| `AbsentNode` | OWID | The marker for an absent OWID, a single zero byte, which is well formed and is not an identifier |
| `PayloadTooShort` | this package | The payload holds fewer than the 5 header bytes, so the type cannot be read |
| `InvalidTypePayloadLength` | this package | The header names a type whose match key the payload is too short to hold, being 16 bytes after the header for Random and 32 for Probabilistic or HashedEmail |

Both enums are string backed with the cross language name of the status,
so `$result->status->value` can be logged or carried between services
whichever kind it is, and a status never carries the input that produced
it.

Every one of these is an expected outcome of reading external data rather
than a fault in the program, which is why the `try` factories report them.
The exceptional cases are the ones that remain exceptions. A key that
cannot be read, a cloud that cannot be reached, a key endpoint that answers
with an error, and a transport that answers in the wrong shape are all
faults in the operation rather than in the identifier, and `verify()` and
`DidClient` raise for them as they always have.

### Verifying

`verify($publicKeyPem)` answers `true` or `false` and raises an
`OwidException` when the key itself cannot be read. Where the difference
between a signature that does not match and a check that could not be made
changes what your code does, ask `signatureStatus($publicKeyPem)` instead,
which answers a `SwanCommunity\Owid\SignatureStatus`.
`SignatureStatus::SignatureInvalid` is the only answer that means the
identifier should be distrusted, and a key that cannot be read is
`SignatureStatus::InvalidKey`, so an operational fault is never reported as
a forgery. `DidClient::verifySignature()` fetches the published keys, and
when the keys cannot be fetched it raises rather than answering `false`,
for the same reason.

### Before and after

A caller who reached the OWID library through this package before this
release used its throwing factories or built an OWID directly. Both are
gone from the library, and the package now reads like this.

```php
// Before. The OWID was built or parsed directly and raised on bad input,
// and the exception text was the only account of what was wrong.
try {
    $fodId = FodId::fromOwid(Owid::fromBase64($value));
} catch (OwidException $e) {
    error_log('not a 51Did: ' . $e->getMessage());
}

// After. The read answers with a named reason and nothing is raised for
// data that merely fails to be a 51Did.
$result = FodId::tryFromBase64($value);
if (!$result->ok) {
    error_log('not a 51Did: ' . $result->status->value);
    return;
}
$fodId = $result->fodId;
```

`FodId::fromBase64($value)` still works and still raises `OwidException`
when the envelope cannot be read (the message now names the library's
status) and `InvalidArgumentException` when the envelope is sound and the
payload does not fit, so a catch block written against either keeps
working. An `Owid` reaches your code only from a successful read or from
the library's `Creator::create`, so `new Owid(...)` and `Owid::fromBase64()`
no longer exist to call.

## Comparing two 51Dids

```php
$a = FodId::fromBase64($idprobglobalA);
$b = FodId::fromBase64($idprobglobalB);

// The envelope (date, signature, base64) differs across reissues.
// The match key inside the payload is stable, so that is what you compare.
$sameMatchKey = $a->getMatchKey() === $b->getMatchKey();
```

Use `getMatchKey()` as the cache and dedup key. The same match key means
the same browser instance under the same usage policy on the same licence
key (for `idproblic`) or across all callers (for `idprobglobal`).

## Verifying on your server

`DidClient` handles every manipulation of a 51Did a server needs against
the cloud. Build one at start-up with the page's resource key, the
account's licence key (server side only, needed to redeem where the
account holds licence keys) and, optionally, the API base. When the base
is not given the client reads `FOD_CLOUD_API_URL`, the same variable the
cloud request engine honours, and falls back to
`https://cloud.51degrees.com/api/v4/`. A value with or without a trailing
slash is accepted. Credentials never travel in a URL. The key list and
verify calls carry the resource key in the route, and redeem is a POST
whose form body carries the resource key, the identifier, the sealed
result, the challenge and the licence key. A fourth constructor argument
takes an HTTP transport callable so tests can run without the network.

```php
use fiftyone\pipeline\did\ContextOutcome;
use fiftyone\pipeline\did\DidClient;
use fiftyone\pipeline\did\FodId;
use fiftyone\pipeline\did\NotSupportedException;

$client = new DidClient($resourceKey, $licenceKey);

// 1. Read. The identifier arrives from a page in the URL-safe alphabet,
//    and a value that is not a 51Did is an answer rather than an error.
$read = FodId::tryFromBase64($fromThePage);
if (!$read->ok) {
    return;   // $read->status says why
}
$fodId = $read->fodId;

// 2. Verify the signature offline. The client fetches the published
//    signing keys once, caches them for a day, and tries the key in force
//    when the identifier was created plus a neighbouring key where the
//    date sits close to a key boundary. Version 3 envelopes only.
$genuine = $client->verifySignature($fodId);
$key = $client->publicKeyFor($fodId);   // null when no key covers the date

// 3. Verify the signature through the cloud (one use, no licence key).
$valid = $client->verify($fodId);

// 4. Redeem a sealed creator context result the page relayed (one use).
try {
    $redeemed = $client->redeem($fodId, $sealedResult, $challenge);
    if ($redeemed->context === ContextOutcome::Verified) {
        // Presented from the browser and connection it was created on.
    }
    $redeemed->signature;            // SignatureOutcome
    $redeemed->factors;              // name => FactorOutcome, mismatch only
    $redeemed->verifiedAt;           // DateTimeImmutable or null
    $redeemed->secondsSinceVerified; // int or null
    $redeemed->statusCode;           // 200, or 503 for Unconfirmed
} catch (NotSupportedException $e) {
    // The host does not offer the creator context.
}
```

`redeem()` returns a `RedeemResult` for a 200 and for a 503 (context
`Unconfirmed`, so retry). It throws `InvalidArgumentException` with the
cloud's message when the 51Did was malformed (400),
`NotSupportedException` when the host does not offer the creator context
(404), `CloudException` carrying the status and body for any other
status, and `RuntimeException` when the cloud cannot be reached. A
`context` string the package does not know maps to
`ContextOutcome::Unreadable` and the raw value stays on `rawContext`.
Every cryptographic failure comes back as the one word `unreadable`, by
design, so the client does not try to distinguish them either.

`verify()` and `redeem()` also take the identifier as a string, in either
alphabet. The client reads the string with `FodId::tryFromBase64()` first
and refuses one that is not a 51Did with an `InvalidArgumentException`
naming the status, before any key fetch or request, so a malformed value
costs no use. A string that reads is sent exactly as given. Separately, and
before the read, the client refuses any string longer than 4096 characters
with the same exception type. That figure is client policy, deliberately
arbitrary and generous, chosen so that obviously hostile input is dropped
before it is even decoded, and it says nothing about how long a 51Did is or
may be. It is not a limit of the format and the reader applies no such
limit.

The verify-context and verify-full endpoints are browser calls rather
than client methods, because the context describes the browser's own
connection, and creation is the cloud `json` endpoint for the same
reason. The demo below shows both.

## Non-goals

- **No signature verification on reading.** A parsed 51Did is not
  necessarily genuine. Call `verify($publicKeyPem)`,
  `signatureStatus($publicKeyPem)` or `DidClient::verifySignature()` when
  needed.
- **No upper bound on the payload.** The type minimums in the table above
  are the only length rule. The 4096 character figure in `DidClient` is
  that client's own guard on what it will send and not a property of the
  format.
- **No creation of new 51Dids.** `FodId` is a parser and `DidClient`
  verifies and redeems; new 51Dids are issued by the 51Degrees cloud /
  on-premise hashing engines.

## Tests

```bash
composer install
vendor/bin/phpunit
```

The `Live` suite calls the cloud and is skipped unless
`_51DEGREES_RESOURCE_KEY` (or the legacy `RESOURCE_KEY`) is set, with
`_51DEGREES_LICENSE_KEY` and `FOD_CLOUD_API_URL` read as the demo reads
them. Each live test costs uses against the subscription behind the key.

## Creator context demo

Every 51Did the 51Degrees cloud issues carries a creator context, which
binds the identifier to the browser and connection it was created on.
The demo under `examples/creator-context-web/` shows the flow against the
cloud from a real browser, which is the only place the check makes sense,
since a program verifying its own connection checks itself against
itself. The demo's server uses `DidClient` from this package, so run
`composer install` at the repository root first.

### What the demo shows

The flow has three steps.

1. **Create** a 51Did by calling the `json` endpoint, which issues an
   identifier for the calling connection.
2. **Verify** it with `verify-full`, which returns everything the cloud
   concluded, the signature outcome and the creator context verdict, only
   as an encrypted `result` that the caller cannot read or forge.
3. **Redeem** the encrypted result with `redeem`, presenting the 51Did,
   the encrypted result and the account's licence key, and receive the
   signature outcome, the true creator context verdict, when the
   verification happened (`verifiedAt`) and how long ago that was
   (`secondsSinceVerified`).

In production step 2 runs in the visitor's browser (the page relays the
encrypted result to your server) and step 3 runs on your server, which is
the party holding the licence key. The demo passes a single-use
`challenge`, binding the encrypted result to one transaction.

A verdict of `nocontext` is a normal outcome rather than an error,
because a self-hosted service may be configured not to emit the creator
context, so an identifier it issued has none to check. A 404 from
`verify-full` or `redeem` means the host answering does not offer the
creator context at all, which is a service without the feature rather
than a failed check, so the page shows `not supported by this host` and
the sentence `The service at <api base> does not support the creator
context. Point the demo at a service that does.` Only a transport
failure, another status outside the 2xx range, a body that is not JSON or
an `errors` answer from the service is an error. The server relays the
service's status and body to the page, which shows the failure naming the
status and the start of the body.

`examples/creator-context-web/` is a small demo web app, `server.php`
serving `page.html`, that runs the flow the way production does. The
browser creates the 51Did and calls `verify-full`, so the cloud observes
the browser's live connection, then the page hands the encrypted result
to its own server, which redeems it with the licence key. A fresh
challenge is issued per page load and bound through both steps by the
cloud. A production server would also remember the value it issued and
reject a redemption carrying any other, which the demo keeps out of
scope. The creation call requests every 51Did identifier in one request
and the page shows all six in a table, the probabilistic pair
(`IdProbGlobal` and `IdProbLic`) derived from the connection, the
deterministic hashed-email pair (`IdHemGlobal` and `IdHemLic`) derived
from the `id.email` evidence (the demo sends `demo@51did.example`), and
the random pair (`IdRandGlobal` and `IdRandLic`). Global identifiers are
shared across customers, licensed ones are scoped to the licence key.

### The server-side step, which you copy into your own server

The one part of the demo that belongs on your server is the redeem call,
because it adds the licence key the browser never sees. The `/redeem`
branch of `examples/creator-context-web/server.php` is that call, and
these are its essential lines. The 51Did, the encrypted result and the
challenge arrive from the page, the licence key is the client's, and the
answer goes back to the page in the cloud's own shape with one extra
field, `serverSignature`, from the offline signature check.

```php
$client = new DidClient($resource, $licence);   // once, at start-up

$read = FodId::tryFromBase64($_GET['51did'] ?? null);
if (!$read->ok) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['errors' => [
        'The 51did is not a valid 51Did (' . $read->status->value . ').',
    ]]);
    return;
}
$fodId = $read->fodId;
$serverSignature = $client->verifySignature($fodId) ? 'verified' : 'invalid';
$redeemed = $client->redeem(
    $fodId,
    $_GET['result'] ?? '',
    $_GET['challenge'] ?? ''
);
$answer = $redeemed->toArray();
$answer['serverSignature'] = $serverSignature;
http_response_code($redeemed->statusCode);
header('Content-Type: application/json');
echo json_encode($answer);
```

The branch answers a value that does not read as a 51Did with a 400 naming
the status, a `NotSupportedException` with a 404 and a text body, which the
page reports as not supported by this host, an `InvalidArgumentException`
with a 400 and the cloud's `errors`, and an unreachable cloud with a 502
and `{ "error": ... }`. A production server
would also remember the challenge it issued and reject a redemption
carrying any other.

### Environment variables

| Variable | Meaning |
| --- | --- |
| `_51DEGREES_RESOURCE_KEY` | Required. The resource key of your account, public by nature. The legacy `RESOURCE_KEY` is read when the aligned name is not set |
| `_51DEGREES_LICENSE_KEY` | Optional. A licence key of the same account, server side only. The legacy `LICENSE_KEY` is read when the aligned name is not set. Only an account that holds licence keys needs one to redeem, so an account holding none runs without it |
| `FOD_CLOUD_API_URL` | Optional. The cloud API base including the `/api/v4/` segment, defaulting to `https://cloud.51degrees.com/api/v4/`. This is the same variable the cloud request engine honours. A host other than `cloud.51degrees.com` would be used to (a) use an on premise web server, or (b) use a privately hosted version of the 51Degrees cloud for performance reasons. This is the private hosting option of the cloud service. Both run the same service, so the demo works unchanged against either |

### How to run

Run `composer install` at the repository root once, then from the
`examples/creator-context-web` folder start the built-in server and open
`http://localhost:5100/` in a browser. The port is the `php -S` argument.

```bash
php -S localhost:5100 server.php
```

To demonstrate across two devices, serve on an address both can reach and
open the copied link on the second device.

### What a run costs

Every call the demo makes to the cloud is one use against the
subscription behind the resource key. Checking a 51Did from the browser
makes two, verify-full from the page and redeem from the server, so a
browser-based context check is two uses every time. Checking only the
signature with `verify` is one use. The offline signature check in the
demo's `/redeem` fetches the public key list, one more use each time, and
under PHP's built-in server that is every redemption because each request
starts afresh, whereas an application server keeping one `DidClient`
alive fetches the list once a day.

### The copy-and-paste proof

Once the 51Did has fully validated, the page shows a **copy-and-paste
section** with a link carrying the same 51Did, and an explanation of what
will happen next. Open that link in a **different browser** and the same
page loads with the same identifier. The signature still verifies and the
identifier unpacks, because it is genuine, but the creator context does
**not** validate, because the context binds the identifier to the browser
and connection it was created on. That visible failure is the
demonstration that matters, a copied or stolen identifier caught at
presentation with nothing stored server side. Opening the link in the
same browser is not the demonstration, since the same browser presents
the same context and may still verify.

### Stylesheet

The `examples-main.min.css` vendored beside `page.html` is the 51Degrees
examples design system build and is refreshed by common-ci's
`update-example-assets` step.
