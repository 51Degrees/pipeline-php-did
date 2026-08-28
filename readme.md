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

On an identifier carrying a creator context the four LicenseId bytes hold an
encrypted value that only 51Degrees can turn back into a licence identifier,
so `getLicenseId()` is the field's raw value and identifies nothing outside
51Degrees. Such an identifier also carries a context section after the value,
which the reader keeps in the payload and does not interpret.

## Requirements & OWID dependency

PHP **>= 8.1** (the OWID library requires it; 7.4 is end-of-life). `FodId`
builds on the OWID envelope library
([SWAN-community/owid-php](https://github.com/SWAN-community/owid-php), package
`swan-community/owid`), consumed via the `51Degrees/owid-php` fork as a git
submodule and a Composer `path` repository. Switch to Packagist once owid-php is
published upstream. `Owid` is `final`, so `FodId` **composes** it rather than
subclassing.

## Install / build

```bash
git submodule update --init   # fetches owid-php into ./owid-php
composer install
```

## Usage

```php
use fiftyone\pipeline\did\FodId;
use fiftyone\pipeline\did\IdType;

// Either base64 alphabet is accepted, standard as the cloud issues it or
// URL-safe as a page puts it in a link, with or without padding, and
// surrounding whitespace such as a trailing newline is ignored.
$fodId = FodId::fromBase64($base64FromCloudService);

$flags     = $fodId->getFlags();
$type      = $fodId->getType();        // IdType::Probabilistic / Random / HashedEmail
$licenseId = $fodId->getLicenseId();
$value     = $fodId->getHash();        // SHA-256 or GUID bytes, see type

// Delegated OWID-level fields and operations.
$domain   = $fodId->getDomain();
$verified = $fodId->verify($publicKeyPem);
$base64   = $fodId->asBase64();
$urlSafe  = $fodId->asBase64Url();    // for a URL, no padding
$minutes  = $fodId->getDateMinutes(); // minutes since 2020-01-01T00:00:00Z
```

## Comparing two 51Dids

```php
$a = FodId::fromBase64($idprobglobalA);
$b = FodId::fromBase64($idprobglobalB);

// The envelope (date, signature, base64) differs across reissues.
// The value inside the payload is stable - this is what you compare:
$sameValue = $a->getHash() === $b->getHash();
```

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

// 1. Parse. The identifier arrives from a page in the URL-safe alphabet.
$fodId = FodId::fromBase64($fromThePage);

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

The verify-context and verify-full endpoints are browser calls rather
than client methods, because the context describes the browser's own
connection, and creation is the cloud `json` endpoint for the same
reason. The demo below shows both.

## Non-goals

- **No signature verification on construction.** Call `verify($publicKeyPem)`
  or `DidClient::verifySignature()` when needed.
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

$fodId = FodId::fromBase64($_GET['51did'] ?? '');
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

The branch answers a `NotSupportedException` with a 404 and a text body,
which the page reports as not supported by this host, an
`InvalidArgumentException` with a 400 and the cloud's `errors`, and an
unreachable cloud with a 502 and `{ "error": ... }`. A production server
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
