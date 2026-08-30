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

/**
 * 51Did creator context demo server.
 *
 * Every 51Did the cloud issues carries a creator context, which binds
 * the identifier to the browser and connection it was created on. This
 * demo runs the flow the way production does, in three steps.
 *
 * 1. Create. The browser calls the json endpoint, which issues a 51Did
 *    for the browser's own connection.
 * 2. Verify. The browser calls verify-full, so the cloud observes the
 *    browser's live connection. Everything the cloud concluded, the
 *    signature outcome and the creator context verdict, comes back only
 *    as an encrypted result that the browser cannot read or forge.
 * 3. Redeem. The page hands the encrypted result to this server, which
 *    parses the 51Did, checks its signature offline against the
 *    published keys, then calls redeem through the DidClient with the
 *    51Did, the encrypted result and the account's licence key, and
 *    receives the signature outcome, the true creator context verdict,
 *    when the verification happened (verifiedAt) and how long ago that
 *    was (secondsSinceVerified).
 *
 * A fresh challenge is issued per page load and bound through both
 * steps by the cloud. A production server would also remember the
 * value it issued and reject a redemption carrying any other, which
 * this demo keeps out of scope.
 *
 * What a run costs. Every call to the cloud is one use against the
 * subscription behind the resource key. A browser check makes two,
 * verify-full from the page and redeem from this server, so a
 * browser-based context check is two uses every time. The offline
 * signature check fetches the public key list once per DidClient
 * instance, which is one more use each time the list is fetched. Under
 * PHP's built-in server every request starts afresh, so this demo
 * fetches the list on every redemption, whereas an application server
 * keeping one client alive fetches it once a day.
 *
 * Uses the 51Did package from this repository (PHP 8.1 or later), so run
 * `composer install` at the repository root first, then from this folder
 * start the built-in server and open http://localhost:5100/ in a browser.
 *
 *   php -S localhost:5100 server.php
 *
 * The port is the php -S argument. Under the built-in server getenv()
 * sees the environment the php -S process was started with.
 *
 * Environment variables.
 *
 *   _51DEGREES_RESOURCE_KEY  required, read before the legacy
 *                            RESOURCE_KEY
 *   _51DEGREES_LICENSE_KEY   optional, read before the legacy
 *                            LICENSE_KEY
 *   FOD_CLOUD_API_URL        optional, the cloud API base including
 *                            the /api/v4/ segment, defaulting to
 *                            https://cloud.51degrees.com/api/v4/
 */

use fiftyone\pipeline\did\CloudException;
use fiftyone\pipeline\did\DidClient;
use fiftyone\pipeline\did\FodId;
use fiftyone\pipeline\did\NotSupportedException;

// The package from this repository, through the repository's own
// autoloader, so the demo exercises the checked-out code.
$autoload = __DIR__ . '/../../vendor/autoload.php';
if (!is_file($autoload)) {
    http_response_code(500);
    exit('Run composer install at the repository root first.');
}
require $autoload;

// The resource key is public by nature and names the account. The
// aligned name is read first, then the legacy one.
$resource = getenv('_51DEGREES_RESOURCE_KEY') ?: getenv('RESOURCE_KEY');
if (!$resource) {
    http_response_code(500);
    exit('Set _51DEGREES_RESOURCE_KEY (or the legacy RESOURCE_KEY) to '
        . 'the resource key of the page.');
}

// Only an account that holds licence keys needs one to redeem, because
// the licence key is what keeps redemption to the acting party's own
// servers. An account holding none has nothing to check against, so the
// demo runs without it, and where the account does hold some the
// redemption reports the context unreadable.
$licence = getenv('_51DEGREES_LICENSE_KEY') ?: getenv('LICENSE_KEY') ?: null;

// One client for the server. The endpoint argument is left null so the
// client reads FOD_CLOUD_API_URL itself, the same variable the 51Degrees
// cloud request engine honours, and falls back to the public cloud. A
// host other than cloud.51degrees.com would be used to (a) use an on
// premise web server, or (b) use a privately hosted version of the
// 51Degrees cloud for performance reasons. This is the private hosting
// option of the cloud service. Both run the same service, so the demo
// works unchanged against either. The page receives the same base
// through its __API__ placeholder.
$client = new DidClient($resource, $licence);

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

/**
 * Answers the page with a status and a JSON body.
 *
 * @param array<string, mixed> $body
 */
function answerJson(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body);
}

if ($path === '/examples-main.min.css') {
    // The design system stylesheet, vendored beside this server exactly
    // as the other 51Degrees web examples vendor it. Its source of truth
    // is pattern-library/source/sass in the 51Degrees/documentation
    // repository.
    header('Content-Type: text/css');
    readfile(__DIR__ . '/examples-main.min.css');
    exit;
}

if ($path === '/redeem') {
    // The server-side step, and the lines a developer copies into their
    // own server. The 51Did arrives from the page in the URL-safe
    // alphabet, which fromBase64 accepts. The licence key is added by the
    // client here and only here, so the browser never sees it.
    try {
        $fodId = FodId::fromBase64($_GET['51did'] ?? '');
    } catch (Throwable $error) {
        answerJson(400, ['errors' => [
            'The 51did is not a valid 51Did: ' . $error->getMessage(),
        ]]);
        return;
    }
    try {
        // The offline check against the published keys, which needs no
        // sealed result. A production server could refuse here before
        // spending a redemption on a forged envelope. The demo carries on
        // so the page can show both answers side by side.
        $serverSignature = $client->verifySignature($fodId)
            ? 'verified'
            : 'invalid';
        $redeemed = $client->redeem(
            $fodId,
            $_GET['result'] ?? '',
            $_GET['challenge'] ?? ''
        );
    } catch (NotSupportedException $error) {
        // The host answering does not offer the creator context at all,
        // which the page reports as "not supported by this host".
        http_response_code(404);
        header('Content-Type: text/plain');
        echo 'The service at ' . $client->getEndpoint()
            . ' does not support the creator context.';
        return;
    } catch (InvalidArgumentException $error) {
        // The cloud refused the 51Did, and its message says why.
        answerJson(400, ['errors' => [$error->getMessage()]]);
        return;
    } catch (CloudException $error) {
        // Another status from the service, relayed with what it said.
        $status = $error->getStatusCode();
        answerJson($status >= 100 ? $status : 502, [
            'error' => $error->getMessage(),
        ]);
        return;
    } catch (Throwable $error) {
        // The cloud could not be reached, or a key could not be read.
        answerJson(502, ['error' => 'redeem failed: ' . $error->getMessage()]);
        return;
    }
    // The cloud's own shape (signature, context, factors when present,
    // verifiedAt, secondsSinceVerified) plus the offline check, which the
    // page shows when it knows the field and ignores otherwise.
    $answer = $redeemed->toArray();
    $answer['serverSignature'] = $serverSignature;
    answerJson($redeemed->statusCode, $answer);
    return;
}

if ($path === '/') {
    header('Content-Type: text/html; charset=utf-8');
    echo strtr(file_get_contents(__DIR__ . '/page.html'), [
        '__RESOURCE__' => $resource,
        '__CHALLENGE__' => bin2hex(random_bytes(16)),
        '__API__' => $client->getEndpoint(),
    ]);
    return;
}

http_response_code(404);
