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
 *    calls redeem with the 51Did, the encrypted result and the account's
 *    licence key, and receives the signature outcome, the true creator
 *    context verdict, when the verification happened (verifiedAt) and
 *    how long ago that was (secondsSinceVerified).
 *
 * A fresh challenge is issued per page load and bound through both
 * steps by the cloud. A production server would also remember the
 * value it issued and reject a redemption carrying any other, which
 * this demo keeps out of scope.
 *
 * What a run costs. Every call to the cloud is one use against the
 * subscription behind the resource key. A browser check makes two,
 * verify-full from the page and redeem from this server, so a
 * browser-based context check is two uses every time.
 *
 * Standard library only (PHP 8.1 or later), so it runs with PHP's
 * built-in server and does not need Composer's autoloader. Run from
 * this folder, then open http://localhost:5100/ in a browser.
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
$licence = getenv('_51DEGREES_LICENSE_KEY') ?: getenv('LICENSE_KEY') ?: '';

// The cloud API base including the /api/v4/ segment. This is the same
// variable the 51Degrees cloud request engine honours, so setting it
// once points every 51Degrees example at the same place. Normalised to
// end in exactly one slash so every URL is base plus a path, here and
// in the page, which receives the base through its __API__ placeholder.
// A host other than cloud.51degrees.com would be used to (a) use an on
// premise web server, or (b) use a privately hosted version of the
// 51Degrees cloud for performance reasons. This is the private hosting
// option of the cloud service. Both run the same service, so the demo
// works unchanged against either.
$base = rtrim(
    getenv('FOD_CLOUD_API_URL') ?: 'https://cloud.51degrees.com/api/v4/',
    '/'
) . '/';

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

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
    // The server-side step. The licence key is added here and only
    // here, so the browser never sees it, and it is sent empty when the
    // account holds no licence keys.
    $params = http_build_query([
        '51did' => $_GET['51did'] ?? '',
        'result' => $_GET['result'] ?? '',
        'challenge' => $_GET['challenge'] ?? '',
        'license' => $licence,
    ]);
    $context = stream_context_create(['http' => [
        'header' => "User-Agent: 51did-demo-php\r\n",
        // Read the body of an error response too, so the page is shown
        // what the service said rather than a bare warning.
        'ignore_errors' => true,
    ]]);
    $url = "{$base}id/redeem/{$resource}?{$params}";
    // The @ keeps a connection failure from printing a warning into the
    // response, since the false return is reported below.
    $body = @file_get_contents($url, false, $context);
    // The upstream status code, content type and body are relayed
    // exactly as received, so a 404 from a service that does not offer
    // this endpoint yet, or an error object from one that does, reaches
    // the page as the failure it is rather than as an unexpected token.
    // PHP sets $http_response_header with the response headers, the
    // status line first.
    $status = 502;
    $type = 'text/plain';
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $match)) {
            $status = (int) $match[1];
        } elseif (stripos($header, 'Content-Type:') === 0) {
            $type = trim(substr($header, strlen('Content-Type:')));
        }
    }
    if ($body === false) {
        $body = "redeem failed: no response from {$url}";
    }
    http_response_code($status);
    // Without this PHP appends its default charset to a text content
    // type, which would alter what the service sent.
    ini_set('default_charset', '');
    header('Content-Type: ' . $type);
    echo $body;
    return;
}

if ($path === '/') {
    header('Content-Type: text/html; charset=utf-8');
    echo strtr(file_get_contents(__DIR__ . '/page.html'), [
        '__RESOURCE__' => $resource,
        '__CHALLENGE__' => bin2hex(random_bytes(16)),
        '__API__' => $base,
    ]);
    return;
}

http_response_code(404);
