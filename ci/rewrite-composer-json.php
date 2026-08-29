<?php

/**
 * Write the composer.json of the published package.
 *
 * The composer.json kept on main points Composer at the owid-php git
 * submodule through a "path" repository. A consumer never sees that
 * repository, because Composer only reads the repositories of the root
 * project, so the published file has to stand on its own. This script
 * takes the development file and produces the published one by
 *
 *   - dropping the "repositories" block,
 *   - dropping the requirement on swan-community/owid, which is not on
 *     Packagist, and carrying across the PHP extensions that library
 *     needs so the consumer still gets them checked,
 *   - autoloading the copied OWID source under its own namespace, and
 *   - stating both licences, because the published archive carries the
 *     Apache-2.0 files as well as our own EUPL-1.2 ones.
 *
 * Usage:
 *
 *   php ci/rewrite-composer-json.php <source> <owid source> <output>
 *       <owid autoload path>
 */

declare(strict_types=1);

const OWID_PACKAGE = 'swan-community/owid';
const OWID_NAMESPACE = 'SwanCommunity\\Owid\\';
const PACKAGE_LICENCE = 'EUPL-1.2';
const OWID_LICENCE = 'Apache-2.0';

function fail(string $message): never
{
    fwrite(STDERR, "rewrite-composer-json: $message\n");
    exit(1);
}

function readJson(string $path): array
{
    $text = file_get_contents($path);
    if ($text === false) {
        fail("cannot read $path");
    }
    $data = json_decode($text, true);
    if (!is_array($data)) {
        fail("cannot parse $path as JSON");
    }
    return $data;
}

if ($argc !== 5) {
    fail(
        'usage: php ci/rewrite-composer-json.php <source> <owid source> '
        . '<output> <owid autoload path>'
    );
}
[, $sourcePath, $owidPath, $outputPath, $owidAutoloadPath] = $argv;

$package = readJson($sourcePath);
$owid = readJson($owidPath);

// The path repository is the development arrangement and has no meaning
// in a published package.
unset($package['repositories']);

$require = $package['require'] ?? [];
if (!array_key_exists(OWID_PACKAGE, $require)) {
    fail(
        'the source composer.json no longer requires ' . OWID_PACKAGE
        . ', so this script is out of date with the package'
    );
}
unset($require[OWID_PACKAGE]);

// The OWID source is copied in, so its own requirements become ours.
foreach ($owid['require'] ?? [] as $name => $constraint) {
    if ($name === 'php') {
        if (($require['php'] ?? null) !== $constraint) {
            fail(
                'the package requires PHP ' . ($require['php'] ?? 'nothing')
                . ' and the OWID library requires PHP ' . $constraint
                . ', so a person has to decide which applies'
            );
        }
        continue;
    }
    if (!array_key_exists($name, $require)) {
        $require[$name] = $constraint;
    }
}
$package['require'] = $require;

// Composer reads a bare list of licences as a choice between them and an
// SPDX expression as a combination, and the published archive carries
// files under both, so state the combination.
if (($package['license'] ?? null) !== PACKAGE_LICENCE) {
    fail(
        'expected the package licence to be ' . PACKAGE_LICENCE
        . ', so this script is out of date with the package'
    );
}
$package['license'] = '(' . PACKAGE_LICENCE . ' AND ' . OWID_LICENCE . ')';

$autoload = $package['autoload']['psr-4'] ?? [];
$autoload[OWID_NAMESPACE] = rtrim($owidAutoloadPath, '/') . '/';
$package['autoload']['psr-4'] = $autoload;

$json = json_encode(
    $package,
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
);
if ($json === false) {
    fail('cannot encode the package as JSON');
}
if (file_put_contents($outputPath, $json . "\n") === false) {
    fail("cannot write $outputPath");
}

echo "rewrite-composer-json: wrote $outputPath\n";
