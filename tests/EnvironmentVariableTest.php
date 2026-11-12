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

namespace fiftyone\pipeline\did\tests;

use PHPUnit\Framework\TestCase;

/**
 * A variable is read by its name first and, when that is not set or is
 * empty, by the deprecated name it replaced, whose use is reported once.
 * The example server reads its keys the same way.
 */
class EnvironmentVariableTest extends TestCase
{
    /** @var array<string, array{0: string|false, 1: mixed}> */
    private $previous = [];

    protected function tearDown(): void
    {
        foreach ($this->previous as $name => $was) {
            putenv($was[0] === false ? $name : $name . '=' . $was[0]);
            if ($was[1] === null) {
                unset($_ENV[$name]);
            } else {
                $_ENV[$name] = $was[1];
            }
        }
        $this->previous = [];
    }

    public function testNameIsReadBeforeTheDeprecatedName(): void
    {
        $this->set('_51DEGREES_TEST_BOTH', 'new');
        $this->set('OLD_TEST_BOTH', 'old');

        $logged = $this->logged(function (): void {
            $this->assertSame(
                'new',
                EnvironmentVariable::read('_51DEGREES_TEST_BOTH', 'OLD_TEST_BOTH')
            );
        });
        $this->assertSame([], $logged);
    }

    public function testDeprecatedNameIsReadWhenTheNameIsNotSet(): void
    {
        $this->set('_51DEGREES_TEST_UNSET', null);
        $this->set('OLD_TEST_UNSET', 'old');

        $this->logged(function (): void {
            $this->assertSame(
                'old',
                EnvironmentVariable::read('_51DEGREES_TEST_UNSET', 'OLD_TEST_UNSET')
            );
        });
    }

    public function testDeprecatedNameIsReadWhenTheNameIsEmpty(): void
    {
        $this->set('_51DEGREES_TEST_EMPTY', '');
        $this->set('OLD_TEST_EMPTY', 'old');

        $this->logged(function (): void {
            $this->assertSame(
                'old',
                EnvironmentVariable::read('_51DEGREES_TEST_EMPTY', 'OLD_TEST_EMPTY')
            );
        });
    }

    public function testNeitherNameSetGivesAnEmptyString(): void
    {
        $this->set('_51DEGREES_TEST_NEITHER', null);
        $this->set('OLD_TEST_NEITHER', null);

        $logged = $this->logged(function (): void {
            $this->assertSame(
                '',
                EnvironmentVariable::read('_51DEGREES_TEST_NEITHER', 'OLD_TEST_NEITHER')
            );
        });
        $this->assertSame([], $logged);
    }

    public function testPlaceholderCountsAsNotSet(): void
    {
        $this->set('_51DEGREES_TEST_PLACEHOLDER', '!!NOT_SET!!');
        $this->set('OLD_TEST_PLACEHOLDER', 'old');

        $this->logged(function (): void {
            $this->assertSame('old', EnvironmentVariable::read(
                '_51DEGREES_TEST_PLACEHOLDER',
                'OLD_TEST_PLACEHOLDER',
                '!!NOT_SET!!'
            ));
        });

        $this->set('OLD_TEST_PLACEHOLDER', '!!NOT_SET!!');
        $this->assertSame('', EnvironmentVariable::read(
            '_51DEGREES_TEST_PLACEHOLDER',
            'OLD_TEST_PLACEHOLDER',
            '!!NOT_SET!!'
        ));
    }

    public function testDeprecatedNameInUseIsReportedOnce(): void
    {
        $this->set('_51DEGREES_TEST_ONCE', null);
        $this->set('OLD_TEST_ONCE', 'old');

        $logged = $this->logged(function (): void {
            EnvironmentVariable::read('_51DEGREES_TEST_ONCE', 'OLD_TEST_ONCE');
            EnvironmentVariable::read('_51DEGREES_TEST_ONCE', 'OLD_TEST_ONCE');
        });

        $this->assertCount(1, $logged);
        $this->assertStringContainsString('OLD_TEST_ONCE', $logged[0]);
        $this->assertStringContainsString('deprecated', $logged[0]);
        $this->assertStringContainsString('_51DEGREES_TEST_ONCE', $logged[0]);
    }

    public function testExampleServerReadsItsKeysFromTheirDeprecatedNames(): void
    {
        $lines = $this->serverLog([
            'RESOURCE_KEY' => 'resource-from-the-old-name',
            'LICENSE_KEY' => 'licence-from-the-old-name',
        ]);

        $this->assertCount(2, $lines);
        $this->assertStringContainsString(
            'RESOURCE_KEY, which is deprecated. _51DEGREES_RESOURCE_KEY replaces it',
            $lines[0]
        );
        $this->assertStringContainsString(
            'LICENSE_KEY, which is deprecated. _51DEGREES_LICENSE_KEY replaces it',
            $lines[1]
        );
    }

    public function testExampleServerReadsTheNamesFirst(): void
    {
        $lines = $this->serverLog([
            '_51DEGREES_RESOURCE_KEY' => 'resource-from-the-new-name',
            '_51DEGREES_LICENSE_KEY' => 'licence-from-the-new-name',
            'RESOURCE_KEY' => 'resource-from-the-old-name',
            'LICENSE_KEY' => 'licence-from-the-old-name',
        ]);

        $this->assertSame([], $lines);
    }

    /**
     * Asks the example server for its stylesheet with the given keys in
     * the environment, checks that it answered with the stylesheet and
     * not with a request for a key, and returns what it wrote to the PHP
     * error log.
     *
     * @param array<string, string> $keys
     * @return string[]
     */
    private function serverLog(array $keys): array
    {
        $folder = __DIR__ . '/../examples/creator-context-web';
        $log = (string) tempnam(sys_get_temp_dir(), 'did');
        try {
            [$output] = $this->runPhp(
                ['-d', 'error_log=' . $log, $folder . '/server.php'],
                array_merge($keys, ['REQUEST_URI' => '/examples-main.min.css']),
                [
                    '_51DEGREES_RESOURCE_KEY',
                    '_51DEGREES_LICENSE_KEY',
                    'RESOURCE_KEY',
                    'LICENSE_KEY',
                ]
            );
            $this->assertSame(
                file_get_contents($folder . '/examples-main.min.css'),
                $output
            );

            return array_values(array_filter(
                array_map('trim', (array) file($log)),
                'strlen'
            ));
        } finally {
            unlink($log);
        }
    }

    /**
     * Runs a PHP script with some variables set and others removed, and
     * returns what it wrote to standard output and standard error.
     *
     * @param string[] $arguments
     * @param array<string, string> $set
     * @param string[] $remove
     * @return array{0: string, 1: string}
     */
    private function runPhp(array $arguments, array $set, array $remove): array
    {
        $environment = [];
        foreach (getenv() as $name => $value) {
            if ($name !== '' && $name[0] !== '=' && !in_array($name, $remove, true)) {
                $environment[$name] = $value;
            }
        }
        $process = proc_open(
            array_merge([PHP_BINARY], $arguments),
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            array_merge($environment, $set)
        );
        $this->assertIsResource($process);
        $output = (string) stream_get_contents($pipes[1]);
        $errors = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        return [$output, $errors];
    }

    /**
     * Sets a variable until the test ends, or removes it when the value is
     * null.
     */
    private function set(string $name, ?string $value): void
    {
        if (!array_key_exists($name, $this->previous)) {
            $this->previous[$name] = [getenv($name), $_ENV[$name] ?? null];
        }
        putenv($value === null ? $name : $name . '=' . $value);
        unset($_ENV[$name]);
    }

    /**
     * Runs the action and returns the lines it wrote to the PHP error log.
     * The log is pointed at a file from inside the test, because PHPUnit
     * points it at a file of its own while a test runs.
     *
     * @return string[]
     */
    private function logged(callable $action): array
    {
        $log = (string) tempnam(sys_get_temp_dir(), 'env');
        $previous = ini_set('error_log', $log);
        try {
            $action();

            return array_values(array_filter(
                array_map('trim', (array) file($log)),
                'strlen'
            ));
        } finally {
            ini_set('error_log', (string) $previous);
            unlink($log);
        }
    }
}
