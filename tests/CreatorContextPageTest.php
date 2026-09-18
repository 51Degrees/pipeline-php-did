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
 * What the creator context demo page does in a browser, checked by
 * running its script in Node with a small stand in for a browser
 * (creator-context-page-harness.js). Both the parse check and the run
 * need Node on the path, which every GitHub hosted runner has.
 *
 * The service creates a 51Did only once the page has run the snippets it
 * asks for and sent what they collected, so a page that asks for one
 * directly is told the page has not finished and is given nothing. The
 * 51Degrees client script is what runs those snippets, so the page has
 * to create through the script and then send what the snippets collected
 * with its verification call as well. These tests pin both, because
 * neither can be seen from the PHP side of the demo and neither shows up
 * in a unit test of the server.
 */
class CreatorContextPageTest extends TestCase
{
    /**
     * The licensed probabilistic identifier the stand in client script
     * reports, and the same value once the page has made it safe for a
     * URL.
     */
    private const CREATED_URL_SAFE = 'prob-lic_value';

    private static ?string $node = null;

    public static function setUpBeforeClass(): void
    {
        foreach (['node --version', 'node.exe --version'] as $candidate) {
            $output = [];
            $status = 0;
            exec($candidate . ' 2>&1', $output, $status);
            if ($status === 0) {
                self::$node = explode(' ', $candidate)[0];
                return;
            }
        }
    }

    protected function setUp(): void
    {
        if (self::$node === null) {
            $this->markTestSkipped('Node is not on the path');
        }
    }

    private function harness(): string
    {
        return __DIR__ . DIRECTORY_SEPARATOR
            . 'creator-context-page-harness.js';
    }

    private function page(): string
    {
        return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'examples'
            . DIRECTORY_SEPARATOR . 'creator-context-web'
            . DIRECTORY_SEPARATOR . 'page.html';
    }

    /**
     * Runs the page's script and returns what the harness recorded.
     *
     * @return array<string, mixed>
     */
    private function runPage(?string $given = null): array
    {
        $command = escapeshellarg((string)self::$node) . ' '
            . escapeshellarg($this->harness()) . ' '
            . escapeshellarg($this->page());
        if ($given !== null) {
            $command .= ' ' . escapeshellarg($given);
        }
        $output = [];
        $status = 0;
        exec($command . ' 2>&1', $output, $status);
        $text = implode("\n", $output);
        $this->assertSame(0, $status, 'the harness failed: ' . $text);
        $lines = array_values(array_filter(
            array_map('trim', $output),
            static fn (string $line): bool => $line !== ''
        ));
        $record = json_decode(end($lines), true);
        $this->assertIsArray($record, 'the harness printed: ' . $text);
        return $record;
    }

    /**
     * A page whose script does not parse defines nothing and reports
     * nothing, and the browser says so only in its console. node --check
     * reads JavaScript rather than HTML, so the page's script block is
     * written out on its own and checked.
     */
    public function testThePageScriptParses(): void
    {
        $page = file_get_contents($this->page());
        $this->assertIsString($page);
        // A checkout on Windows has carriage returns in it.
        $found = preg_match(
            '/<script>\r?\n(.*?)\r?\n<\/script>/s',
            $page,
            $matches
        );
        $this->assertSame(1, $found, 'the page has a script block');
        $path = tempnam(sys_get_temp_dir(), 'page') . '.js';
        file_put_contents($path, $matches[1]);
        $output = [];
        $status = 0;
        exec(
            escapeshellarg((string)self::$node) . ' --check '
            . escapeshellarg($path) . ' 2>&1',
            $output,
            $status
        );
        unlink($path);
        $this->assertSame(
            0,
            $status,
            "the page's script does not parse: " . implode("\n", $output)
        );
        $this->assertSame([], $this->runPage()['errors']);
    }

    /**
     * The page asks the cloud for the client script, with the usage and
     * the email address on its address, and takes the identifier from
     * what the script reports.
     */
    public function testTheIdentifierComesFromTheClientScript(): void
    {
        $record = $this->runPage();
        $this->assertCount(
            1,
            $record['scripts'],
            'the page loads the client script exactly once'
        );
        $script = $record['scripts'][0];
        $this->assertStringContainsString('TEST-RESOURCE-KEY.js', $script);
        $this->assertStringContainsString('id.usage=non-marketing', $script);
        $this->assertStringContainsString('id.email=', $script);
        $this->assertSame(
            'created for this browser',
            $record['rows']['s-create']
        );
    }

    /**
     * A request of the page's own would be made before the snippets had
     * run, and the service would answer it with no identifier at all.
     */
    public function testThePageDoesNotAskForAnIdentifierItself(): void
    {
        foreach ($this->runPage()['fetches'] as $address) {
            $this->assertStringNotContainsString('json?resource=', $address);
            $this->assertStringNotContainsString('/json', $address);
        }
    }

    /**
     * The identifier the script reported is verified, made safe for a
     * URL, and what the snippets collected goes with it, because the
     * service compares this browser against the creator from those
     * values.
     */
    public function testTheVerificationCarriesTheIdentifierAndSnippets(): void
    {
        $record = $this->runPage();
        $verify = array_values(array_filter(
            $record['fetches'],
            static fn (string $a): bool => str_contains($a, 'id/verify-full')
        ));
        $this->assertCount(1, $verify);
        $this->assertStringContainsString(self::CREATED_URL_SAFE, $verify[0]);
        $this->assertStringNotContainsString(
            '+',
            explode('?', $verify[0])[0]
        );
        $this->assertStringContainsString(
            '51D_ScreenPixelsHeight=1080',
            $verify[0]
        );
        $this->assertStringContainsString('51D_ProfileIds=1-2-3', $verify[0]);
        $this->assertStringNotContainsString('unrelated=ignored', $verify[0]);
    }

    /**
     * The licence key lives on the server, so the sealed result goes
     * there and the verdict comes back from there.
     */
    public function testTheResultIsRedeemedOnThePagesOwnServer(): void
    {
        $record = $this->runPage();
        $redeem = array_values(array_filter(
            $record['fetches'],
            static fn (string $a): bool => str_starts_with($a, '/redeem?')
        ));
        $this->assertCount(1, $redeem);
        $this->assertStringContainsString('result=sealed-result', $redeem[0]);
        $this->assertSame('verified', $record['rows']['s-signature']);
        $this->assertSame('verified', $record['rows']['s-context']);
    }

    /**
     * The page opened with an identifier from another browser checks
     * that identifier, and still needs this browser's snippet values for
     * the comparison, so the script runs on that path too.
     */
    public function testATransplantedIdentifierStillRunsTheClientScript(): void
    {
        $record = $this->runPage('given-value');
        $this->assertCount(1, $record['scripts']);
        $verify = array_values(array_filter(
            $record['fetches'],
            static fn (string $a): bool => str_contains($a, 'id/verify-full')
        ));
        $this->assertCount(1, $verify);
        $this->assertStringContainsString('given-value', $verify[0]);
        $this->assertStringContainsString('51D_ProfileIds=1-2-3', $verify[0]);
    }

    /**
     * Someone running the demo is interested in the subject, so the page
     * ends with somewhere to go next. The links to 51degrees.com carry
     * the five part campaign tags the 51Degrees convention asks for,
     * which nothing in this repository lints, and the source
     * repositories are given as plain addresses.
     */
    public function testThePageEndsWithFindOutMore(): void
    {
        $page = file_get_contents($this->page());
        $this->assertIsString($page);
        $this->assertStringContainsString('Find out more', $page);
        $this->assertStringContainsString(
            'utm_campaign=pipeline-php-did',
            $page
        );
        $this->assertStringContainsString(
            'https://github.com/51Degrees/pipeline-php-did',
            $page
        );
    }
}
