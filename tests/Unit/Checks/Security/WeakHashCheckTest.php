<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Security;

use SajjadHossain\Artican\Checks\Security\WeakHashCheck;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Tests\TestCase;

class WeakHashCheckTest extends TestCase
{
    private string $fixturePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixturePath = __DIR__ . '/../../../Fixtures/App/Isolated/WeakHash';
    }

    /** @test */
    public function it_detects_weak_hashes_of_secrets(): void
    {
        $result = (new WeakHashCheck())
            ->withPaths([$this->fixturePath . '/WeakHashSmell.php'])
            ->run();

        $this->assertCheckFailed($result, Severity::Warning, 'md5()/sha1()');
        $this->assertCount(35, $result->locations);
    }

    /** @test */
    public function it_reports_the_line_of_each_call_exactly_once(): void
    {
        $result = (new WeakHashCheck())
            ->withPaths([$this->fixturePath . '/WeakHashSmell.php'])
            ->run();

        $expected = [];
        foreach (file($this->fixturePath . '/WeakHashSmell.php') as $index => $line) {
            // "// 7" marks one finding on that line; "// 18, 18" marks two separate findings on it.
            if (preg_match('#// (\d+(?:, \d+)*)$#', rtrim($line), $match)) {
                for ($i = 0, $count = count(explode(',', $match[1])); $i < $count; $i++) {
                    $expected[] = $index + 1;
                }
            }
        }

        $actual = array_column($result->locations, 'line');
        sort($actual);

        $this->assertSame($expected, $actual);
    }

    /** @test */
    public function it_passes_for_non_security_hashes_and_strong_algorithms(): void
    {
        $result = (new WeakHashCheck())
            ->withPaths([$this->fixturePath . '/WeakHashClean.php'])
            ->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_only_reports_the_smell_file_when_both_are_scanned(): void
    {
        $result = (new WeakHashCheck())
            ->withPaths([$this->fixturePath])
            ->run();

        $this->assertCount(35, $result->locations);
        foreach ($result->locations as $location) {
            $this->assertStringContainsString('WeakHashSmell.php', $location['file']);
        }
    }

    /** @test */
    public function each_location_says_which_weak_function_was_hit(): void
    {
        $result = (new WeakHashCheck())
            ->withPaths([$this->fixturePath . '/WeakHashSmell.php'])
            ->run();

        foreach ($result->locations as $location) {
            $this->assertSame('Weak hash', $location['issue']);
            $this->assertMatchesRegularExpression('/^(md5|sha1)\(\)$|^hash\(/', $location['value']);
        }
    }

    /** @test */
    public function overlapping_scan_paths_do_not_double_report(): void
    {
        $result = (new WeakHashCheck())
            ->withPaths([$this->fixturePath, $this->fixturePath . '/WeakHashSmell.php'])
            ->run();

        $this->assertCount(35, $result->locations);
    }

    /** @test */
    public function it_has_the_expected_metadata(): void
    {
        $check = new WeakHashCheck();

        $this->assertSame('security', $check->category());
        $this->assertSame(Severity::Warning, $check->severity());
    }
}
