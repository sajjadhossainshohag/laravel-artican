<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Security;

use SajjadHossain\Artican\Checks\Security\RawQueryInterpolationCheck;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Tests\TestCase;

class RawQueryInterpolationCheckTest extends TestCase
{
    private string $fixturePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixturePath = __DIR__ . '/../../../Fixtures/App/Isolated/RawQueryInterpolation';
    }

    /** @test */
    public function it_detects_all_unsafe_calls_in_smell_file(): void
    {
        $result = (new RawQueryInterpolationCheck())
            ->withPaths([$this->fixturePath . '/RawQuerySmell.php'])
            ->run();

        $this->assertCheckFailed($result, Severity::Error, 'SQL injection');
        $this->assertCount(13, $result->locations);
    }

    /** @test */
    public function it_reports_the_line_of_each_call(): void
    {
        $result = (new RawQueryInterpolationCheck())
            ->withPaths([$this->fixturePath . '/RawQuerySmell.php'])
            ->run();

        $source = file($this->fixturePath . '/RawQuerySmell.php');
        $expected = [];
        foreach ($source as $index => $line) {
            if (preg_match('#// \d+$#', rtrim($line))) {
                $expected[] = $index + 1;
            }
        }

        $actual = array_column($result->locations, 'line');
        sort($actual);

        $this->assertSame($expected, $actual);
    }

    /** @test */
    public function it_passes_for_bindings_literals_casts_and_constants(): void
    {
        $result = (new RawQueryInterpolationCheck())
            ->withPaths([$this->fixturePath . '/RawQueryClean.php'])
            ->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_only_reports_the_smell_file_when_both_are_scanned(): void
    {
        $result = (new RawQueryInterpolationCheck())
            ->withPaths([$this->fixturePath])
            ->run();

        $this->assertCount(13, $result->locations);
        foreach ($result->locations as $location) {
            $this->assertStringContainsString('RawQuerySmell.php', $location['file']);
        }
    }

    /** @test */
    public function it_has_the_expected_metadata(): void
    {
        $check = new RawQueryInterpolationCheck();

        $this->assertSame('security', $check->category());
        $this->assertSame(Severity::Error, $check->severity());
    }
}
