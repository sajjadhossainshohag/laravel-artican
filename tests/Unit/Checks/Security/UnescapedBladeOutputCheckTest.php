<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Security;

use SajjadHossain\Artican\Checks\Security\UnescapedBladeOutputCheck;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Tests\TestCase;

class UnescapedBladeOutputCheckTest extends TestCase
{
    private string $fixturePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixturePath = __DIR__ . '/../../../Fixtures/App/Isolated/UnescapedBlade';
    }

    /** @test */
    public function it_detects_unescaped_output(): void
    {
        $result = (new UnescapedBladeOutputCheck())
            ->withPaths([$this->fixturePath])
            ->run();

        $this->assertCheckFailed($result, Severity::Warning, 'XSS');
        $this->assertCount(5, $result->locations);
    }

    /** @test */
    public function it_reports_correct_lines_and_skips_comments_and_verbatim(): void
    {
        $result = (new UnescapedBladeOutputCheck())
            ->withPaths([$this->fixturePath])
            ->run();

        $lines = array_column($result->locations, 'line');
        sort($lines);

        // Lines 3 (blade comment) and 5 (@verbatim) are not reported.
        $this->assertSame([1, 2, 7, 10, 11], $lines);
    }

    /** @test */
    public function it_only_reports_the_smell_template(): void
    {
        $result = (new UnescapedBladeOutputCheck())
            ->withPaths([$this->fixturePath])
            ->run();

        foreach ($result->locations as $location) {
            $this->assertStringContainsString('smell.blade.php', $location['file']);
        }
    }

    /** @test */
    public function it_passes_for_trusted_and_escaped_output(): void
    {
        $result = (new UnescapedBladeOutputCheck())
            ->withPaths([$this->fixturePath . '/clean.blade.php'])
            ->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_ignores_non_blade_php_files(): void
    {
        $result = (new UnescapedBladeOutputCheck())
            ->withPaths([$this->fixturePath . '/NotBlade.php'])
            ->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_has_the_expected_metadata(): void
    {
        $check = new UnescapedBladeOutputCheck();

        $this->assertSame('security', $check->category());
        $this->assertSame(Severity::Warning, $check->severity());
    }
}
