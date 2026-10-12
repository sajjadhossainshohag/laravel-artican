<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Security;

use SajjadHossain\Artican\Checks\Security\EnvOutsideConfigCheck;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Tests\TestCase;

class EnvOutsideConfigCheckTest extends TestCase
{
    private string $fixturePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixturePath = __DIR__ . '/../../../Fixtures/App/Isolated/EnvOutsideConfig';
    }

    private function check(): EnvOutsideConfigCheck
    {
        return (new EnvOutsideConfigCheck())
            ->withPaths([$this->fixturePath])
            ->withConfigPath($this->fixturePath . '/config');
    }

    /** @test */
    public function it_detects_env_calls_outside_config(): void
    {
        $result = $this->check()->run();

        $this->assertCheckFailed($result, Severity::Warning, 'env()');
        $this->assertCount(5, $result->locations);
    }

    /** @test */
    public function it_reports_exact_lines_in_php_files(): void
    {
        $result = $this->check()->run();

        $lines = [];
        foreach ($result->locations as $location) {
            if (str_ends_with($location['file'], 'EnvSmell.php')) {
                $lines[] = $location['line'];
            }
        }
        sort($lines);

        $this->assertSame([9, 14, 19], $lines);
    }

    /** @test */
    public function it_detects_env_in_blade_but_ignores_blade_comments(): void
    {
        $result = $this->check()->run();

        $bladeHits = array_filter(
            $result->locations,
            fn (array $l) => str_ends_with($l['file'], 'env-in-view.blade.php')
        );

        $this->assertCount(2, $bladeHits);
    }

    /** @test */
    public function it_ignores_files_inside_the_config_directory(): void
    {
        $result = $this->check()->run();

        foreach ($result->locations as $location) {
            $this->assertStringNotContainsString('services.php', $location['file']);
        }
    }

    /** @test */
    public function it_does_not_flag_env_methods_facades_or_comments(): void
    {
        $result = $this->check()->run();

        foreach ($result->locations as $location) {
            $this->assertStringNotContainsString('EnvClean.php', $location['file']);
        }
    }

    /** @test */
    public function it_passes_when_only_clean_file_is_scanned(): void
    {
        $result = (new EnvOutsideConfigCheck())
            ->withPaths([$this->fixturePath . '/App/EnvClean.php'])
            ->withConfigPath($this->fixturePath . '/config')
            ->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_flags_config_files_when_they_are_not_the_config_directory(): void
    {
        $result = (new EnvOutsideConfigCheck())
            ->withPaths([$this->fixturePath . '/config'])
            ->withConfigPath($this->fixturePath . '/elsewhere')
            ->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertCount(2, $result->locations);
    }

    /** @test */
    public function it_has_the_expected_metadata(): void
    {
        $check = new EnvOutsideConfigCheck();

        $this->assertSame('security', $check->category());
        $this->assertSame(Severity::Warning, $check->severity());
    }
}
