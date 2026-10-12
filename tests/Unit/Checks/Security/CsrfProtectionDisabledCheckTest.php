<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Security;

use SajjadHossain\Artican\Checks\Security\CsrfProtectionDisabledCheck;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Tests\TestCase;

class CsrfProtectionDisabledCheckTest extends TestCase
{
    private string $fixturePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixturePath = __DIR__ . '/../../../Fixtures/App/Isolated/CsrfDisabled';
    }

    /** @test */
    public function it_detects_wildcard_in_except_property_and_bootstrap_calls(): void
    {
        $result = (new CsrfProtectionDisabledCheck())
            ->withPaths([$this->fixturePath . '/Smell'])
            ->run();

        $this->assertCheckFailed($result, Severity::Error, 'every route');
        $this->assertCount(4, $result->locations);
    }

    /** @test */
    public function it_reports_the_except_property_line(): void
    {
        $result = (new CsrfProtectionDisabledCheck())
            ->withPaths([$this->fixturePath . '/Smell/VerifyCsrfToken.php'])
            ->run();

        $this->assertCount(1, $result->locations);
        $this->assertSame(7, $result->locations[0]['line']);
    }

    /** @test */
    public function it_passes_for_specific_exclusions(): void
    {
        $result = (new CsrfProtectionDisabledCheck())
            ->withPaths([$this->fixturePath . '/Clean'])
            ->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_scans_bootstrap_app_by_default(): void
    {
        $this->app->setBasePath(__DIR__ . '/../../../Fixtures/App/Isolated/CsrfDisabled/Base');
        config(['artican.scan_paths' => []]);

        $result = (new CsrfProtectionDisabledCheck())->run();

        $this->assertCheckFailed($result, Severity::Error);
        $this->assertStringContainsString('app.php', $result->locations[0]['file']);
    }

    /** @test */
    public function it_has_the_expected_metadata(): void
    {
        $check = new CsrfProtectionDisabledCheck();

        $this->assertSame('security', $check->category());
        $this->assertSame(Severity::Error, $check->severity());
    }
}
