<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Views;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Views\MissingComponentCheck;
use SajjadHossain\Artican\Enums\Severity;

class MissingComponentCheckTest extends TestCase
{
    /** @test */
    public function it_detects_missing_component_references(): void
    {
        config()->set('view.paths', [__DIR__.'/../../../Fixtures/Views/broken']);

        $result = (new MissingComponentCheck())->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertStringContainsString('point to missing views', strtolower($result->message));
    }

    /** @test */
    public function it_passes_when_components_exist(): void
    {
        config()->set('view.paths', [__DIR__.'/../../../Fixtures/Views/good']);

        $result = (new MissingComponentCheck())->run();

        $this->assertCheckPassed($result);
    }
}
