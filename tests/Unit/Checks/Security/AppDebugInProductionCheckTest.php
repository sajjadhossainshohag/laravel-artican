<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Security;

use SajjadHossain\Artican\Checks\Security\AppDebugInProductionCheck;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Tests\TestCase;

class AppDebugInProductionCheckTest extends TestCase
{
    /** @test */
    public function it_fails_when_debug_is_on_in_production(): void
    {
        config(['app.env' => 'production', 'app.debug' => true]);

        $result = (new AppDebugInProductionCheck())->run();

        $this->assertCheckFailed($result, Severity::Error, 'APP_DEBUG');
    }

    /** @test */
    public function it_fails_for_string_boolean_values_and_any_casing(): void
    {
        config(['app.env' => 'Production', 'app.debug' => 'true']);

        $this->assertCheckFailed((new AppDebugInProductionCheck())->run(), Severity::Error);

        config(['app.env' => 'production', 'app.debug' => '1']);

        $this->assertCheckFailed((new AppDebugInProductionCheck())->run(), Severity::Error);
    }

    /** @test */
    public function it_passes_when_debug_is_off_in_production(): void
    {
        config(['app.env' => 'production', 'app.debug' => false]);

        $this->assertCheckPassed((new AppDebugInProductionCheck())->run());

        config(['app.debug' => 'false']);

        $this->assertCheckPassed((new AppDebugInProductionCheck())->run());
    }

    /** @test */
    public function it_passes_when_debug_is_on_outside_production(): void
    {
        foreach (['local', 'testing', 'staging'] as $env) {
            config(['app.env' => $env, 'app.debug' => true]);

            $this->assertCheckPassed((new AppDebugInProductionCheck())->run());
        }
    }

    /** @test */
    public function it_passes_when_debug_is_not_set(): void
    {
        config(['app.env' => 'production', 'app.debug' => null]);

        $this->assertCheckPassed((new AppDebugInProductionCheck())->run());
    }
}
