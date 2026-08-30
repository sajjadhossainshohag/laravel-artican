<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Components;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Components\ComponentClassCheck;
use SajjadHossain\Artican\Enums\Severity;
use Illuminate\Support\Facades\Blade;

class ComponentClassCheckTest extends TestCase
{
    /** @test */
    public function it_detects_non_existent_component_class(): void
    {
        Blade::component('missing-component', 'App\\View\\Components\\NonExistentComponent');

        $result = (new ComponentClassCheck())->run();

        $this->assertCheckFailed($result, Severity::Error);
    }

    /** @test */
    public function it_passes_with_registered_component_classes(): void
    {
        // No broken components registered — should pass
        $result = (new ComponentClassCheck())->run();

        $this->assertCheckPassed($result);
    }
}
