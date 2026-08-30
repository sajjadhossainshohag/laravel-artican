<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Components;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Components\ComponentNamespaceCheck;
use SajjadHossain\Artican\Enums\Severity;

class ComponentNamespaceCheckTest extends TestCase
{
    /** @test */
    public function it_passes_when_namespace_paths_exist(): void
    {
        $result = (new ComponentNamespaceCheck())->run();

        // Default testbench namespace hints exist — should pass
        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_fails_when_namespace_path_is_missing(): void
    {
        // Register a fake view namespace pointing to a non-existent directory
        app('view')->addNamespace('fake.test.namespace', '/this/path/does/not/exist/67890');

        $result = (new ComponentNamespaceCheck())->run();

        $this->assertCheckFailed($result, Severity::Info);
        $this->assertNotEmpty($result->locations);
        $this->assertStringContainsString('fake.test.namespace', $result->locations[0]['namespace'] ?? '');
    }
}
