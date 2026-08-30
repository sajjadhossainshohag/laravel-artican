<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Components;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Components\AnonymousComponentCheck;
use SajjadHossain\Artican\Enums\Severity;

class AnonymousComponentCheckTest extends TestCase
{
    /** @test */
    public function it_passes_when_anonymous_component_paths_exist(): void
    {
        $result = (new AnonymousComponentCheck())->run();

        // All paths set up by Orchestra Testbench at this point exist
        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_fails_when_anonymous_component_path_is_missing(): void
    {
        $compiler = app('blade.compiler');

        // Create a temp directory, register it via anonymousComponentNamespace, then delete it
        $tempDir = sys_get_temp_dir().'/artican_anon_component_'.uniqid();
        mkdir($tempDir, 0777, true);

        // Register using the method that populates getAnonymousComponentNamespaces()
        $compiler->anonymousComponentNamespace($tempDir, 'test.namespace');

        // Now delete the directory so it's "missing"
        rmdir($tempDir);

        $result = (new AnonymousComponentCheck())->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertNotEmpty($result->locations);
        $this->assertStringContainsString('test.namespace', $result->locations[0]['namespace'] ?? '');
    }
}
