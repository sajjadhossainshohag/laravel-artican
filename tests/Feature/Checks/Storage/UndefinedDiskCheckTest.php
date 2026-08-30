<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Storage;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Storage\UndefinedDiskCheck;
use SajjadHossain\Artican\Enums\Severity;

class UndefinedDiskCheckTest extends TestCase
{
    /** @test */
    public function it_detects_storage_disk_call_to_undefined_disk(): void
    {
        $check = (new UndefinedDiskCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Storage']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Error);
        $this->assertNotEmpty($result->locations);
        $this->assertStringContainsString('undefined-disk', $result->locations[0]['issue'] ?? '');
    }

    /** @test */
    public function it_passes_when_disk_is_defined_in_filesystems_config(): void
    {
        config(['filesystems.disks.local' => [
            'driver' => 'local',
            'root'   => storage_path('app'),
        ]]);

        $check = (new UndefinedDiskCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Models/Good']);

        $result = $check->run();

        $this->assertCheckPassed($result);
    }
}
