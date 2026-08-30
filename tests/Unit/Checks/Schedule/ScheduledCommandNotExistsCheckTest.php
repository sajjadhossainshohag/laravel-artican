<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Schedule;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Schedule\ScheduledCommandNotExistsCheck;
use SajjadHossain\Artican\Enums\Severity;

class ScheduledCommandNotExistsCheckTest extends TestCase
{
    /** @test */
    public function it_detects_scheduled_command_class_that_does_not_exist(): void
    {
        $check = (new ScheduledCommandNotExistsCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Console']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertStringContainsString('NonExistentCommand', $result->locations[0]['issue'] ?? '');
    }
}
