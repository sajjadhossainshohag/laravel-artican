<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Schedule;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Schedule\DeletedScheduledCommandCheck;
use SajjadHossain\Artican\Enums\Severity;

class DeletedScheduledCommandCheckTest extends TestCase
{
    /** @test */
    public function it_detects_scheduled_command_name_not_in_artisan(): void
    {
        $check = (new DeletedScheduledCommandCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Console']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Warning);

        $issues = array_column($result->locations, 'issue');
        $this->assertStringContainsString('deleted:command', implode(' ', $issues));
    }
}
