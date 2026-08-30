<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Jobs;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Jobs\JobHasHandleMethodCheck;
use SajjadHossain\Artican\Enums\Severity;

class MissingHandleMethodCheckTest extends TestCase
{
    /** @test */
    public function it_detects_job_with_no_handle_method(): void
    {
        $check = (new JobHasHandleMethodCheck())
            ->withPaths([\SajjadHossain\Artican\Tests\Fixtures\App\Jobs\BrokenJob::class]);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Error, 'handle');
    }

    /** @test */
    public function it_passes_for_job_with_handle_method(): void
    {
        $check = (new JobHasHandleMethodCheck())
            ->withPaths([\SajjadHossain\Artican\Tests\Fixtures\App\Jobs\GoodJob::class]);

        $result = $check->run();

        $this->assertCheckPassed($result);
    }
}
