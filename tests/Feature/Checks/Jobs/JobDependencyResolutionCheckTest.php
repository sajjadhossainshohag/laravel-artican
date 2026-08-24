<?php

namespace SajjadHossain\Doctor\Tests\Feature\Checks\Jobs;

use SajjadHossain\Doctor\Tests\TestCase;
use SajjadHossain\Doctor\Checks\Jobs\JobDependencyResolutionCheck;
use SajjadHossain\Doctor\Enums\Severity;

class JobDependencyResolutionCheckTest extends TestCase
{
    /** @test */
    public function it_detects_closure_typed_constructor_parameter(): void
    {
        // Ensure bad job class is loaded
        require_once __DIR__.'/../../../Fixtures/App/Jobs/ClosureTypedJob.php';

        $result = (new JobDependencyResolutionCheck())->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertStringContainsString('ClosureTypedJob', $result->locations[0]['job'] ?? '');
    }

    /** @test */
    public function it_does_not_flag_serializable_constructor_parameters(): void
    {
        // Load both jobs - ClosureTypedJob should be flagged, SerializableTypedJob should not
        require_once __DIR__.'/../../../Fixtures/App/Jobs/ClosureTypedJob.php';
        require_once __DIR__.'/../../../Fixtures/App/Jobs/SerializableTypedJob.php';

        $result = (new JobDependencyResolutionCheck())->run();

        $this->assertCheckFailed($result, Severity::Warning);

        // Only ClosureTypedJob should be in locations; SerializableTypedJob must not appear
        $flaggedJobs = array_column($result->locations, 'job');
        $this->assertContains('SajjadHossain\Doctor\Tests\Fixtures\App\Jobs\ClosureTypedJob', $flaggedJobs);
        $this->assertNotContains('SajjadHossain\Doctor\Tests\Fixtures\App\Jobs\SerializableTypedJob', $flaggedJobs);
    }
}
