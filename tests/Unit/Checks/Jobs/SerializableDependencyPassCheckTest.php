<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Jobs;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Jobs\JobDependencyResolutionCheck;

class SerializableDependencyPassCheckTest extends TestCase
{
    /** @test */
    public function it_passes_for_serializable_constructor_parameters(): void
    {
        require_once __DIR__.'/../../../Fixtures/App/Jobs/SerializableTypedJob.php';

        $result = (new JobDependencyResolutionCheck())->run();

        $this->assertCheckPassed($result);
    }
}
