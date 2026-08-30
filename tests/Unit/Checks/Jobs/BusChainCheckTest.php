<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Jobs;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Jobs\BusChainCheck;
use SajjadHossain\Artican\Enums\Severity;

class BusChainCheckTest extends TestCase
{
    /** @test */
    public function it_detects_non_existent_jobs_in_bus_chain(): void
    {
        config()->set('artican.scan_paths', [
            __DIR__.'/../../../Fixtures/App/Http/Controllers',
        ]);

        $result = (new BusChainCheck())->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertStringContainsString('NonExistentJob', $result->locations[0]['job'] ?? '');
    }
}
