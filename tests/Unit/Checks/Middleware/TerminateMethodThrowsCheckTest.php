<?php

namespace SajjadHossain\Doctor\Tests\Unit\Checks\Middleware;

use SajjadHossain\Doctor\Tests\TestCase;
use SajjadHossain\Doctor\Checks\Middleware\TerminateMethodThrowsCheck;
use SajjadHossain\Doctor\Enums\Severity;

class TerminateMethodThrowsCheckTest extends TestCase
{
    /** @test */
    public function it_reports_terminate_with_external_calls_and_no_try_catch_as_informational(): void
    {
        $check = (new TerminateMethodThrowsCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Middleware']);

        $result = $check->run();

        // Info severity checks always pass but report locations
        $this->assertNotEmpty($result->locations);
        $this->assertStringContainsString('without try/catch', $result->locations[0]['issue'] ?? '');
    }
}
