<?php

namespace SajjadHossain\Doctor\Tests\Unit\Checks\Validation;

use SajjadHossain\Doctor\Tests\TestCase;
use SajjadHossain\Doctor\Checks\Validation\AuthorizeAlwaysFalseCheck;
use SajjadHossain\Doctor\Enums\Severity;

class AuthorizeAlwaysFalseCheckTest extends TestCase
{
    /** @test */
    public function it_reports_authorize_returning_false_as_informational(): void
    {
        $check = (new AuthorizeAlwaysFalseCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Http/Requests']);

        $result = $check->run();

        // Info severity checks always pass but report locations
        $this->assertTrue($result->passed);
        $this->assertNotEmpty($result->locations);
        $this->assertStringContainsString('AlwaysFalse', $result->locations[0]['file'] ?? '');
    }
}
