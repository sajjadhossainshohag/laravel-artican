<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Validation;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Validation\AuthorizeAlwaysFalseCheck;
use SajjadHossain\Artican\Enums\Severity;

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
