<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Gates;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Gates\MissingPolicyClassCheck;
use SajjadHossain\Artican\Enums\Severity;

class PolicyRegisteredButMissingClassCheckTest extends TestCase
{
    /** @test */
    public function it_detects_policy_bound_to_non_existent_class(): void
    {
        $check = (new MissingPolicyClassCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Providers']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertNotEmpty($result->locations);
        $this->assertStringContainsString('NonExistentPolicy', $result->locations[0]['issue'] ?? '');
    }
}
