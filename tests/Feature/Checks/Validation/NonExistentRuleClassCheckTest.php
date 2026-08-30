<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Validation;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Validation\NonExistentRuleClassCheck;
use SajjadHossain\Artican\Enums\Severity;

class NonExistentRuleClassCheckTest extends TestCase
{
    /** @test */
    public function it_detects_non_existent_rule_class_in_requests(): void
    {
        $result = (new NonExistentRuleClassCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Http/Requests'])
            ->run();

        $this->assertCheckFailed($result, Severity::Warning);
    }
}
