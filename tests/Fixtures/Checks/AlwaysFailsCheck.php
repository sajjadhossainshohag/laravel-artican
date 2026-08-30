<?php

namespace SajjadHossain\Artican\Tests\Fixtures\Checks;

use SajjadHossain\Artican\Contracts\HealthCheck;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;

class AlwaysFailsCheck implements HealthCheck
{
    public function name(): string     { return 'always_fails'; }
    public function category(): string { return 'test'; }
    public function severity(): Severity { return Severity::Error; }

    public function run(): CheckResult
    {
        return new CheckResult(
            check:    $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed:   false,
            message:  'This check always fails — used in command integration tests.',
        );
    }
}
