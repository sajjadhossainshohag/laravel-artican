<?php

namespace SajjadHossain\Artican\Contracts;

use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;

interface HealthCheck
{
    public function name(): string;

    public function category(): string;

    public function run(): CheckResult;

    public function severity(): Severity;
}
