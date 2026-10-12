<?php

namespace SajjadHossain\Artican\Checks\Security;

use SajjadHossain\Artican\Contracts\HealthCheck;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;

class AppDebugInProductionCheck implements HealthCheck
{
    public function name(): string
    {
        return 'APP_DEBUG enabled in production';
    }

    public function category(): string
    {
        return 'security';
    }

    public function severity(): Severity
    {
        return Severity::Error;
    }

    public function run(): CheckResult
    {
        $environment = strtolower((string) config('app.env'));
        $debug = filter_var(config('app.debug'), FILTER_VALIDATE_BOOLEAN);

        if ($environment === 'production' && $debug) {
            return new CheckResult(
                check: $this->name(),
                category: $this->category(),
                severity: $this->severity(),
                passed: false,
                message: 'APP_DEBUG is true while APP_ENV is "production".',
                suggestion: 'Set APP_DEBUG=false in production. Debug mode shows stack traces, config values, and environment variables to visitors.',
            );
        }

        return new CheckResult(
            check: $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed: true,
            message: 'Debug mode is not enabled in production.',
        );
    }
}
