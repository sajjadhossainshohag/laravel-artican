<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Config;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Config\AbortIfWrongHttpCodeCheck;
use SajjadHossain\Artican\Enums\Severity;

class AbortIfWrongHttpCodeCheckTest extends TestCase
{
    /** @test */
    public function it_detects_abort_if_called_with_success_status_code(): void
    {
        $check = (new AbortIfWrongHttpCodeCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Http/Controllers']); // has abort_if(..., 100) 

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertNotEmpty($result->locations);

        $issues = array_column($result->locations, 'issue');
        $this->assertStringContainsString('100', implode(' ', $issues));
    }
}
