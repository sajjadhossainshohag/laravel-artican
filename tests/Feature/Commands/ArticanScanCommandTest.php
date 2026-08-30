<?php

namespace SajjadHossain\Artican\Tests\Feature\Commands;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Facades\Artican;

class ArticanScanCommandTest extends TestCase
{
    /** @test */
    public function it_exits_zero_when_no_issues_found(): void
    {
        $this->artisan('artican:scan', [
            '--only' => 'env',
        ])->assertExitCode(0);
    }

    /** @test */
    public function it_outputs_valid_json_when_json_flag_used(): void
    {
        $this->artisan('artican:scan --json')
            ->assertExitCode(0);
    }

    /** @test */
    public function it_runs_only_specified_categories(): void
    {
        $this->artisan('artican:scan', [
            '--only' => 'routes,views',
        ])->assertExitCode(0);
    }
}
