<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Blade;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Blade\MissingNamedRoutesCheck;
use SajjadHossain\Artican\Enums\Severity;
use Illuminate\Support\Facades\Route;

class MissingNamedRoutesCheckTest extends TestCase
{
    /** @test */
    public function it_detects_route_call_referencing_undefined_route_name(): void
    {
        Route::get('/', fn () => '')->name('home');

        $check = (new MissingNamedRoutesCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/Views/broken']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Error);
        $this->assertNotEmpty($result->locations);
        $this->assertArrayHasKey('file', $result->locations[0]);
        $this->assertArrayHasKey('line', $result->locations[0]);
    }

    /** @test */
    public function it_passes_when_all_referenced_routes_exist(): void
    {
        Route::get('/', fn () => '')->name('home');

        $check = (new MissingNamedRoutesCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/Views/good']);

        $result = $check->run();

        $this->assertCheckPassed($result);
    }
}
