<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Routes;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Routes\DuplicateRouteNamesCheck;
use SajjadHossain\Artican\Enums\Severity;
use Illuminate\Support\Facades\Route;

class DuplicateRouteNamesCheckTest extends TestCase
{
    /** @test */
    public function it_detects_duplicate_route_names(): void
    {
        Route::get('/a', fn () => '')->name('duplicate.name');
        Route::get('/b', fn () => '')->name('duplicate.name');

        $result = (new DuplicateRouteNamesCheck())->run();

        $this->assertCheckFailed($result, Severity::Error);
    }

    /** @test */
    public function it_passes_with_unique_route_names(): void
    {
        Route::get('/a', fn () => '')->name('unique.a');
        Route::get('/b', fn () => '')->name('unique.b');

        $result = (new DuplicateRouteNamesCheck())->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_detects_trailing_dot_group_prefix_without_child_names(): void
    {
        Route::get('/admin/dashboard', fn () => '')->name('admin.');
        Route::get('/admin/users', fn () => '')->name('admin.');
        Route::get('/admin/settings', fn () => '')->name('admin.');

        $result = (new DuplicateRouteNamesCheck())->run();

        $this->assertCheckFailed($result, Severity::Error);
        $this->assertStringContainsString('admin.', $result->message);
        $this->assertStringContainsString('3 routes', $result->message);
        $this->assertStringContainsString('forget ->name()', $result->message);
        $this->assertCount(3, $result->locations);
        foreach ($result->locations as $loc) {
            $this->assertSame('missing_child_name', $loc['issue'] ?? null);
        }
    }

    /** @test */
    public function it_distinguishes_trailing_dot_from_genuine_duplicates(): void
    {
        Route::get('/api/dashboard', fn () => '')->name('api.');
        Route::get('/api/users', fn () => '')->name('api.');
        Route::get('/a', fn () => '')->name('realdup');
        Route::get('/b', fn () => '')->name('realdup');

        $result = (new DuplicateRouteNamesCheck())->run();

        $this->assertCheckFailed($result, Severity::Error);
        $this->assertStringContainsString('api.', $result->message);
        $this->assertStringContainsString('realdup', $result->message);

        $apiIssues = array_filter($result->locations, fn ($l) => ($l['issue'] ?? null) === 'missing_child_name');
        $dupIssues = array_filter($result->locations, fn ($l) => ($l['issue'] ?? null) === 'duplicate_name');
        $this->assertCount(2, $apiIssues);
        $this->assertCount(2, $dupIssues);
    }
}
