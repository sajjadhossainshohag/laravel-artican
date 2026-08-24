<?php

namespace SajjadHossain\Doctor\Tests\Unit\Checks\Routes;

use SajjadHossain\Doctor\Tests\TestCase;
use SajjadHossain\Doctor\Checks\Routes\DuplicateUrisCheck;
use SajjadHossain\Doctor\Enums\Severity;
use Illuminate\Support\Facades\Route;

class DuplicateUrisCheckTest extends TestCase
{
    /** @test */
    public function it_passes_when_no_duplicate_uris_registered(): void
    {
        Route::get('/unique-get', fn () => '')->name('unique.get');
        Route::post('/unique-get', fn () => '')->name('unique.post'); // Different method = not duplicate

        $result = (new DuplicateUrisCheck())->run();

        $this->assertCheckPassed($result);
    }
}
