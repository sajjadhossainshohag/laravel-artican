<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Eloquent;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Schema\InvalidCastsCheck;
use SajjadHossain\Artican\Enums\Severity;

class BadCastCheckTest extends TestCase
{
    /** @test */
    public function it_detects_cast_to_non_existent_enum_class(): void
    {
        $check = (new InvalidCastsCheck())
            ->withModels([\SajjadHossain\Artican\Tests\Fixtures\App\Models\Broken\BadCastModel::class]);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Error);
        $this->assertNotEmpty($result->locations);
        $this->assertEquals('NonExistentEnum', $result->locations[0]['cast'] ?? '');
    }

    /** @test */
    public function it_passes_for_model_with_valid_casts(): void
    {
        $check = (new InvalidCastsCheck())
            ->withModels([\SajjadHossain\Artican\Tests\Fixtures\App\Models\Good\WellDefinedModel::class]);

        $result = $check->run();

        $this->assertCheckPassed($result);
    }
}
