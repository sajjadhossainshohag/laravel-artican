<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Env;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Env\MissingEnvKeysCheck;
use SajjadHossain\Artican\Enums\Severity;

class MissingEnvKeyCheckTest extends TestCase
{
    /** @test */
    public function it_detects_env_key_referenced_in_config_but_missing_from_env_file(): void
    {
        $check = (new MissingEnvKeysCheck())
            ->withEnvFile(__DIR__.'/../../../Fixtures/Env/.env.broken')
            ->withConfigPaths([__DIR__.'/../../../Fixtures/Config']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertNotEmpty($result->locations);
        $this->assertEquals('STRIPE_KEY', $result->locations[0]['key']);
    }

    /** @test */
    public function it_passes_when_all_env_keys_are_present(): void
    {
        $check = (new MissingEnvKeysCheck())
            ->withEnvFile(__DIR__.'/../../../Fixtures/Env/.env.good')
            ->withConfigPaths([__DIR__.'/../../../Fixtures/Config']);

        $result = $check->run();

        $this->assertCheckPassed($result);
    }
}
