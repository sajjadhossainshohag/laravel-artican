<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Events;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Events\MissingListenerClassCheck;
use SajjadHossain\Artican\Enums\Severity;

class MissingListenerClassCheckTest extends TestCase
{
    /** @test */
    public function it_detects_non_existent_listener_classes(): void
    {
        $check = (new MissingListenerClassCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Providers']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $locations = $result->locations;
        $this->assertNotEmpty($locations);
        $this->assertStringContainsString('DeletedListener', $locations[0]['issue'] ?? '');
    }
}
