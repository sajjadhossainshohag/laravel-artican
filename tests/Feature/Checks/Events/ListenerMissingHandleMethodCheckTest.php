<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Events;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Events\ListenerMissingHandleMethodCheck;
use SajjadHossain\Artican\Enums\Severity;

class ListenerMissingHandleMethodCheckTest extends TestCase
{
    /** @test */
    public function it_detects_listener_missing_dispatch_method(): void
    {
        $result = (new ListenerMissingHandleMethodCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Listeners'])
            ->run();

        $this->assertCheckFailed($result, Severity::Warning);
    }
}
