<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Container;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Container\InterfaceBoundToDeletedConcreteCheck;
use SajjadHossain\Artican\Enums\Severity;

class InterfaceBoundToDeletedConcreteCheckTest extends TestCase
{
    /** @test */
    public function it_detects_binding_pointing_to_non_existent_class(): void
    {
        $check = (new InterfaceBoundToDeletedConcreteCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/App/Providers']);

        $result = $check->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertNotEmpty($result->locations);
        $this->assertStringContainsString('DeletedPaymentGateway', $result->locations[0]['issue'] ?? '');
    }

    /** @test */
    public function it_passes_when_no_bindings_to_non_existent_classes(): void
    {
        $check = (new InterfaceBoundToDeletedConcreteCheck())
            ->withPaths([__DIR__.'/../../../Fixtures/Config']);

        $result = $check->run();

        $this->assertCheckPassed($result);
    }
}
