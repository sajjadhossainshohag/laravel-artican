<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Storage;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Storage\StoreAsPathTraversalCheck;
use SajjadHossain\Artican\Enums\Severity;

class StoreAsPathTraversalCheckTest extends TestCase
{
    /** @test */
    public function it_detects_path_traversal_in_storeas(): void
    {
        config()->set('artican.scan_paths', [__DIR__.'/../../../Fixtures/App/Storage']);

        $result = (new StoreAsPathTraversalCheck())->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertCount(3, $result->locations);
    }
}
