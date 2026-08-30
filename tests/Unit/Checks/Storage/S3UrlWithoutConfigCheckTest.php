<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Storage;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Storage\S3UrlWithoutConfigCheck;
use SajjadHossain\Artican\Enums\Severity;

class S3UrlWithoutConfigCheckTest extends TestCase
{
    /** @test */
    public function it_detects_s3_url_without_bucket_or_region(): void
    {
        // The check uses config('artican.scan_paths', [...]) internally,
        // so we set the config path to our fixture.
        config()->set('artican.scan_paths', [
            __DIR__.'/../../../Fixtures/App/Storage',
        ]);
        config()->set('filesystems.disks.s3', []);

        $result = (new S3UrlWithoutConfigCheck())->run();

        $this->assertCheckFailed($result, Severity::Info);
        $this->assertStringContainsString('without required bucket/region', $result->message);
    }

    /** @test */
    public function it_passes_when_s3_has_required_config(): void
    {
        config()->set('artican.scan_paths', [
            __DIR__.'/../../../Fixtures/App/Storage',
        ]);
        config()->set('filesystems.disks.s3', [
            'bucket' => 'my-bucket',
            'region' => 'us-east-1',
        ]);

        $result = (new S3UrlWithoutConfigCheck())->run();

        $this->assertCheckPassed($result);
    }
}
