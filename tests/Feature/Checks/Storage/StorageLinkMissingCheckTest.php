<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Storage;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Storage\MissingStorageSymlinkCheck;
use SajjadHossain\Artican\Enums\Severity;

class StorageLinkMissingCheckTest extends TestCase
{
    /** @test */
    public function it_detects_missing_public_storage_symlink(): void
    {
        // Create a temp "public" directory and a temp "storage/app/public" target
        $publicDir = sys_get_temp_dir().'/artican_test_public_'.uniqid();
        $storageDir = sys_get_temp_dir().'/artican_test_storage_'.uniqid();
        mkdir($publicDir, 0777, true);
        mkdir($storageDir.'/app/public', 0777, true);

        // Mock public_path() and storage_path() to point to our temp dirs
        app()->usePublicPath($publicDir);
        app()->useStoragePath($storageDir);

        config(['filesystems.disks.public' => ['driver' => 'local', 'root' => $storageDir.'/app/public']]);

        $result = (new MissingStorageSymlinkCheck())->run();

        // Cleanup
        rmdir($publicDir);
        rmdir($storageDir.'/app/public');
        rmdir($storageDir.'/app');
        rmdir($storageDir);

        $this->assertCheckFailed($result, Severity::Warning, 'symlink');
    }

    /** @test */
    public function it_passes_when_public_storage_symlink_exists(): void
    {
        $publicDir = sys_get_temp_dir().'/artican_test_public2_'.uniqid();
        $storageDir = sys_get_temp_dir().'/artican_test_storage2_'.uniqid();
        mkdir($publicDir, 0777, true);
        mkdir($storageDir.'/app/public', 0777, true);

        // Create the symlink: public/storage -> storage/app/public
        if (PHP_OS_FAMILY === 'Windows') {
            // On Windows, create a junction or skip symlink creation if not elevated
            // For test purposes, we'll skip Windows symlink creation and just test the missing case
            rmdir($publicDir);
            rmdir($storageDir.'/app/public');
            rmdir($storageDir.'/app');
            rmdir($storageDir);
            $this->markTestSkipped('Symlink creation requires admin on Windows');
        }
        symlink($storageDir.'/app/public', $publicDir.'/storage');

        app()->usePublicPath($publicDir);
        app()->useStoragePath($storageDir);
        config(['filesystems.disks.public' => ['driver' => 'local', 'root' => $storageDir.'/app/public']]);

        $result = (new MissingStorageSymlinkCheck())->run();

        // Cleanup
        unlink($publicDir.'/storage');
        rmdir($publicDir);
        rmdir($storageDir.'/app/public');
        rmdir($storageDir.'/app');
        rmdir($storageDir);

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_passes_when_no_public_disk_configured(): void
    {
        config(['filesystems.disks.public' => null]);

        $result = (new MissingStorageSymlinkCheck())->run();

        $this->assertCheckPassed($result);
    }
}
