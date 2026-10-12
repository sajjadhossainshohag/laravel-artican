<?php

namespace SajjadHossain\Artican\Tests\Feature\Commands;

use ReflectionClass;
use SajjadHossain\Artican\Commands\ScanCommand;
use SajjadHossain\Artican\Tests\TestCase;

class SecurityCacheSaltTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        parent::setUp();

        $this->base = sys_get_temp_dir() . '/artican_salt_' . uniqid();
        mkdir($this->base . '/bootstrap', 0777, true);
        file_put_contents($this->base . '/bootstrap/app.php', "<?php\n");
        file_put_contents($this->base . '/.env', "APP_DEBUG=false\n");

        $this->app->setBasePath($this->base);
        config(['artican.scan_paths' => []]);
        $this->resetSaltCache();
    }

    protected function tearDown(): void
    {
        @unlink($this->base . '/bootstrap/app.php');
        @unlink($this->base . '/.env');
        @rmdir($this->base . '/bootstrap');
        @rmdir($this->base);
        $this->resetSaltCache();

        parent::tearDown();
    }

    /** @test */
    public function security_cache_is_invalidated_when_bootstrap_app_changes(): void
    {
        $before = $this->salt('security');

        $this->touchFile($this->base . '/bootstrap/app.php');

        $this->assertNotSame($before, $this->salt('security'));
    }

    /** @test */
    public function security_cache_is_invalidated_when_dot_env_changes(): void
    {
        $before = $this->salt('security');

        $this->touchFile($this->base . '/.env');

        $this->assertNotSame($before, $this->salt('security'));
    }

    /** @test */
    public function other_categories_are_not_invalidated_by_bootstrap_app(): void
    {
        $before = $this->salt('routes');

        $this->touchFile($this->base . '/bootstrap/app.php');

        $this->assertSame($before, $this->salt('routes'));
    }

    private function touchFile(string $file): void
    {
        touch($file, filemtime($file) + 100);
        clearstatcache();
        $this->resetSaltCache();
    }

    private function salt(string $category): string
    {
        $method = (new ReflectionClass(ScanCommand::class))->getMethod('resolveCacheSalt');

        return $method->invoke(new ScanCommand(), $category);
    }

    private function resetSaltCache(): void
    {
        $property = (new ReflectionClass(ScanCommand::class))->getProperty('cacheSaltCache');
        $property->setValue(null, []);
    }
}
