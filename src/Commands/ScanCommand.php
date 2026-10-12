<?php

namespace SajjadHossain\Artican\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use SajjadHossain\Artican\CheckRegistry;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Output\AgentRenderer;
use SajjadHossain\Artican\Output\ConsoleRenderer;
use SajjadHossain\Artican\ParallelRunner;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class ScanCommand extends Command
{
    protected $signature = 'artican:scan
        {--only= : Comma-separated check categories to run}
        {--json : Output structured JSON}
        {--html : Output HTML report}
        {--format= : Output format (agent)}
        {--fail-on= : Exit non-zero if issues at this severity exist}
        {--no-cache : Skip cached results}
        {--parallel : Distribute checks across parallel subprocesses}
        {--workers= : Number of parallel workers (detected from CPU by default)}';

    protected $description = 'Static analysis — no DB, no HTTP required';

    public function handle(CheckRegistry $registry, ConsoleRenderer $renderer): int
    {
        $checkClasses = $registry->all();
        $only = $this->option('only');
        $instances = [];

        foreach ($checkClasses as $class) {
            $instances[] = new $class();
        }

        if ($only) {
            $categories = explode(',', $only);
            $instances = array_values(array_filter($instances, fn ($c) => in_array($c->category(), $categories, true)));
        }

        if (empty($instances)) {
            $this->warn('No checks registered. Register checks via Artican::register() in a service provider.');

            return 0;
        }

        $isAgent = $this->option('format') === 'agent';
        if (!$isAgent && class_exists(\Laravel\AgentDetector\AgentDetector::class)) {
            $isAgent = \Laravel\AgentDetector\AgentDetector::detect()->isAgent;
        }

        $total = count($instances);
        $noCache = $this->option('no-cache');

        $grouped = [];
        foreach ($instances as $check) {
            $grouped[$check->category()][] = $check;
        }

        $cacheStore = config('artican.cache.store', 'file');
        $cacheTtl = config('artican.cache.ttl', 3600);

        $results = [];
        $overallStart = microtime(true);

        if ($this->option('parallel')) {
            $workerCount = $this->option('workers') ? (int) $this->option('workers') : null;

            $uncachedAll = [];

            foreach ($grouped as $category => $categoryChecks) {
                if (!$noCache) {
                    $cached = Cache::store($cacheStore)->get($this->computeCacheKey($category));
                    if ($cached !== null) {
                        $results = array_merge($results, $cached);
                        continue;
                    }
                }
                foreach ($categoryChecks as $check) {
                    $uncachedAll[] = $check;
                }
            }

            if (!empty($uncachedAll)) {
                if (!$isAgent) {
                    $this->output->write("  <fg=cyan>Running parallel workers...</>");
                }

                $completed = 0;
                $workerTotal = 0;

                $runner = new ParallelRunner($workerCount);

                $workerResults = $runner->run($uncachedAll, function (string $event, int $idx, string $info, bool $success) use ($isAgent, &$completed, &$workerTotal): void {
                    if ($isAgent) {
                        return;
                    }

                    match ($event) {
                        'spawn' => $workerTotal++,
                        'done' => $this->output->write("\r  <fg=cyan>Running parallel workers... </>" . (++$completed) . "/{$workerTotal} complete"),
                        'fallback' => $this->output->write("\r  <fg=yellow>Running parallel workers... </>" . (++$completed) . "/{$workerTotal} complete (fallback)"),
                    };
                });

                $results = array_merge($results, $workerResults);

                if (!$isAgent) {
                    $this->output->writeln("\r  <fg=green>Parallel scan complete. ({$workerTotal} worker" . ($workerTotal !== 1 ? 's' : '') . ')</>');
                }
            }

            if (!$noCache) {
                $byCategory = [];
                foreach ($results as $r) {
                    $byCategory[$r->category][] = $r;
                }
                foreach ($byCategory as $cat => $catResults) {
                    Cache::store($cacheStore)->put($this->computeCacheKey($cat), $catResults, $cacheTtl);
                }
            }

            if (!$isAgent) {
                $this->newLine();
            }
        } else {
            if (!$isAgent) {
                $this->newLine();
                $this->line("  <fg=cyan>Running {$total} checks...</>");
                $this->newLine();
            }

            $checkIndex = 0;

            foreach ($grouped as $category => $categoryChecks) {
                $cachedResults = null;

                if (!$noCache) {
                    $cachedResults = Cache::store($cacheStore)->get($this->computeCacheKey($category));
                }

                if ($cachedResults !== null) {
                    foreach ($cachedResults as $result) {
                        $checkIndex++;
                        $results[] = $result;

                        if (!$isAgent) {
                            $this->output->write("  <fg=gray>[{$this->pad($checkIndex, $total)}/{$total}]</> " . ConsoleRenderer::escape($result->check) . "... ");
                            $icon = $result->passed ? '✓' : '✗';
                            $color = $result->passed ? 'green' : ($result->severity === Severity::Error ? 'red' : 'yellow');
                            $this->output->writeln("<fg={$color}>{$icon}</> <fg=gray>cached</>");
                        }
                    }

                    continue;
                }

                $freshResults = [];

                foreach ($categoryChecks as $check) {
                    $checkIndex++;
                    $name = $check->name();

                    if (!$isAgent) {
                        $this->output->write("  <fg=gray>[{$this->pad($checkIndex, $total)}/{$total}]</> " . ConsoleRenderer::escape($name) . "... ");
                    }

                    $checkStart = microtime(true);
                    $result = $check->run();
                    $checkDuration = (microtime(true) - $checkStart) * 1000;
                    $freshResults[] = $result;

                    if (!$isAgent) {
                        $icon = $result->passed ? '✓' : '✗';
                        $color = $result->passed ? 'green' : ($result->severity === Severity::Error ? 'red' : 'yellow');
                        $ms = number_format($checkDuration, 0);
                        $this->output->writeln("<fg={$color}>{$icon}</> <fg=gray>{$ms}ms</>");
                    }
                }

                if (!$noCache) {
                    Cache::store($cacheStore)->put($this->computeCacheKey($category), $freshResults, $cacheTtl);
                }

                $results = array_merge($results, $freshResults);
            }

            if (!$isAgent) {
                $this->newLine();
            }
        }

        $duration = (microtime(true) - $overallStart) * 1000;

        if ($isAgent) {
            $this->line((new AgentRenderer())->render($results));

            return $this->failOnExitCode($results);
        }

        if ($this->option('json')) {
            $this->line((new \SajjadHossain\Artican\Output\JsonRenderer())->render($results));

            return $this->failOnExitCode($results);
        }

        if ($this->option('html')) {
            $this->line((new \SajjadHossain\Artican\Output\HtmlRenderer())->render($results));

            return $this->failOnExitCode($results);
        }

        $renderer->render($this->output, $results, $duration);

        return $this->failOnExitCode($results);
    }

    private static array $cacheSaltCache = [];

    private static ?string $fingerprint = null;

    private function computeCacheKey(string $category): string
    {
        return "artican_scan_{$category}_" . $this->resolveCacheSalt($category) . '_' . $this->checkFingerprint();
    }

    private function checkFingerprint(): string
    {
        if (self::$fingerprint !== null) {
            return self::$fingerprint;
        }

        $classes = app(CheckRegistry::class)->all();
        $version = $this->packageVersion();

        if ($version !== 'unversioned') {
            return self::$fingerprint = md5($version . '|' . implode('|', $classes));
        }

        // Every package source file, not a hand-picked list; reading modification times loads no classes.
        $mtimes = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__), RecursiveDirectoryIterator::SKIP_DOTS));

        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $mtimes[$file->getPathname()] = $file->getMTime();
            }
        }

        ksort($mtimes);

        return self::$fingerprint = md5(serialize($mtimes) . '|' . implode('|', $classes));
    }

    private function packageVersion(): string
    {
        try {
            if (class_exists(\Composer\InstalledVersions::class)) {
                $pretty = (string) \Composer\InstalledVersions::getPrettyVersion('sajjadhossainshohag/laravel-artican');

                // Dev branches and path installs change without the version changing: they fall back to file mtimes.
                $reference = (string) \Composer\InstalledVersions::getReference('sajjadhossainshohag/laravel-artican');
                $installPath = \Composer\InstalledVersions::getInstallPath('sajjadhossainshohag/laravel-artican');

                $vendor = realpath(base_path('vendor'));
                $installed = $installPath === null ? false : realpath($installPath);

                if ($vendor === false || $installed === false || !str_starts_with(str_replace('\\', '/', $installed), str_replace('\\', '/', $vendor) . '/')) {
                    return 'unversioned';
                }

                if ($pretty !== '' && $reference !== '' && !str_starts_with($pretty, 'dev-') && !str_ends_with($pretty, '-dev')) {
                    return $pretty . '@' . $reference;
                }
            }
        } catch (\Throwable) {
        }

        return 'unversioned';
    }

    private function resolveCacheSalt(string $category): string
    {
        if ($category === 'env') {
            if (isset(self::$cacheSaltCache['env'])) {
                return self::$cacheSaltCache['env'];
            }

            return self::$cacheSaltCache['env'] = $this->hashFileMtimes([
                base_path('.env'),
                config_path(),
            ]);
        }

        if ($category === 'security') {
            return self::$cacheSaltCache['security'] ??= md5(
                $this->hashFileMtimes(
                    array_merge(
                        config('artican.scan_paths', [app_path(), resource_path('views')]),
                        (array) config('view.paths', []),
                        [config_path(), base_path('.env'), base_path('bootstrap/app.php')]
                    )
                ) . serialize([config('app.env'), config('app.debug')])
            );
        }

        if (! isset(self::$cacheSaltCache['_general'])) {
            self::$cacheSaltCache['_general'] = $this->hashFileMtimes(
                array_merge(config('artican.scan_paths', [app_path(), resource_path('views')]), [config_path()])
            );
        }

        return self::$cacheSaltCache['_general'];
    }

    private function hashFileMtimes(array $paths): string
    {
        $mtimes = [];

        foreach ($paths as $path) {
            if (is_file($path)) {
                $mtimes[$path] = filemtime($path);
            } elseif (is_dir($path)) {
                $files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
                );
                foreach ($files as $file) {
                    if ($file->isFile()) {
                        $mtimes[$file->getRealPath()] = $file->getMTime();
                    }
                }
            }
        }

        return md5(serialize($mtimes));
    }

    private function pad(int $current, int $total): string
    {
        return str_pad((string) $current, strlen((string) $total), ' ', STR_PAD_LEFT);
    }

    private function failOnExitCode(array $results): int
    {
        $failOn = $this->option('fail-on');
        if (!$failOn) {
            return 0;
        }

        $levels = explode(',', $failOn);
        foreach ($results as $result) {
            if (!$result->passed && in_array($result->severity->value, $levels, true)) {
                return 1;
            }
        }

        return 0;
    }
}
