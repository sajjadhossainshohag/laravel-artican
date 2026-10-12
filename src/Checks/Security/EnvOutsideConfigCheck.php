<?php

namespace SajjadHossain\Artican\Checks\Security;

use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\NodeVisitorAbstract;
use SajjadHossain\Artican\BladeAstCheck;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;

class EnvOutsideConfigCheck extends BladeAstCheck
{
    private array $scanPaths = [];

    private ?string $configPath = null;

    public function withPaths(array $paths): static
    {
        $this->scanPaths = $paths;
        return $this;
    }

    public function withConfigPath(string $path): static
    {
        $this->configPath = $path;
        return $this;
    }

    public function name(): string
    {
        return 'env() called outside config files';
    }

    public function category(): string
    {
        return 'security';
    }

    public function severity(): Severity
    {
        return Severity::Warning;
    }

    public function run(): CheckResult
    {
        $locations = [];
        $paths = $this->scanPaths ?: config('artican.scan_paths', [app_path(), resource_path('views')]);
        $configDir = $this->normalize($this->configPath ?? config_path());

        foreach ($this->scanPhpFiles($paths) as $file) {
            if ($this->isInside($file['path'], $configDir)) {
                continue;
            }

            $stmts = str_ends_with($file['path'], '.blade.php')
                ? $this->parseBlade($file['content']) // the Blade compiler already drops {{-- --}} comments
                : $this->parse($file['content']);

            if ($stmts === null) {
                continue;
            }

            $visitor = new class extends NodeVisitorAbstract {
                public array $lines = [];

                public function enterNode(Node $node): void
                {
                    if (
                        $node instanceof FuncCall
                        && $node->name instanceof Node\Name
                        && strtolower($node->name->getLast()) === 'env'
                    ) {
                        $this->lines[] = $node->getLine();
                    }
                }
            };

            $this->traverse($stmts, $visitor);

            foreach ($visitor->lines as $line) {
                $locations[] = ['file' => $file['path'], 'line' => $line];
            }
        }

        if (empty($locations)) {
            return new CheckResult(
                check: $this->name(),
                category: $this->category(),
                severity: $this->severity(),
                passed: true,
                message: 'No env() calls found outside config files.',
            );
        }

        return new CheckResult(
            check: $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed: false,
            message: sprintf('Found %d env() call(s) outside config files.', count($locations)),
            locations: $locations,
            suggestion: 'Read the value in a config file (e.g. config/services.php) and use config(\'...\') in application code. env() returns null once "php artisan config:cache" is run.',
        );
    }

    private function normalize(string $path): string
    {
        $real = realpath($path);

        return rtrim(str_replace('\\', '/', $real !== false ? $real : $path), '/');
    }

    private function isInside(string $file, string $dir): bool
    {
        return str_starts_with(str_replace('\\', '/', $file), $dir . '/');
    }
}
