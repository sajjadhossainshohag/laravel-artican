<?php

namespace SajjadHossain\Artican\Checks\Security;

use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\PhpAstCheck;

class UnescapedBladeOutputCheck extends PhpAstCheck
{
    private const SAFE_PATTERNS = [
        '/^\$slot$/',
        '/^csrf_field\(\s*\)$/',
        '/^method_field\([^()]*\)$/',
    ];

    private array $scanPaths = [];

    public function withPaths(array $paths): static
    {
        $this->scanPaths = $paths;
        return $this;
    }

    public function name(): string
    {
        return 'Unescaped Blade output';
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
        // Templates can live in the view paths or in any scanned path (modules, packages).
        $paths = $this->scanPaths ?: array_values(array_unique([
            ...(array) config('view.paths', [resource_path('views')]),
            ...(array) config('artican.scan_paths', []),
        ]));
        $seen = [];

        foreach ($this->scanPhpFiles($paths) as $file) {
            if (!str_ends_with($file['path'], '.blade.php') || isset($seen[$file['path']])) {
                continue;
            }
            $seen[$file['path']] = true;

            $content = $this->blankOut($file['content']);

            if (!preg_match_all('/(?<!@)\{!!(.*?)!!\}/s', $content, $matches, PREG_OFFSET_CAPTURE)) {
                continue;
            }

            foreach ($matches[1] as [$expression, $offset]) {
                if ($this->isTrusted(trim($expression))) {
                    continue;
                }

                $locations[] = [
                    'file' => $file['path'],
                    'line' => substr_count(substr($content, 0, $offset), "\n") + 1,
                ];
            }
        }

        if (empty($locations)) {
            return new CheckResult(
                check: $this->name(),
                category: $this->category(),
                severity: $this->severity(),
                passed: true,
                message: 'No unescaped Blade output found.',
            );
        }

        return new CheckResult(
            check: $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed: false,
            message: sprintf('Found %d unescaped {!! !!} output(s) in Blade templates (XSS risk).', count($locations)),
            locations: $locations,
            suggestion: 'Use {{ }} so the value is escaped. Only use {!! !!} for HTML you generate yourself or have sanitized.',
        );
    }

    private function blankOut(string $content): string
    {
        $blank = static fn (array $m): string => str_repeat("\n", substr_count($m[0], "\n"));

        $content = preg_replace_callback('/\{\{--.*?--\}\}/s', $blank, $content);

        return preg_replace_callback('/@verbatim.*?@endverbatim/s', $blank, $content);
    }

    private function isTrusted(string $expression): bool
    {
        if (preg_match('/^(\'[^\']*\'|"[^"$\{]*")$/', $expression)) {
            return true;
        }

        foreach (self::SAFE_PATTERNS as $pattern) {
            if (preg_match($pattern, $expression)) {
                return true;
            }
        }

        return false;
    }
}
