<?php

namespace SajjadHossain\Artican\Checks\Security;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Stmt\Property;
use PhpParser\NodeVisitorAbstract;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\PhpAstCheck;

class CsrfProtectionDisabledCheck extends PhpAstCheck
{
    /** Method in bootstrap/app.php (Laravel 11+) that takes the CSRF `except` list. */
    private const EXCEPT_METHODS = ['validatecsrftokens'];

    private array $scanPaths = [];

    public function withPaths(array $paths): static
    {
        $this->scanPaths = $paths;
        return $this;
    }

    public function name(): string
    {
        return 'CSRF protection disabled for all routes';
    }

    public function category(): string
    {
        return 'security';
    }

    public function severity(): Severity
    {
        return Severity::Error;
    }

    public function run(): CheckResult
    {
        $locations = [];
        // bootstrap/app.php is never part of scan_paths, but Laravel 11+ configures CSRF there.
        $paths = $this->scanPaths ?: array_values(array_unique([
            ...(array) config('artican.scan_paths', [app_path()]),
            base_path('bootstrap/app.php'),
        ]));
        $seen = [];

        foreach ($this->scanPhpFiles($paths) as $file) {
            // CSRF is configured in PHP classes and bootstrap/app.php, never in Blade templates.
            if (str_ends_with($file['path'], '.blade.php') || isset($seen[$file['path']])) {
                continue;
            }
            $seen[$file['path']] = true;

            $stmts = $this->parse($file['content']);
            if ($stmts === null) {
                continue;
            }

            $visitor = new class (self::EXCEPT_METHODS) extends NodeVisitorAbstract {
                public array $lines = [];

                private array $csrfClassStack = [];

                public function __construct(private array $exceptMethods)
                {
                }

                public function leaveNode(Node $node): void
                {
                    if ($node instanceof Node\Stmt\Class_) {
                        array_pop($this->csrfClassStack);
                    }
                }

                public function enterNode(Node $node): void
                {
                    if ($node instanceof Node\Stmt\Class_) {
                        $this->csrfClassStack[] = $this->isCsrfClass($node);
                        return;
                    }

                    // protected $except = ['*'];  (only inside CSRF middleware, not e.g. TrimStrings)
                    if ($node instanceof Property && end($this->csrfClassStack) === true) {
                        foreach ($node->props as $prop) {
                            if ($prop->name->toString() === 'except' && $prop->default !== null && $this->hasWildcard($prop->default)) {
                                $this->lines[] = $prop->getLine();
                            }
                        }
                        return;
                    }

                    // ->validateCsrfTokens(except: ['*']) or VerifyCsrfToken::except(['*'])
                    if (
                        ($node instanceof MethodCall || $node instanceof StaticCall)
                        && $this->isCsrfExceptCall($node)
                    ) {
                        foreach ($node->args as $arg) {
                            if (!$arg instanceof Node\Arg) {
                                continue;
                            }
                            $isExcept = $arg->name === null || $arg->name->toString() === 'except';
                            if ($isExcept && $this->hasWildcard($arg->value)) {
                                $this->lines[] = $node->getLine();
                                return;
                            }
                        }
                    }
                }

                private function isCsrfExceptCall(MethodCall|StaticCall $node): bool
                {
                    if (!$node->name instanceof Node\Identifier) {
                        return false;
                    }

                    $method = strtolower($node->name->toString());

                    if ($node instanceof MethodCall) {
                        return in_array($method, $this->exceptMethods, true);
                    }

                    return $method === 'except'
                        && $node->class instanceof Node\Name
                        && preg_match('/Csrf|Forgery/i', $node->class->getLast()) === 1;
                }

                private function isCsrfClass(Node\Stmt\Class_ $class): bool
                {
                    $names = [$class->name?->toString(), $class->extends?->toString()];

                    foreach ($names as $name) {
                        if ($name !== null && preg_match('/Csrf|Forgery/i', $name)) {
                            return true;
                        }
                    }

                    return false;
                }

                private function hasWildcard(Node $expr): bool
                {
                    if (!$expr instanceof Node\Expr\Array_) {
                        return false;
                    }

                    foreach ($expr->items as $item) {
                        if (
                            $item !== null
                            && $item->value instanceof Node\Scalar\String_
                            && in_array($item->value->value, ['*', '/*'], true)
                        ) {
                            return true;
                        }
                    }

                    return false;
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
                message: 'CSRF protection is not disabled with a wildcard.',
            );
        }

        return new CheckResult(
            check: $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed: false,
            message: sprintf('Found %d CSRF exclusion(s) that match every route.', count($locations)),
            locations: $locations,
            suggestion: 'Exclude only the specific URIs that need it (e.g. webhook endpoints) instead of "*".',
        );
    }
}
