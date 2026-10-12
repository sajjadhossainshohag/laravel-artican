<?php

namespace SajjadHossain\Artican\Checks\Security;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\Cast;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Scalar;
use PhpParser\NodeVisitorAbstract;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\PhpAstCheck;

class RawQueryInterpolationCheck extends PhpAstCheck
{
    /** Query builder methods whose first argument is raw SQL. */
    private const RAW_METHODS = [
        'whereraw',
        'orwhereraw',
        'selectraw',
        'orderbyraw',
        'groupbyraw',
        'havingraw',
        'orhavingraw',
        'fromraw',
    ];

    /** Methods that are raw SQL only when called statically on the DB facade. */
    private const DB_FACADE_METHODS = [
        'raw',
        'select',
        'selectone',
        'statement',
        'unprepared',
        'insert',
        'update',
        'delete',
    ];

    private array $scanPaths = [];

    public function withPaths(array $paths): static
    {
        $this->scanPaths = $paths;
        return $this;
    }

    public function name(): string
    {
        return 'Variable interpolated into raw SQL';
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
        $paths = $this->scanPaths ?: config('artican.scan_paths', [app_path()]);

        foreach ($this->scanPhpFiles($paths) as $file) {
            if (str_ends_with($file['path'], '.blade.php')) {
                continue;
            }

            $stmts = $this->parse($file['content']);
            if ($stmts === null) {
                continue;
            }

            $visitor = new class (self::RAW_METHODS, self::DB_FACADE_METHODS) extends NodeVisitorAbstract {
                public array $lines = [];

                public function __construct(private array $rawMethods, private array $dbMethods)
                {
                }

                public function enterNode(Node $node): void
                {
                    if (!($node instanceof MethodCall || $node instanceof StaticCall)) {
                        return;
                    }

                    if (!$node->name instanceof Node\Identifier) {
                        return;
                    }

                    $method = strtolower($node->name->toString());
                    $isRaw = in_array($method, $this->rawMethods, true)
                        || ($node instanceof StaticCall && $this->isDbFacade($node) && in_array($method, $this->dbMethods, true))
                        || ($node instanceof MethodCall && $node->var instanceof StaticCall && $this->isDbFacade($node->var)
                            && $method !== 'raw' && in_array($method, $this->dbMethods, true)); // DB::connection('x')->select(...)

                    if (!$isRaw) {
                        return;
                    }

                    $first = $node->args[0] ?? null;
                    if (!$first instanceof Arg || $first->name !== null || $first->unpack) {
                        return;
                    }

                    if ($this->isCompound($first->value) && $this->isTainted($first->value)) {
                        $this->lines[] = $node->getLine();
                    }
                }

                private function isDbFacade(StaticCall $node): bool
                {
                    return $node->class instanceof Node\Name && $node->class->getLast() === 'DB';
                }

                /** Only flag SQL assembled in place; a bare variable may be a safe, prebuilt string. */
                private function isCompound(Node $expr): bool
                {
                    if ($expr instanceof Ternary) {
                        return ($expr->if !== null && $this->isCompound($expr->if)) || $this->isCompound($expr->else);
                    }

                    return $expr instanceof Scalar\InterpolatedString
                        || $expr instanceof Concat
                        || ($expr instanceof FuncCall && $this->isFunction($expr, 'sprintf'));
                }

                private function isTainted(Node $expr): bool
                {
                    if (
                        $expr instanceof Scalar\String_
                        || $expr instanceof Scalar\Int_
                        || $expr instanceof Scalar\Float_
                        || $expr instanceof Scalar\MagicConst
                        || $expr instanceof InterpolatedStringPart
                        || $expr instanceof ConstFetch
                        || $expr instanceof ClassConstFetch
                    ) {
                        return false;
                    }

                    if ($expr instanceof Cast\Int_ || $expr instanceof Cast\Double || $expr instanceof Cast\Bool_) {
                        return false;
                    }

                    if ($expr instanceof Scalar\InterpolatedString) {
                        foreach ($expr->parts as $part) {
                            if ($this->isTainted($part)) {
                                return true;
                            }
                        }
                        return false;
                    }

                    if ($expr instanceof Concat) {
                        return $this->isTainted($expr->left) || $this->isTainted($expr->right);
                    }

                    if ($expr instanceof Ternary) {
                        return ($expr->if !== null && $this->isTainted($expr->if)) || $this->isTainted($expr->else);
                    }

                    if ($expr instanceof FuncCall && $this->isFunction($expr, 'sprintf')) {
                        return $this->isSprintfTainted($expr);
                    }

                    if ($expr instanceof FuncCall && $this->isSafeFunction($expr)) {
                        return false;
                    }

                    return true;
                }

                /** Functions whose result cannot carry user-controlled text. */
                private function isSafeFunction(FuncCall $call): bool
                {
                    foreach (['intval', 'floatval', 'count'] as $name) {
                        if ($this->isFunction($call, $name)) {
                            return true;
                        }
                    }

                    // str_repeat('?,', $n)
                    if ($this->isFunction($call, 'str_repeat')) {
                        $first = $call->args[0] ?? null;

                        return $first instanceof Arg && !$this->isTainted($first->value);
                    }

                    // implode(',', array_fill(0, $n, '?'))
                    if ($this->isFunction($call, 'implode') || $this->isFunction($call, 'join')) {
                        $last = $call->args[count($call->args) - 1] ?? null;
                        if (!$last instanceof Arg || !$last->value instanceof FuncCall || !$this->isFunction($last->value, 'array_fill')) {
                            return false;
                        }

                        $value = $last->value->args[2] ?? null;

                        return $value instanceof Arg && !$this->isTainted($value->value);
                    }

                    return false;
                }

                /** A %d/%f/... placeholder can only produce a number, so its argument is safe. */
                private function isSprintfTainted(FuncCall $call): bool
                {
                    $args = $call->args;
                    $format = $args[0] ?? null;

                    if (!$format instanceof Arg || !$format->value instanceof Scalar\String_) {
                        return true;
                    }

                    preg_match_all('/%(?:(\d+)\$)?[-+ 0]*(?:\'.)?\d*(?:\.\d+)?([a-zA-Z%])/', $format->value->value, $matches, PREG_SET_ORDER);

                    $conversions = [];
                    $positional = false;
                    foreach ($matches as $match) {
                        if ($match[2] === '%') {
                            continue;
                        }
                        $positional = $positional || $match[1] !== '';
                        $conversions[] = $match[2];
                    }

                    $numeric = static fn (string $c): bool => str_contains('dfFeEgGuxXob', $c);
                    $values = array_slice($args, 1);

                    if ($positional) {
                        // Argument order is not sequential: safe only if every placeholder is numeric.
                        if (count(array_filter($conversions, static fn ($c) => !$numeric($c))) === 0) {
                            return false;
                        }

                        foreach ($values as $arg) {
                            if (!$arg instanceof Arg || $this->isTainted($arg->value)) {
                                return true;
                            }
                        }

                        return false;
                    }

                    foreach ($values as $index => $arg) {
                        if (!$arg instanceof Arg) {
                            return true;
                        }

                        $conversion = $conversions[$index] ?? null;
                        if ($conversion !== null && $numeric($conversion)) {
                            continue;
                        }

                        if ($this->isTainted($arg->value)) {
                            return true;
                        }
                    }

                    return false;
                }

                private function isFunction(FuncCall $call, string $name): bool
                {
                    return $call->name instanceof Node\Name && strtolower($call->name->getLast()) === $name;
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
                message: 'No variables interpolated into raw SQL.',
            );
        }

        return new CheckResult(
            check: $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed: false,
            message: sprintf('Found %d raw SQL call(s) built from interpolated values (SQL injection risk).', count($locations)),
            locations: $locations,
            suggestion: 'Use "?" placeholders and pass values as bindings, e.g. whereRaw(\'price > ?\', [$price]). Column or direction names must be checked against an allow-list.',
        );
    }
}
