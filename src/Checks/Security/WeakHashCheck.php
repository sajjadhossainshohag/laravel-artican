<?php

namespace SajjadHossain\Artican\Checks\Security;

use PhpParser\Node;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\NullsafePropertyFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\StaticPropertyFetch;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Scalar\String_;
use PhpParser\NodeVisitorAbstract;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\PhpAstCheck;

class WeakHashCheck extends PhpAstCheck
{
    /** Algorithms that are unsuitable for passwords, tokens and secrets. */
    private const WEAK_ALGORITHMS = ['md2', 'md4', 'md5', 'sha1'];

    /** Calls whose string argument names the value being read (request input, config, env, session...). */
    private const INPUT_ACCESSORS = [
        'input', 'get', 'post', 'query', 'old', 'string', 'only', 'pull', 'value', 'cookie', 'header',
        'config', 'env', 'getenv', 'session', 'data_get', 'array_get', 'json', 'route',
        'request', 'validated', 'safe', 'str',
    ];

    private array $scanPaths = [];

    public function withPaths(array $paths): static
    {
        $this->scanPaths = $paths;
        return $this;
    }

    public function name(): string
    {
        return 'Weak hash used for passwords or tokens';
    }

    public function category(): string
    {
        return 'security';
    }

    public function severity(): Severity
    {
        // Judged by names, so a hit is a strong hint rather than proof.
        return Severity::Warning;
    }

    public function run(): CheckResult
    {
        $locations = [];
        $paths = $this->scanPaths ?: config('artican.scan_paths', [app_path()]);

        foreach ($this->scanPhpFiles($paths) as $file) {
            if (str_ends_with($file['path'], '.blade.php')) {
                continue;
            }

            // Cheap prefilter: skip the parse when the file cannot contain a weak hash call.
            if (preg_match('/\b(md5|sha1|hash|md4|md2)\s*\(|[\'"](md5|sha1)[\'"]/i', $file['content']) !== 1) {
                continue;
            }

            $stmts = $this->parse($file['content']);
            if ($stmts === null) {
                continue;
            }

            $visitor = new class (self::WEAK_ALGORITHMS, self::INPUT_ACCESSORS, fn (string $name): ?string => $this->resolveFqcn($file['content'], $name)) extends NodeVisitorAbstract {
                /** @var array<int, array{line: int, function: string}> */
                public array $issues = [];

                /** Weak calls already reported through their assignment or array key. */
                private array $reported = [];

                /** String helpers that pass their input through, so a secret inside them is still the thing hashed. */
                private const TRANSPARENT_FUNCTIONS = [
                    'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'mb_strtolower', 'mb_strtoupper',
                    'strval', 'base64_encode', 'implode', 'join', 'sprintf', 'substr', 'mb_substr', 'str_pad',
                ];

                /** @param \Closure(string): ?string $resolve resolves a class name through this file's imports */
                public function __construct(private array $weakAlgorithms, private array $inputAccessors, private \Closure $resolve)
                {
                }

                /** Ancestors of the node being visited, to see what wraps a weak hash call. */
                private array $stack = [];

                public function leaveNode(Node $node): void
                {
                    array_pop($this->stack);
                }

                public function enterNode(Node $node): void
                {
                    $this->stack[] = $node;

                    // Legacy login code compares a weak hash with the stored value:
                    //   md5($input) === $user->password   /   hash_equals($user->api_token, sha1($raw))
                    if (
                        $node instanceof Node\Expr\BinaryOp\Identical
                        || $node instanceof Node\Expr\BinaryOp\Equal
                        || $node instanceof Node\Expr\BinaryOp\NotIdentical
                        || $node instanceof Node\Expr\BinaryOp\NotEqual
                    ) {
                        $this->checkComparison($node->left, $node->right);
                        $this->checkComparison($node->right, $node->left);
                    } elseif (
                        $node instanceof FuncCall
                        && $node->name instanceof Node\Name
                        && strtolower($node->name->getLast()) === 'hash_equals'
                        && count($node->args) >= 2
                        && $node->args[0] instanceof Node\Arg
                        && $node->args[1] instanceof Node\Arg
                    ) {
                        $this->checkComparison($node->args[0]->value, $node->args[1]->value);
                        $this->checkComparison($node->args[1]->value, $node->args[0]->value);
                    }

                    // $user->password = md5($x);  /  $token = sha1(...);
                    // Also compound forms: $secret .= sha1(...), and pushes: $tokens[] = md5(...)
                    if ($node instanceof Assign || $node instanceof AssignOp) {
                        $this->checkAssignedValue($node->expr, $this->nameOf($node->var));
                        return;
                    }

                    // ['password' => md5($x)]; only a literal key names the target: [$password => md5($row)] is a map.
                    if ($node instanceof ArrayItem && $node->key instanceof String_) {
                        $this->checkAssignedValue($node->value, $this->nameOf($node->key));
                        return;
                    }

                    // User::where('password', md5($input)), $user->tokens()->where('token', sha1($raw)):
                    // a literal column name that is a secret, next to a weak hash of the value to look up.
                    if (
                        ($node instanceof MethodCall || $node instanceof NullsafeMethodCall || $node instanceof StaticCall)
                        && $node->name instanceof Node\Identifier
                        && in_array(strtolower($node->name->toString()), self::LOOKUP_METHODS, true)
                    ) {
                        $this->checkLookup($node->args);
                    }

                    // array_map('md5', $passwords): the weak hash is named as a callable string
                    if (
                        $node instanceof FuncCall
                        && $node->name instanceof Node\Name
                        && strtolower($node->name->getLast()) === 'array_map'
                        && ($node->args[0] ?? null) instanceof Node\Arg
                        && $node->args[0]->value instanceof String_
                        && in_array(strtolower($node->args[0]->value->value), ['md5', 'sha1'], true)
                        && ($node->args[1] ?? null) instanceof Node\Arg
                        && $this->containsSensitiveName($node->args[1]->value)
                    ) {
                        $this->report($node, strtolower($node->args[0]->value->value) . '()');
                    }

                    // md5($request->password), sha1($user->api_token . 'salt'), ...
                    if ($node instanceof FuncCall) {
                        $function = $this->weakFunction($node);
                        if ($function === null || isset($this->reported[spl_object_id($node)]) || $this->isWrappedByStrongHasher()) {
                            return;
                        }

                        foreach ($node->args as $arg) {
                            if ($arg instanceof Node\Arg && $this->containsSensitiveName($arg->value)) {
                                $this->report($node, $function);
                                return;
                            }
                        }
                    }
                }

                /**
                 * Hash::make(md5($pw)), bcrypt(md5($pw) . $pepper), password_hash(strtolower(sha1($pw))): a strong
                 * hash is applied on top. Walk up through argument lists, concatenations, casts and plain string
                 * helpers; the first call that is not one of those decides.
                 */
                private function isWrappedByStrongHasher(): bool
                {
                    for ($i = count($this->stack) - 2; $i >= 0; $i--) {
                        $ancestor = $this->stack[$i];

                        if (
                            $ancestor instanceof Node\Arg
                            || $ancestor instanceof Node\Expr\BinaryOp\Concat
                            || $ancestor instanceof Node\Expr\BinaryOp\Coalesce
                            || $ancestor instanceof Node\Expr\Cast
                            || $ancestor instanceof Node\Expr\Ternary
                            || $ancestor instanceof Node\Expr\Array_
                            || $ancestor instanceof ArrayItem
                            || $ancestor instanceof Node\Scalar\InterpolatedString
                        ) {
                            continue;
                        }

                        if ($ancestor instanceof FuncCall && $ancestor->name instanceof Node\Name) {
                            $name = strtolower($ancestor->name->getLast());

                            if (in_array($name, ['bcrypt', 'password_hash'], true)) {
                                return true;
                            }

                            if (in_array($name, self::TRANSPARENT_FUNCTIONS, true)) {
                                continue;
                            }

                            return false;
                        }

                        // Hash::make(...) or Hash::driver('bcrypt')->make(...). Not Hash::check(), which compares, and
                        // not Crypt, which is reversible encryption rather than a hash.
                        if (
                            ($ancestor instanceof StaticCall || $ancestor instanceof MethodCall || $ancestor instanceof NullsafeMethodCall)
                            && $ancestor->name instanceof Node\Identifier
                            && strtolower($ancestor->name->toString()) === 'make'
                        ) {
                            $root = $ancestor;
                            while ($root instanceof MethodCall || $root instanceof NullsafeMethodCall) {
                                $root = $root->var;
                            }

                            // Hash::make(), Hash::driver('bcrypt')->make(), app('hash')->make()
                            if ($root instanceof FuncCall && $root->name instanceof Node\Name && strtolower($root->name->getLast()) === 'app') {
                                $first = $root->args[0] ?? null;

                                return $first instanceof Node\Arg && $first->value instanceof String_ && $first->value->value === 'hash';
                            }

                            // An injected hasher: $this->hasher->make(...), $hasher->make(...)
                            $injected = match (true) {
                                $root instanceof Variable => is_string($root->name) ? $root->name : '',
                                $root instanceof PropertyFetch || $root instanceof NullsafePropertyFetch => $root->name instanceof Node\Identifier ? $root->name->toString() : '',
                                default => '',
                            };

                            if ($injected !== '' && preg_match('/hash/i', $injected) === 1) {
                                return true;
                            }

                            return $root instanceof StaticCall
                                && $root->class instanceof Node\Name
                                && (
                                    strtolower($root->class->getLast()) === 'hash'
                                    || str_ends_with((string) ($this->resolve)($root->class->toString()), '\\Facades\\Hash')
                                );
                        }

                        return false;
                    }

                    return false;
                }

                /** @param array<int, Node\Arg|Node\VariadicPlaceholder> $args */
                private function checkLookup(array $args): void
                {
                    $secretColumn = false;
                    foreach ($args as $arg) {
                        if ($arg instanceof Node\Arg && $arg->value instanceof String_ && $this->isSensitiveTarget($arg->value->value)) {
                            $secretColumn = true;
                        }
                    }

                    if (!$secretColumn) {
                        return;
                    }

                    foreach ($args as $arg) {
                        if ($arg instanceof Node\Arg) {
                            foreach ($this->weakCallsIn($arg->value) as $call) {
                                $this->report($call, $this->weakFunction($call));
                            }
                        }
                    }
                }

                /** A weak hash compared with something that looks like a stored password or token. */
                private function checkComparison(Node $hashed, Node $other): void
                {
                    $calls = $this->weakCallsIn($hashed);

                    if ($calls !== [] && $this->containsSensitiveName($other)) {
                        foreach ($calls as $call) {
                            $this->report($call, $this->weakFunction($call));
                        }
                    }
                }

                /** A weak hash that ends up in a password/token/secret target is a finding. */
                private function checkAssignedValue(Node $value, ?string $targetName): void
                {
                    if ($targetName === null || !$this->isSensitiveTarget($targetName)) {
                        return;
                    }

                    // $token = md5(uniqid()) . 'x';  $token = strtoupper(sha1(...));
                    foreach ($this->weakCallsIn($value) as $call) {
                        $this->report($call, $this->weakFunction($call));
                    }
                }

                /**
                 * Weak hash calls whose result is what gets stored: not ones passed into another call such as
                 * Hash::make(md5($pw)), which a stronger function then wraps. String helpers are looked through.
                 *
                 * @return FuncCall[]
                 */
                private function weakCallsIn(Node $node): array
                {
                    if ($node instanceof FuncCall) {
                        if ($this->weakFunction($node) !== null) {
                            return [$node];
                        }

                        $name = $node->name instanceof Node\Name ? strtolower($node->name->getLast()) : null;
                        if ($name === null || !in_array($name, self::TRANSPARENT_FUNCTIONS, true)) {
                            return [];
                        }
                    }

                    if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall || $node instanceof StaticCall || $node instanceof Closure || $node instanceof ArrowFunction) {
                        return [];
                    }

                    $found = [];

                    foreach ($node->getSubNodeNames() as $sub) {
                        $child = $node->$sub;
                        foreach (is_array($child) ? $child : [$child] as $item) {
                            if ($item instanceof Node) {
                                array_push($found, ...$this->weakCallsIn($item));
                            }
                        }
                    }

                    return $found;
                }

                private function report(FuncCall $call, string $function): void
                {
                    if (isset($this->reported[spl_object_id($call)])) {
                        return;
                    }

                    $this->reported[spl_object_id($call)] = true;
                    $this->markNestedAsReported($call);
                    $this->issues[] = ['line' => $call->getLine(), 'function' => $function];
                }

                /** md5(md5($password)) is one finding, not two; separate hashes on one line are still separate. */
                private function markNestedAsReported(Node $node): void
                {
                    foreach ($node->getSubNodeNames() as $sub) {
                        $child = $node->$sub;

                        foreach (is_array($child) ? $child : [$child] as $item) {
                            if (!$item instanceof Node) {
                                continue;
                            }

                            if ($item instanceof FuncCall && $this->weakFunction($item) !== null) {
                                $this->reported[spl_object_id($item)] = true;
                            }

                            $this->markNestedAsReported($item);
                        }
                    }
                }

                /** md5(), sha1() or hash('md5'|'sha1', ...): returns the display name, or null. */
                private function weakFunction(FuncCall $call): ?string
                {
                    // md5(...) is a first-class callable: nothing is hashed.
                    if (!$call->name instanceof Node\Name || $call->isFirstClassCallable()) {
                        return null;
                    }

                    $name = strtolower($call->name->getLast());

                    if ($name === 'md5' || $name === 'sha1') {
                        return $name . '()';
                    }

                    if ($name === 'hash') {
                        $first = null;
                        foreach ($call->args as $position => $arg) {
                            if ($arg instanceof Node\Arg && ($arg->name?->toString() === 'algo' || ($arg->name === null && $position === 0))) {
                                $first = $arg;
                                break;
                            }
                        }

                        if (
                            $first instanceof Node\Arg
                            && $first->value instanceof String_
                            && in_array(strtolower($first->value->value), $this->weakAlgorithms, true)
                        ) {
                            return "hash('" . strtolower($first->value->value) . "')";
                        }
                    }

                    return null;
                }

                /** Name of a variable, property, array key or literal key, if it has one. */
                private function nameOf(Node $node): ?string
                {
                    return match (true) {
                        $node instanceof Variable => is_string($node->name) ? $node->name : null,
                        $node instanceof PropertyFetch,
                        $node instanceof NullsafePropertyFetch,
                        $node instanceof StaticPropertyFetch => $node->name instanceof Node\Identifier || $node->name instanceof Node\VarLikeIdentifier
                            ? $node->name->toString()
                            : null,
                        $node instanceof ArrayDimFetch => $node->dim instanceof String_ ? $node->dim->value : $this->nameOf($node->var),
                        $node instanceof String_ => $node->value,
                        default => null,
                    };
                }

                /** Does anything inside the expression look like a password/token/secret? */
                private function containsSensitiveName(Node $expr): bool
                {
                    $candidates = [];
                    $this->collectNames($expr, $candidates);

                    foreach ($candidates as $candidate) {
                        if ($this->isSensitiveTarget($candidate)) {
                            return true;
                        }
                    }

                    return false;
                }

                /** @param string[] $candidates names found in the expression, appended to */
                private function collectNames(Node $node, array &$candidates): void
                {
                    if ($node instanceof Variable || $node instanceof PropertyFetch || $node instanceof NullsafePropertyFetch || $node instanceof StaticPropertyFetch) {
                        // Only the leaf names the value: md5($user->token->email) hashes an email, not a token.
                        $name = $this->nameOf($node);
                        if ($name !== null) {
                            $candidates[] = $name;
                        }

                        return;
                    } elseif ($node instanceof ArrayDimFetch && $node->dim instanceof String_) {
                        // $data['password'], and $tokens['a']: the key and the array both say what is held.
                        $candidates[] = $node->dim->value;
                    } elseif (
                        ($node instanceof MethodCall || $node instanceof NullsafeMethodCall || $node instanceof StaticCall || $node instanceof FuncCall)
                        && ($node->name instanceof Node\Identifier || $node->name instanceof Node\Name)
                    ) {
                        // $request->input('password'), $user->getPassword(), csrf_token(), config('app.key')
                        $callName = $node instanceof FuncCall ? $node->name->getLast() : $node->name->toString();
                        $candidates[] = $callName;

                        // A string argument names the value being read only for input/config accessors:
                        // input('password') counts, __('Password reset') does not.
                        if (in_array(strtolower($callName), $this->inputAccessors, true)) {
                            foreach ($node->args as $arg) {
                                if ($arg instanceof Node\Arg && $arg->value instanceof String_) {
                                    $candidates[] = $arg->value->value;
                                }
                            }
                        }

                        // Do not look inside arbitrary calls: md5(json_encode($tokens)) hashes a derived value,
                        // not a secret. Only follow the receiver ($password->toString()) and plain string helpers.
                        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
                            $this->collectNames($node->var, $candidates);
                        } elseif ($node instanceof FuncCall && in_array(strtolower($callName), self::TRANSPARENT_FUNCTIONS, true)) {
                            foreach ($node->args as $arg) {
                                if ($arg instanceof Node\Arg) {
                                    $this->collectNames($arg->value, $candidates);
                                }
                            }
                        }

                        return;
                    }

                    foreach ($node->getSubNodeNames() as $sub) {
                        $child = $node->$sub;

                        foreach (is_array($child) ? $child : [$child] as $item) {
                            if ($item instanceof Node) {
                                $this->collectNames($item, $candidates);
                            }
                        }
                    }
                }

                /** A name like "token_id" or "password_count" is about a secret, not the secret itself. */
                private const NON_SECRET_SUFFIXES = [
                    'key', 'keys', 'id', 'ids', 'count', 'name', 'names', 'type', 'length', 'len', 'url', 'path',
                    'expires', 'expiry', 'at', 'ttl', 'cache', 'prefix', 'field', 'column', 'label', 'index',
                ];

                /** Query-builder methods that look a row up by column and value: where('password', md5($x)). */
                private const LOOKUP_METHODS = [
                    'where', 'orwhere', 'firstwhere', 'wherenot', 'orwherenot', 'wherein', 'having', 'orhaving',
                    'updateorcreate', 'firstorcreate', 'firstornew',
                ];

                private const SENSITIVE_WORDS = 'passwords?|passwds?|passphrases?|pwds?|secrets?|secret_?keys?|private_?keys?|signing_?keys?|encryption_?keys?|tokens?|api_?keys?|app_keys?|credentials?';

                
                /**
                 * Is this name a secret itself ("password", "remember_token", "user_password_hash", "userPassword",
                 * "client-secret") rather than something about one ("token_id", "cache_token_key", "password_count")?
                 * "bypass" and "passport" are not secrets. Used for hashed values and assignment targets alike.
                 */
                private function isSensitiveTarget(string $name): bool
                {
                    $snake = $this->snake($name);

                    // "password", "remember_token", "user_password_hash", "api_key", "pass", "user_pass"
                    if (preg_match('/(^|_)(' . self::SENSITIVE_WORDS . '|pass)(_(hash|hashed|digest|value))?$/', $snake) === 1) {
                        return true;
                    }

                    // "password_reset", "secret_code", "api_key_hex": the secret word is a segment, and the name does
                    // not end in a word that says it is only about the secret ("token_id", "cache_token_key").
                    $segments = explode('_', $snake);

                    return preg_match('/(^|_)(' . self::SENSITIVE_WORDS . ')(_|$)/', $snake) === 1
                        && !in_array(end($segments), self::NON_SECRET_SUFFIXES, true);
                }

                private function snake(string $name): string
                {
                    // userPassword -> user_password, APIToken -> api_token, userAPISecret -> user_api_secret
                    $spaced = preg_replace('/(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/', '_', $name);

                    return preg_replace('/[^a-z0-9]+/', '_', strtolower($spaced));
                }
            };

            $this->traverse($stmts, $visitor);

            foreach ($visitor->issues as $issue) {
                $locations[] = [
                    'file' => $file['path'],
                    'line' => $issue['line'],
                    'issue' => 'Weak hash',
                    'value' => $issue['function'],
                ];
            }
        }

        if (empty($locations)) {
            return new CheckResult(
                check: $this->name(),
                category: $this->category(),
                severity: $this->severity(),
                passed: true,
                message: 'No weak hashing of passwords or tokens detected.',
            );
        }

        return new CheckResult(
            check: $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed: false,
            message: sprintf('Found %d use(s) of md5()/sha1() on passwords, tokens or secrets.', count($locations)),
            locations: $locations,
            suggestion: 'Hash passwords with Hash::make() (bcrypt/argon2) and generate tokens with Str::random() or random_bytes(). md5 and sha1 are fast to brute-force and are not safe for secrets.',
        );
    }
}
