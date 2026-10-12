<?php

namespace SajjadHossain\Artican\Checks\Security;

use PhpParser\Node;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\BinaryOp;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Match_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\NullsafePropertyFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Foreach_;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeFinder;
use PhpParser\NodeVisitorAbstract;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\PhpAstCheck;

class FileUploadWithoutValidationCheck extends PhpAstCheck
{
    private const FILE_WRITE_METHODS = ['store', 'storeas', 'storepublicly', 'storepubliclyas', 'move'];

    private const DISK_WRITE_METHODS = ['putfile', 'putfileas'];

    private const DISK_CONTENT_METHODS = ['put', 'write', 'writestream', 'putstream', 'append', 'prepend', 'copy', 'move'];

    private const PHP_WRITE_FUNCTIONS = ['file_put_contents', 'move_uploaded_file', 'copy', 'rename'];

    private const UPLOAD_METADATA_METHODS = [
        'getclientoriginalname', 'getclientoriginalextension', 'getclientmimetype', 'getmimetype', 'getsize',
        'getclientsize', 'extension', 'guessextension', 'guessclientextension', 'hashname', 'getfilename',
        'getbasename', 'isvalid', 'geterror', 'geterrormessage',
    ];

    private const NON_FILE_RULES = [
        'required', 'nullable', 'sometimes', 'present', 'filled', 'bail', 'array', 'string', 'integer', 'int', 'numeric',
        'boolean', 'bool', 'email', 'url', 'date', 'exists', 'unique', 'in', 'not_in', 'regex', 'alpha', 'alpha_num',
        'alpha_dash', 'uuid', 'json', 'confirmed', 'accepted', 'declined',
    ];

    private const POTENTIAL_WRITE_METHODS = [
        ...self::FILE_WRITE_METHODS,
        ...self::DISK_WRITE_METHODS,
        ...self::DISK_CONTENT_METHODS,
    ];

    private const FILE_SOURCE_METHODS = ['file', 'allfiles'];

    private array $scanPaths = [];

    private ?NodeFinder $nodeFinder = null;

    private array $formRequestCache = [];

    public function withPaths(array $paths): static
    {
        $this->scanPaths = $paths;
        return $this;
    }

    public function name(): string
    {
        return 'Uploaded file stored without validation';
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
        $paths = $this->scanPaths ?: config('artican.scan_paths', [app_path()]);

        foreach ($this->scanPhpFiles($paths) as $file) {
            if (str_ends_with($file['path'], '.blade.php')) {
                continue;
            }

            if (
                preg_match('/(->|::)\s*(store|storeAs|storePublicly|storePubliclyAs|move|putFile|putFileAs)\s*\(/i', $file['content']) !== 1
                && preg_match('/\b(file_put_contents|move_uploaded_file|copy|rename)\s*\(/i', $file['content']) !== 1
                && !(
                    preg_match('/\b(Storage|File)::|->\s*(disk|storage|filesystem|files?)\w*\s*->|\$\w*(disk|storage|filesystem|files?)\w*\s*->/i', $file['content']) === 1
                    && preg_match('/(->|::)\s*(put|write|writeStream|putStream|append|prepend|copy)\s*\(/i', $file['content']) === 1
                )
            ) {
                continue;
            }

            $stmts = $this->parse($file['content']);
            if ($stmts === null) {
                continue;
            }

            $this->formRequestCache = [];

            $visitor = new class extends NodeVisitorAbstract {
                public array $functions = [];

                private int $depth = 0;

                public function enterNode(Node $node): void
                {
                    if (!FileUploadWithoutValidationCheck::isFunctionLikeNode($node)) {
                        return;
                    }

                    if ($this->depth === 0) {
                        $this->functions[] = $node;
                    }

                    $this->depth++;
                }

                public function leaveNode(Node $node): void
                {
                    if (FileUploadWithoutValidationCheck::isFunctionLikeNode($node)) {
                        $this->depth--;
                    }
                }

            };

            $this->traverse($stmts, $visitor);

            $writes = [];
            foreach ($visitor->functions as $function) {
                foreach ($this->analyzeFunction($function, $file['content']) as $write) {
                    $writes[$write['pos']] = $write;
                }
            }

            ksort($writes);

            foreach ($writes as $write) {
                $locations[] = [
                    'file' => $file['path'],
                    'line' => $write['line'],
                    'issue' => 'Upload stored before validation',
                    'value' => $write['what'] . '()',
                ];
            }
        }

        if (empty($locations)) {
            return new CheckResult(
                check: $this->name(),
                category: $this->category(),
                severity: $this->severity(),
                passed: true,
                message: 'No uploaded files are stored without validation.',
            );
        }

        return new CheckResult(
            check: $this->name(),
            category: $this->category(),
            severity: $this->severity(),
            passed: false,
            message: sprintf('Found %d uploaded file(s) stored without validation.', count($locations)),
            locations: $locations,
            suggestion: 'Validate the upload first, e.g. $request->validate([\'file\' => \'required|file|mimes:jpg,png,pdf|max:2048\']), or use a FormRequest. Never trust the client-supplied name or type.',
        );
    }

    private function analyzeFunction(Node $function, string $fileContent): array
    {
        $finder = $this->finder();

        if ($finder->findFirst($function, fn (Node $n) => $this->isPotentialWrite($n)) === null) {
            return [];
        }

        $requestVariables = [];

        foreach ($finder->findInstanceOf($function, Node\Param::class) as $param) {
            if (!$param->var instanceof Variable || !is_string($param->var->name)) {
                continue;
            }

            foreach ($this->typeNames($param->type) as $typeName) {
                if (str_ends_with(basename(str_replace('\\', '/', $typeName)), 'Request')) {
                    $requestVariables[] = $param->var->name;
                }
            }
        }

        $fields = [];
        foreach ($finder->find($function, fn (Node $n) => ($n instanceof MethodCall || $n instanceof NullsafeMethodCall) && $n->name instanceof Node\Identifier) as $call) {
            $first = $call->args[0] ?? null;

            if (
                in_array(strtolower($call->name->toString()), ['hasfile', 'file'], true)
                && $first instanceof Node\Arg
                && $first->value instanceof String_
                && $this->isRequestLike($call->var, $requestVariables)
            ) {
                $fields[] = $first->value->value;
            }
        }

        $validators = [];
        foreach ($finder->findInstanceOf($function, Assign::class) as $assign) {
            if ($assign->var instanceof Variable && is_string($assign->var->name) && $this->isValidator($assign->expr, [], ['content' => $fileContent])) {
                $validators[] = $assign->var->name;
            }
        }

        $openFields = $finder->findFirst($function, function (Node $n) use ($requestVariables): bool {
            if (!($n instanceof MethodCall || $n instanceof NullsafeMethodCall) || !$n->name instanceof Node\Identifier || !$this->isRequestLike($n->var, $requestVariables)) {
                return false;
            }

            $method = strtolower($n->name->toString());
            $first = $n->args[0] ?? null;

            return $method === 'allfiles' || ($method === 'file' && (!$first instanceof Node\Arg || !$first->value instanceof String_));
        }) !== null;

        $context = ['request' => $requestVariables, 'files' => [], 'fields' => $fields, 'openFields' => $openFields, 'validators' => $validators, 'content' => $fileContent];
        $context['files'] = $this->uploadedFileVariables($function->getStmts() ?? [], $finder, $context);

        return $this->analyzeUnit($function, false, $context);
    }

    private function analyzeUnit(Node $function, bool $inheritedValidated, array $context): array
    {
        foreach ($function->getParams() as $param) {
            foreach ($this->typeNames($param->type) as $typeName) {
                if ($this->isFormRequest($typeName, $context['content'])) {
                    return [];
                }
            }
        }

        $lines = [];
        $this->flow($function->getStmts() ?? [], $inheritedValidated, $context, $lines);

        return $lines;
    }

    /** Walks code in execution order, tracking whether the request has definitely been validated by now. */
    private function flow(mixed $node, bool $validated, array $context, array &$lines): bool
    {
        if (is_array($node)) {
            foreach ($node as $child) {
                $validated = $this->flow($child, $validated, $context, $lines);
            }

            return $validated;
        }

        if (!$node instanceof Node) {
            return $validated;
        }

        if (self::isFunctionLikeNode($node)) {
            array_push($lines, ...$this->analyzeUnit($node, $validated, $context));

            return $validated;
        }

        if ($node instanceof Stmt\If_) {
            $validated = $this->flow($node->cond, $validated, $context, $lines);

            // fails()/passes() only guard through the branch taken: the branch where it passed continues validated.
            $guard = $this->validatorGuard($node->cond, $context);
            $thenState = $guard === false ? true : $validated;
            $elseState = $guard === true ? true : $validated;

            $branches = [$this->branch($node->stmts, $thenState, $context, $lines)];

            foreach ($node->elseifs as $elseif) {
                $elseState = $this->flow($elseif->cond, $elseState, $context, $lines);
                $elseifGuard = $this->validatorGuard($elseif->cond, $context);

                $branches[] = $this->branch($elseif->stmts, $elseifGuard === false ? true : $elseState, $context, $lines);

                if ($elseifGuard === true) {
                    $elseState = true;
                }
            }

            $branches[] = $node->else === null
                ? $elseState
                : $this->branch($node->else->stmts, $elseState, $context, $lines);

            return !in_array(false, $branches, true);
        }

        if ($node instanceof Stmt\Foreach_) {
            $validated = $this->flow($node->expr, $validated, $context, $lines);
            $this->flow($node->stmts, $validated, $context, $lines);

            return $validated;
        }

        if ($node instanceof Stmt\For_) {
            $this->flow($node->init, $validated, $context, $lines);
            $validated = $this->flow($node->cond, $validated, $context, $lines);
            $this->flow($node->stmts, $validated, $context, $lines);
            $this->flow($node->loop, $validated, $context, $lines);

            return $validated;
        }

        if ($node instanceof Stmt\While_) {
            $validated = $this->flow($node->cond, $validated, $context, $lines);
            $this->flow($node->stmts, $validated, $context, $lines);

            return $validated;
        }

        if ($node instanceof Stmt\Do_) {
            $validated = $this->flow($node->stmts, $validated, $context, $lines);

            return $this->flow($node->cond, $validated, $context, $lines);
        }

        if ($node instanceof Stmt\Switch_) {
            $validated = $this->flow($node->cond, $validated, $context, $lines);
            $branches = [];
            $hasDefault = false;

            $lastIndex = count($node->cases) - 1;

            foreach ($node->cases as $index => $case) {
                $this->flow($case->cond, $validated, $context, $lines);
                $hasDefault = $hasDefault || $case->cond === null;

                // An empty case falls through to the next one; an empty last case or default is a path that does nothing.
                if ($case->stmts === [] && $index < $lastIndex) {
                    continue;
                }

                $stmts = $case->stmts;
                if (end($stmts) instanceof Stmt\Break_) {
                    array_pop($stmts);
                }

                $branches[] = $this->branch($stmts, $validated, $context, $lines);
            }

            return $hasDefault && $branches !== [] ? !in_array(false, $branches, true) : $validated;
        }

        if ($node instanceof Stmt\TryCatch) {
            // A catch that swallows the failure leaves the request unvalidated.
            $states = [$this->flow($node->stmts, $validated, $context, $lines)];

            foreach ($node->catches as $catch) {
                $states[] = $this->branch($catch->stmts, $validated, $context, $lines);
            }

            $after = !in_array(false, $states, true);

            return $node->finally !== null ? $this->flow($node->finally->stmts, $after, $context, $lines) : $after;
        }

        if ($node instanceof Ternary) {
            $validated = $this->flow($node->cond, $validated, $context, $lines);
            $this->flow($node->if, $validated, $context, $lines);
            $this->flow($node->else, $validated, $context, $lines);

            return $validated;
        }

        if (
            $node instanceof BinaryOp\Coalesce
            || $node instanceof BinaryOp\BooleanAnd
            || $node instanceof BinaryOp\BooleanOr
            || $node instanceof BinaryOp\LogicalAnd
            || $node instanceof BinaryOp\LogicalOr
        ) {
            $validated = $this->flow($node->left, $validated, $context, $lines);
            $this->flow($node->right, $validated, $context, $lines);

            return $validated;
        }

        if ($node instanceof Match_) {
            $validated = $this->flow($node->cond, $validated, $context, $lines);

            foreach ($node->arms as $arm) {
                $this->flow($arm->conds, $validated, $context, $lines);
                $this->flow($arm->body, $validated, $context, $lines);
            }

            return $validated;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $validated = $this->flow($node->$name, $validated, $context, $lines);
        }

        if ($this->isValidationCall($node, $context) || $this->abortsOnInvalid($node, $context)) {
            return true;
        }

        if (!$validated && $this->isUploadWrite($node, $context)) {
            $lines[] = [
                'line' => $node->getLine(),
                'pos' => $node->getStartFilePos(),
                'what' => $node->name instanceof Node\Name ? $node->name->getLast() : ($node->name instanceof Node\Identifier ? $node->name->toString() : 'write'),
            ];
        }

        return $validated;
    }

    private function branch(array $stmts, bool $validated, array $context, array &$lines): bool
    {
        $after = $this->flow($stmts, $validated, $context, $lines);

        return $this->exits($stmts) ? true : $after;
    }

    private function exits(array $stmts): bool
    {
        $last = end($stmts);

        if ($last instanceof Stmt\Return_ || $last instanceof Stmt\Continue_ || $last instanceof Stmt\Break_) {
            return true;
        }

        if (!$last instanceof Stmt\Expression) {
            return false;
        }

        return $last->expr instanceof Node\Expr\Throw_
            || $last->expr instanceof Node\Expr\Exit_
            || ($last->expr instanceof FuncCall && $last->expr->name instanceof Node\Name && strtolower($last->expr->name->getLast()) === 'abort');
    }

    private function isUploadWrite(Node $call, array $context): bool
    {
        if ($call instanceof FuncCall) {
            if (!$call->name instanceof Node\Name || !in_array(strtolower($call->name->getLast()), self::PHP_WRITE_FUNCTIONS, true)) {
                return false;
            }

            $position = strtolower($call->name->getLast()) === 'file_put_contents' ? 1 : 0;

            return $this->argumentHoldsUpload($call->args, $position, $context);
        }

        if (!($call instanceof MethodCall || $call instanceof NullsafeMethodCall || $call instanceof StaticCall) || !$call->name instanceof Node\Identifier) {
            return false;
        }

        $method = strtolower($call->name->toString());

        if (
            ($call instanceof MethodCall || $call instanceof NullsafeMethodCall)
            && in_array($method, self::FILE_WRITE_METHODS, true)
            && $this->isUploadedFile($call->var, $context)
        ) {
            return true;
        }

        if (in_array($method, self::DISK_WRITE_METHODS, true)) {
            foreach ($call->args as $arg) {
                if ($arg instanceof Node\Arg && $this->isUploadedFile($arg->value, $context)) {
                    return true;
                }
            }
        }

        if (in_array($method, self::DISK_CONTENT_METHODS, true) && $this->isFilesystem($call, $context)) {
            return $this->argumentHoldsUpload($call->args, in_array($method, ['copy', 'move'], true) ? 0 : 1, $context);
        }

        return false;
    }

    private function argumentHoldsUpload(array $args, int $position, array $context): bool
    {
        $arg = $args[$position] ?? null;

        return $arg instanceof Node\Arg && $this->holdsUpload($arg->value, $context);
    }

    private function holdsUpload(Node $node, array $context): bool
    {
        if (
            ($node instanceof MethodCall || $node instanceof NullsafeMethodCall)
            && $node->name instanceof Node\Identifier
            && in_array(strtolower($node->name->toString()), self::UPLOAD_METADATA_METHODS, true)
        ) {
            return false;
        }

        if ($this->isUploadedFile($node, $context)) {
            return true;
        }

        foreach ($node->getSubNodeNames() as $name) {
            foreach (is_array($node->$name) ? $node->$name : [$node->$name] as $child) {
                if ($child instanceof Node && $this->holdsUpload($child, $context)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isFacade(Node\Name $name, string $facade, array $context): bool
    {
        $short = $name->getLast();

        // `use App\Models\File;` imports a model, not the facade, even though the short name is the same.
        $imported = preg_match('/^\s*use\s+([\w\\\\]*\\\\)?' . preg_quote($facade, '/') . '\s*;/m', $context['content'], $import) === 1;
        if ($short === $facade && $imported) {
            $namespace = rtrim((string) ($import[1] ?? ''), '\\');

            return $namespace === '' || str_ends_with($namespace, 'Facades');
        }

        if ($short === $facade) {
            return true;
        }

        $fqcn = $this->resolveFqcn($context['content'], $name->toString());

        return $fqcn !== null && str_ends_with($fqcn, '\\Facades\\' . $facade);
    }

    private function isFilesystem(Node $call, array $context): bool
    {
        $root = $call instanceof StaticCall ? $call : $call->var;

        while ($root instanceof MethodCall || $root instanceof NullsafeMethodCall) {
            $root = $root->var;
        }

        if ($root instanceof StaticCall) {
            return $root->class instanceof Node\Name
                && ($this->isFacade($root->class, 'Storage', $context) || $this->isFacade($root->class, 'File', $context));
        }

        $name = match (true) {
            $root instanceof Variable => is_string($root->name) ? $root->name : '',
            $root instanceof PropertyFetch || $root instanceof NullsafePropertyFetch => $root->name instanceof Node\Identifier ? $root->name->toString() : '',
            default => '',
        };

        return preg_match('/^(disk|storage|filesystem|fs)$|[a-z0-9](Disk|Storage|Filesystem)$/', $name) === 1
            || ($root instanceof PropertyFetch && $name === 'files');
    }

    public static function isFunctionLikeNode(Node $node): bool
    {
        return $node instanceof ClassMethod
            || $node instanceof Function_
            || $node instanceof Closure
            || $node instanceof ArrowFunction;
    }

    private function isPotentialWrite(Node $node): bool
    {
        if ($node instanceof FuncCall) {
            return $node->name instanceof Node\Name && in_array(strtolower($node->name->getLast()), self::PHP_WRITE_FUNCTIONS, true);
        }

        return ($node instanceof MethodCall || $node instanceof NullsafeMethodCall || $node instanceof StaticCall)
            && $node->name instanceof Node\Identifier
            && in_array(strtolower($node->name->toString()), self::POTENTIAL_WRITE_METHODS, true);
    }

    private function finder(): NodeFinder
    {
        return $this->nodeFinder ??= new NodeFinder;
    }

    private function isValidationCall(Node $node, array $context): bool
    {
        if (!($node instanceof MethodCall || $node instanceof NullsafeMethodCall || $node instanceof StaticCall) || !$node->name instanceof Node\Identifier) {
            return false;
        }

        $name = $node->name->toString();

        $standard = in_array(strtolower($name), ['validate', 'validatewithbag', 'validatewith'], true);

        // Custom helpers count only when named after the upload or request: validateQuota() says nothing about it.
        $helper = !$standard && preg_match('/^validate(?=[A-Z])\w*(?i:upload|file|image|attachment|document|photo|media|avatar|request|input|data|form)/', $name) === 1;

        if ($node instanceof StaticCall) {
            if (!$node->class instanceof Node\Name) {
                return false;
            }

            $class = $node->class->getLast();

            if ($helper && in_array(strtolower($class), ['self', 'static', 'parent'], true)) {
                foreach ($node->args as $arg) {
                    if ($arg instanceof Node\Arg && ($this->isRequestLike($arg->value, $context['request']) || $this->isUploadedFile($arg->value, $context))) {
                        return true;
                    }
                }
            }

            if ($standard && $class === 'Request') {
                return true;
            }

            return $this->isFacade($node->class, 'Validator', $context)
                && strtolower($name) === 'validate'
                && $this->rulesCoverUploads($node, $context, 1);
        }

        if (in_array(strtolower($name), ['validate', 'validatewithbag', 'validated'], true) && $this->isValidator($node->var, $context['validators'], $context)) {
            $root = $node->var;
            while ($root instanceof MethodCall || $root instanceof NullsafeMethodCall) {
                $root = $root->var;
            }

            return $root instanceof StaticCall ? $this->rulesCoverUploads($root, $context, 1) : true;
        }

        if (!$standard && !$helper) {
            return false;
        }

        if ($helper) {
            foreach ($node->args as $arg) {
                if ($arg instanceof Node\Arg && ($this->isRequestLike($arg->value, $context['request']) || $this->isUploadedFile($arg->value, $context))) {
                    return true;
                }
            }

            return false;
        }

        if ($standard && $this->isRequestLike($node->var, $context['request'])) {
            return $this->rulesCoverUploads($node, $context);
        }

        if ($this->isThis($node->var) && $standard) {
            return $this->rulesCoverUploads($node, $context);
        }

        return false;
    }

    private function rulesCoverUploads(Node $call, array $context, ?int $rulesPosition = null): bool
    {
        $position = $rulesPosition ?? (($call instanceof MethodCall || $call instanceof NullsafeMethodCall) && $call->var instanceof Variable && $call->var->name === 'this' ? 1 : 0);
        $rulesArgument = null;

        foreach ($call->args as $index => $arg) {
            if ($arg instanceof Node\Arg && ($arg->name?->toString() === 'rules' || ($arg->name === null && $index === $position))) {
                $rulesArgument = $arg->value;
                break;
            }
        }

        if (!$rulesArgument instanceof Node\Expr\Array_) {
            return true;
        }

        $rules = $rulesArgument;

        foreach ($rules->items as $item) {
            if ($item === null || !$item->key instanceof String_) {
                return true;
            }

            $key = $item->key->value;
            $isUploadKey = false;
            foreach ($context['fields'] as $field) {
                if ($key === $field || str_starts_with($key, $field . '.')) {
                    $isUploadKey = true;
                    break;
                }
            }

            $names = [];
            if ($item->value instanceof String_) {
                $names = $this->ruleNames($item->value->value);
            } elseif ($item->value instanceof Node\Expr\Array_) {
                foreach ($item->value->items as $inner) {
                    if ($inner !== null && $inner->value instanceof String_) {
                        array_push($names, ...$this->ruleNames($inner->value->value));
                    } else {
                        return true;
                    }
                }
            } else {
                return true;
            }

            // A file rule counts on the upload's own key; on another key only when the field name is not a literal.
            if (
                array_intersect($names, ['file', 'image', 'mimes', 'mimetypes', 'dimensions', 'extensions']) !== []
                && ($isUploadKey || $context['openFields'])
            ) {
                return true;
            }

            if ($isUploadKey && array_diff($names, self::NON_FILE_RULES) !== []) {
                return true;
            }
        }

        return false;
    }

    private function ruleNames(string $rules): array
    {
        return array_values(array_filter(array_map(
            fn (string $rule) => strtolower(trim(explode(':', $rule, 2)[0])),
            explode('|', $rules)
        )));
    }

    private function abortsOnInvalid(Node $node, array $context): bool
    {
        if (!$node instanceof FuncCall || !$node->name instanceof Node\Name) {
            return false;
        }

        $name = strtolower($node->name->getLast());
        $first = $node->args[0] ?? null;

        if (!in_array($name, ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'], true) || !$first instanceof Node\Arg) {
            return false;
        }

        $guard = $this->validatorGuard($first->value, $context);

        return $guard === str_ends_with($name, '_if');
    }

    private function validatorGuard(Node $cond, array $context): ?bool
    {
        if ($cond instanceof Node\Expr\BooleanNot) {
            $inner = $this->validatorGuard($cond->expr, $context);

            return $inner === null ? null : !$inner;
        }

        if ($cond instanceof BinaryOp\BooleanOr || $cond instanceof BinaryOp\LogicalOr) {
            return $this->validatorGuard($cond->left, $context) === true || $this->validatorGuard($cond->right, $context) === true ? true : null;
        }

        if ($cond instanceof BinaryOp\BooleanAnd || $cond instanceof BinaryOp\LogicalAnd) {
            return $this->validatorGuard($cond->left, $context) === false || $this->validatorGuard($cond->right, $context) === false ? false : null;
        }

        if (
            ($cond instanceof MethodCall || $cond instanceof NullsafeMethodCall)
            && $cond->name instanceof Node\Identifier
            && $this->isValidator($cond->var, $context['validators'], $context)
        ) {
            return match (strtolower($cond->name->toString())) {
                'fails' => true,
                'passes' => false,
                default => null,
            };
        }

        return null;
    }

    private function isValidator(Node $expr, array $validatorVariables, array $context): bool
    {
        while ($expr instanceof MethodCall || $expr instanceof NullsafeMethodCall) {
            $expr = $expr->var;
        }

        if ($expr instanceof Variable) {
            return is_string($expr->name) && in_array($expr->name, $validatorVariables, true);
        }

        if ($expr instanceof StaticCall) {
            return $expr->class instanceof Node\Name
                && $this->isFacade($expr->class, 'Validator', $context)
                && $expr->name instanceof Node\Identifier
                && strtolower($expr->name->toString()) === 'make';
        }

        return $expr instanceof FuncCall
            && $expr->name instanceof Node\Name
            && strtolower($expr->name->getLast()) === 'validator';
    }

    private function typeNames(?Node $type): array
    {
        if ($type instanceof Node\Name) {
            return [$type->toString()];
        }

        if ($type instanceof Node\NullableType) {
            return $this->typeNames($type->type);
        }

        if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
            return array_merge(...array_map(fn (Node $t) => $this->typeNames($t), $type->types));
        }

        return [];
    }

    private function isFormRequest(string $typeName, string $fileContent): bool
    {
        return $this->formRequestCache[$typeName] ??= $this->resolveIsFormRequest($typeName, $fileContent);
    }

    private function resolveIsFormRequest(string $typeName, string $fileContent): bool
    {
        $short = basename(str_replace('\\', '/', $typeName));

        if ($short === 'Request') {
            return false;
        }

        if (preg_match('/\bclass\s+' . preg_quote($short, '/') . '\s+extends\s+[\w\\\\]*FormRequest\b/', $fileContent) === 1) {
            return true;
        }

        $fqcn = $this->resolveFqcn($fileContent, $typeName);
        $conventional = str_ends_with($short, 'Request') || str_contains((string) $fqcn, '\\Requests\\');

        if (!$conventional) {
            return false;
        }

        try {
            if ($fqcn !== null && class_exists($fqcn)) {
                return is_subclass_of($fqcn, \Illuminate\Foundation\Http\FormRequest::class);
            }
        } catch (\Throwable) {
        }

        return str_contains((string) $fqcn, '\\Requests\\');
    }

    private function uploadedFileVariables(array $stmts, NodeFinder $finder, array $context): array
    {
        $assigns = $finder->findInstanceOf($stmts, Assign::class);
        $loops = $finder->findInstanceOf($stmts, Foreach_::class);
        $calls = $finder->find($stmts, fn (Node $n) => $n instanceof MethodCall || $n instanceof NullsafeMethodCall || $n instanceof StaticCall || $n instanceof FuncCall);

        do {
            $changed = false;

            foreach ($assigns as $assign) {
                if (
                    $assign->var instanceof Variable
                    && is_string($assign->var->name)
                    && !in_array($assign->var->name, $context['files'], true)
                    && $this->isUploadedFile($assign->expr, $context)
                ) {
                    $context['files'][] = $assign->var->name;
                    $changed = true;
                }
            }

            foreach ($loops as $loop) {
                if (
                    $loop->valueVar instanceof Variable
                    && is_string($loop->valueVar->name)
                    && !in_array($loop->valueVar->name, $context['files'], true)
                    && $this->isUploadedFile($loop->expr, $context)
                ) {
                    $context['files'][] = $loop->valueVar->name;
                    $changed = true;
                }
            }

            foreach ($calls as $call) {
                $closureArgs = [];
                $others = [];

                foreach ($call->args as $arg) {
                    if (!$arg instanceof Node\Arg) {
                        continue;
                    }

                    if ($arg->value instanceof Closure || $arg->value instanceof ArrowFunction) {
                        $closureArgs[] = $arg->value;
                    } else {
                        $others[] = $arg->value;
                    }
                }

                if ($closureArgs === []) {
                    continue;
                }

                if ($call instanceof MethodCall || $call instanceof NullsafeMethodCall) {
                    $others[] = $call->var;
                }

                $feedsUploads = $finder->findFirst($others, fn (Node $n) => $this->isUploadedFile($n, $context)) !== null;

                foreach ($closureArgs as $closure) {
                    $first = $closure->params[0] ?? null;
                    $param = $first && $first->var instanceof Variable && is_string($first->var->name) ? $first->var->name : null;

                    if ($feedsUploads && $param !== null && !in_array($param, $context['files'], true)) {
                        $context['files'][] = $param;
                        $changed = true;
                    }
                }
            }
        } while ($changed);

        return $context['files'];
    }

    private function isUploadedFile(Node $expr, array $context): bool
    {
        if ($expr instanceof Variable) {
            return is_string($expr->name) && ($expr->name === '_FILES' || in_array($expr->name, $context['files'], true));
        }

        if ($expr instanceof ArrayDimFetch) {
            return $this->isUploadedFile($expr->var, $context);
        }

        // Dynamic properties are too generic (store()/move()), so require hasFile('x') or file('x') as evidence.
        if (($expr instanceof PropertyFetch || $expr instanceof NullsafePropertyFetch) && $expr->name instanceof Node\Identifier) {
            return in_array($expr->name->toString(), $context['fields'], true)
                && $this->isRequestLike($expr->var, $context['request']);
        }

        return $this->isFileSource($expr, $context['request']);
    }

    private function isFileSource(Node $expr, array $requestVariables): bool
    {
        if ($expr instanceof StaticCall) {
            return $expr->class instanceof Node\Name
                && $expr->class->getLast() === 'Request'
                && $expr->name instanceof Node\Identifier
                && in_array(strtolower($expr->name->toString()), self::FILE_SOURCE_METHODS, true);
        }

        if (!($expr instanceof MethodCall || $expr instanceof NullsafeMethodCall) || !$expr->name instanceof Node\Identifier) {
            return false;
        }

        return in_array(strtolower($expr->name->toString()), self::FILE_SOURCE_METHODS, true)
            && $this->isRequestLike($expr->var, $requestVariables);
    }

    private function isRequestLike(Node $expr, array $requestVariables): bool
    {
        if ($expr instanceof Variable) {
            return is_string($expr->name)
                && (in_array($expr->name, $requestVariables, true) || preg_match('/^(req|request|r)$/i', $expr->name) === 1);
        }

        if ($expr instanceof PropertyFetch || $expr instanceof NullsafePropertyFetch) {
            return $expr->name instanceof Node\Identifier && strtolower($expr->name->toString()) === 'request';
        }

        return $expr instanceof FuncCall
            && $expr->name instanceof Node\Name
            && strtolower($expr->name->getLast()) === 'request';
    }

    private function isThis(Node $expr): bool
    {
        return $expr instanceof Variable && $expr->name === 'this';
    }
}
