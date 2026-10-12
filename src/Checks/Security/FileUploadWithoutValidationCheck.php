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
    /** Methods on an uploaded file that write it to disk. */
    private const FILE_WRITE_METHODS = ['store', 'storeas', 'storepublicly', 'storepubliclyas', 'move'];

    /** Filesystem methods that take an uploaded file as an argument. */
    private const DISK_WRITE_METHODS = ['putfile', 'putfileas'];

    /** Filesystem methods that write whatever content they are given, e.g. Storage::put($path, $upload). */
    private const DISK_CONTENT_METHODS = ['put', 'write', 'writestream', 'putstream', 'append', 'prepend', 'copy', 'move'];

    /** Plain PHP functions that persist data; flagged when an uploaded file feeds them. */
    private const PHP_WRITE_FUNCTIONS = ['file_put_contents', 'move_uploaded_file', 'copy', 'rename'];

    /** Every method name that may write an upload; the precise test (is the argument an upload?) comes later. */
    /** Methods that read facts about an upload without touching its content. */
    private const UPLOAD_METADATA_METHODS = [
        'getclientoriginalname', 'getclientoriginalextension', 'getclientmimetype', 'getmimetype', 'getsize',
        'getclientsize', 'extension', 'guessextension', 'guessclientextension', 'hashname', 'getfilename',
        'getbasename', 'isvalid', 'geterror', 'geterrormessage',
    ];

    /** Rules that say nothing about an upload: presence and plain-type checks. Anything else (max, size, a custom rule) constrains it. */
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

    /** Request methods that return uploaded file(s). */
    private const FILE_SOURCE_METHODS = ['file', 'allfiles'];

    private array $scanPaths = [];

    private ?NodeFinder $nodeFinder = null;

    /** @var array<string, bool> memoized isFormRequest() answers for the file being analysed, keyed by type name */
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

            // Cheap prefilter: nothing to report unless the file writes a file somewhere.
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
                /** @var Node[] outermost functions, methods and closures */
                public array $functions = [];

                private int $depth = 0;

                public function enterNode(Node $node): void
                {
                    if (!FileUploadWithoutValidationCheck::isFunctionLikeNode($node)) {
                        return;
                    }

                    // Nested closures are analysed as part of their outermost function.
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

            // Keyed by file offset, so two writes on one line are two findings (and one write is never counted twice).
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

    /** Lines of upload writes in an outermost function (and the closures inside it) that can run before validation. */
    private function analyzeFunction(Node $function, string $fileContent): array
    {
        $finder = $this->finder();

        // Nothing to report in a function that never writes a file.
        if ($finder->findFirst($function, fn (Node $n) => $this->isPotentialWrite($n)) === null) {
            return [];
        }

        $requestVariables = [];

        // Request-typed parameters anywhere in the function, including nested closures (`function (Request $req)`).
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

        // Input names the code treats as file inputs: hasFile('photo'), file('photo').
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

        // request: names of request variables; files: variables holding uploads; fields: upload input names
        // seen in hasFile()/file() calls; validators: variables holding a validator; content: the file source.
        // $validator = Validator::make(...): later $validator->fails()/validate() enforce validation.
        $validators = [];
        foreach ($finder->findInstanceOf($function, Assign::class) as $assign) {
            if ($assign->var instanceof Variable && is_string($assign->var->name) && $this->isValidator($assign->expr, [], ['content' => $fileContent])) {
                $validators[] = $assign->var->name;
            }
        }

        // Uploads whose input name is not a literal (allFiles(), file($field)): rules cannot be matched to them by key.
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

    /** One function body in execution order; nested closures are analysed in turn with the state at their definition. */
    private function analyzeUnit(Node $function, bool $inheritedValidated, array $context): array
    {
        // A FormRequest parameter validates before the function runs.
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

    /**
     * Walk code in execution order, tracking whether the request has definitely been validated by now.
     * Returns the "validated" state after $node. Writes made while not validated are added to $lines.
     *
     * Branches are analysed with the state at their start; after an if/else the request counts as
     * validated only if every branch (that does not return or throw) validated it.
     */
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

            // `if ($validator->fails()) { return ...; }`: fails()/passes() only enforce anything through the
            // branch that is taken. The branch where the check passed continues as validated; the other one is
            // handled as usual, so it only helps if it exits.
            $guard = $this->validatorGuard($node->cond, $context);
            $thenState = $guard === false ? true : $validated;
            $elseState = $guard === true ? true : $validated;

            $branches = [$this->branch($node->stmts, $thenState, $context, $lines)];

            foreach ($node->elseifs as $elseif) {
                // Reached only when the conditions above were false, so `elseif ($v->fails()) { return; }` is a guard too.
                $elseState = $this->flow($elseif->cond, $elseState, $context, $lines);
                $elseifGuard = $this->validatorGuard($elseif->cond, $context);

                $branches[] = $this->branch($elseif->stmts, $elseifGuard === false ? true : $elseState, $context, $lines);

                if ($elseifGuard === true) {
                    $elseState = true;
                }
            }

            // Without an else, the implicit "condition was false" path continues with the else state.
            $branches[] = $node->else === null
                ? $elseState
                : $this->branch($node->else->stmts, $elseState, $context, $lines);

            return !in_array(false, $branches, true);
        }

        if ($node instanceof Stmt\Foreach_) {
            $validated = $this->flow($node->expr, $validated, $context, $lines);
            $this->flow($node->stmts, $validated, $context, $lines);

            return $validated; // the loop body may run zero times
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

                // `case 'a': case 'b': ...` : an empty case shares the code of the case below it. An empty LAST
                // case (or `default:`) shares nothing: it is a path that does nothing, validated or not.
                if ($case->stmts === [] && $index < $lastIndex) {
                    continue;
                }

                // A trailing `break` only leaves the switch, so the code after it still runs.
                $stmts = $case->stmts;
                if (end($stmts) instanceof Stmt\Break_) {
                    array_pop($stmts);
                }

                $branches[] = $this->branch($stmts, $validated, $context, $lines);
            }

            // Validated afterwards only if some case always runs (there is a default) and every case validated.
            return $hasDefault && $branches !== [] ? !in_array(false, $branches, true) : $validated;
        }

        if ($node instanceof Stmt\TryCatch) {
            // After try/catch the request is validated only if the try body validated it and every catch
            // that continues did too: a catch that swallows the failure leaves the request unvalidated.
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
            // The right operand only runs sometimes.
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

        // Everything else runs its children first (arguments, receivers), then the node itself.
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

    /** State after a branch; a branch that returns or throws never continues, so it cannot weaken the result. */
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

        // throw, exit/die, abort(403)
        return $last->expr instanceof Node\Expr\Throw_
            || $last->expr instanceof Node\Expr\Exit_
            || ($last->expr instanceof FuncCall && $last->expr->name instanceof Node\Name && strtolower($last->expr->name->getLast()) === 'abort');
    }

    private function isUploadWrite(Node $call, array $context): bool
    {
        // file_put_contents(storage_path($file->getClientOriginalName()), $file->get()), move_uploaded_file($_FILES[...]), copy(...)
        if ($call instanceof FuncCall) {
            if (!$call->name instanceof Node\Name || !in_array(strtolower($call->name->getLast()), self::PHP_WRITE_FUNCTIONS, true)) {
                return false;
            }

            // file_put_contents($path, $data): the data. copy($from, $to), rename(...), move_uploaded_file($from, ...): the source.
            $position = strtolower($call->name->getLast()) === 'file_put_contents' ? 1 : 0;

            return $this->argumentHoldsUpload($call->args, $position, $context);
        }

        if (!($call instanceof MethodCall || $call instanceof NullsafeMethodCall || $call instanceof StaticCall) || !$call->name instanceof Node\Identifier) {
            return false;
        }

        $method = strtolower($call->name->toString());

        // $request->file('x')->store(...)  /  $request->photo->store(...)  /  $file->move(...)
        if (
            ($call instanceof MethodCall || $call instanceof NullsafeMethodCall)
            && in_array($method, self::FILE_WRITE_METHODS, true)
            && $this->isUploadedFile($call->var, $context)
        ) {
            return true;
        }

        // Storage::putFile('dir', $file)  /  Storage::disk('s3')->putFileAs('dir', $file, 'name')
        if (in_array($method, self::DISK_WRITE_METHODS, true)) {
            foreach ($call->args as $arg) {
                if ($arg instanceof Node\Arg && $this->isUploadedFile($arg->value, $context)) {
                    return true;
                }
            }
        }

        // Storage::disk('public')->put('x/' . $file->getClientOriginalName(), file_get_contents($upload))
        if (in_array($method, self::DISK_CONTENT_METHODS, true) && $this->isFilesystem($call, $context)) {
            // put($path, $contents): the contents. copy($from, $to) / move($from, $to): the source.
            return $this->argumentHoldsUpload($call->args, in_array($method, ['copy', 'move'], true) ? 0 : 1, $context);
        }

        return false;
    }

    /**
     * Does the argument at $position carry the upload itself (the file, its contents, its path)? Calls that only
     * read metadata, such as `$file->getClientOriginalName()`, do not: logging a file name is not storing the file.
     *
     * @param array<int, Node\Arg|Node\VariadicPlaceholder> $args
     */
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

    /** The Storage / File facade, also under an alias (`use Illuminate\Support\Facades\Storage as Disk;`). */
    private function isFacade(Node\Name $name, string $facade, array $context): bool
    {
        $short = $name->getLast();

        // `use App\Models\File;` imports a model, not the facade, even though the short name is the same.
        $imported = preg_match('/^\s*use\s+([\w\\\\]*\\\\)?' . preg_quote($facade, '/') . '\s*;/m', $context['content'], $import) === 1;
        if ($short === $facade && $imported) {
            $namespace = rtrim((string) ($import[1] ?? ''), '\\');

            // `use Storage;` is the global alias; `use Illuminate\Support\Facades\Storage;` the facade itself.
            return $namespace === '' || str_ends_with($namespace, 'Facades');
        }

        if ($short === $facade) {
            return true; // the global alias (\Storage, \File) or the same file declares nothing else under that name
        }

        $fqcn = $this->resolveFqcn($context['content'], $name->toString());

        return $fqcn !== null && str_ends_with($fqcn, '\\Facades\\' . $facade);
    }

    /** Storage::..., Storage::disk()->..., or a variable that looks like a disk ($disk, $storage, $filesystem, $this->files). */
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

        // $disk, $this->disk, $this->storage, $filesystem
        $name = match (true) {
            $root instanceof Variable => is_string($root->name) ? $root->name : '',
            $root instanceof PropertyFetch || $root instanceof NullsafePropertyFetch => $root->name instanceof Node\Identifier ? $root->name->toString() : '',
            default => '',
        };

        // $disk, $storage, $filesystem, $fs, $publicDisk, $s3Storage; and, as a property only, $this->files.
        // Not $storageManager or $file: any object with those words in its name is not a disk.
        return preg_match('/^(disk|storage|filesystem|fs)$|[a-z0-9](Disk|Storage|Filesystem)$/', $name) === 1
            || ($root instanceof PropertyFetch && $name === 'files');
    }

    /** Methods, functions, closures and arrow functions: the units this check analyses. */
    public static function isFunctionLikeNode(Node $node): bool
    {
        return $node instanceof ClassMethod
            || $node instanceof Function_
            || $node instanceof Closure
            || $node instanceof ArrowFunction;
    }

    /** A call that could write a file; the precise test (is it an upload?) comes later. */
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

    /**
     * A call that actually enforces validation: $request->validate(), $this->validate($request, ...),
     * Validator::make(...)->validate(), $validator->validate() for a validator built earlier. Building a
     * validator enforces nothing, and fails()/passes() only enforce through the branch taken (see validatorGuard()).
     */
    private function isValidationCall(Node $node, array $context): bool
    {
        if (!($node instanceof MethodCall || $node instanceof NullsafeMethodCall || $node instanceof StaticCall) || !$node->name instanceof Node\Identifier) {
            return false;
        }

        $name = $node->name->toString();

        // The framework's own methods: validate(), validateWithBag(), validateWith().
        $standard = in_array(strtolower($name), ['validate', 'validatewithbag', 'validatewith'], true);

        // A custom controller helper such as validateUpload($request) or validateAvatarFile($request): camelCase
        // after "validate" and a word that says it is about the request or its upload. validateQuota(),
        // validateOwnership(), validateSignature() and validatedData() say nothing about the upload.
        $helper = !$standard && preg_match('/^validate(?=[A-Z])\w*(?i:upload|file|image|attachment|document|photo|media|avatar|request|input|data|form)/', $name) === 1;

        if ($node instanceof StaticCall) {
            if (!$node->class instanceof Node\Name) {
                return false;
            }

            $class = $node->class->getLast();

            // self::validateUpload($request), static::validateFile($request): a helper handed the request or upload.
            if ($helper && in_array(strtolower($class), ['self', 'static', 'parent'], true)) {
                foreach ($node->args as $arg) {
                    if ($arg instanceof Node\Arg && ($this->isRequestLike($arg->value, $context['request']) || $this->isUploadedFile($arg->value, $context))) {
                        return true;
                    }
                }
            }

            // Request::validate(...), Validator::validate($data, $rules)
            if ($standard && $class === 'Request') {
                return true;
            }

            return $this->isFacade($node->class, 'Validator', $context)
                && strtolower($name) === 'validate'
                && $this->rulesCoverUploads($node, $context, 1);
        }

        // $validator->validate() / ->validated(), where $validator comes from Validator::make() or validator().
        if (in_array(strtolower($name), ['validate', 'validatewithbag', 'validated'], true) && $this->isValidator($node->var, $context['validators'], $context)) {
            // Validator::make($data, $rules)->validate(): the literal rules must say something about the upload.
            $root = $node->var;
            while ($root instanceof MethodCall || $root instanceof NullsafeMethodCall) {
                $root = $root->var;
            }

            return $root instanceof StaticCall ? $this->rulesCoverUploads($root, $context, 1) : true;
        }

        if (!$standard && !$helper) {
            return false;
        }

        // $validator->validateUpload($request), $this->uploadValidator->validateFile($request): a helper that is
        // handed the request, on whatever object provides it.
        if ($helper) {
            foreach ($node->args as $arg) {
                if ($arg instanceof Node\Arg && ($this->isRequestLike($arg->value, $context['request']) || $this->isUploadedFile($arg->value, $context))) {
                    return true;
                }
            }

            return false;
        }

        // $request->validate(): the receiver is the request.
        if ($standard && $this->isRequestLike($node->var, $context['request'])) {
            return $this->rulesCoverUploads($node, $context);
        }

        // $this->validate($request, ...) is the controller trait. A custom helper such as
        // $this->validateUpload($request) counts only if it is handed the request; $this->validateQuota() or
        // $this->validateOwnership($order) say nothing about the upload.
        if ($this->isThis($node->var) && $standard) {
            return $this->rulesCoverUploads($node, $context);
        }

        return false;
    }

    /**
     * Does a literal rules array in this validate() call say anything about files? True unless the rules are a
     * literal array whose keys are none of the upload fields and whose rules never mention file, image, mimes ...:
     * `$request->validate(['name' => 'required'])` does not validate `$request->file('doc')`.
     * Rules that are not a literal array (a variable, a method call) are given the benefit of the doubt.
     */
    private function rulesCoverUploads(Node $call, array $context, ?int $rulesPosition = null): bool
    {
        // $request->validate($rules, $messages) vs $this->validate($request, $rules, $messages)
        $position = $rulesPosition ?? (($call instanceof MethodCall || $call instanceof NullsafeMethodCall) && $call->var instanceof Variable && $call->var->name === 'this' ? 1 : 0);
        $rulesArgument = null;

        foreach ($call->args as $index => $arg) {
            if ($arg instanceof Node\Arg && ($arg->name?->toString() === 'rules' || ($arg->name === null && $index === $position))) {
                $rulesArgument = $arg->value;
                break;
            }
        }

        if (!$rulesArgument instanceof Node\Expr\Array_) {
            return true; // a variable or method call: cannot tell
        }

        $rules = $rulesArgument;

        foreach ($rules->items as $item) {
            if ($item === null || !$item->key instanceof String_) {
                return true; // dynamic keys: cannot tell
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
                        return true; // Rule::file(), new MyRule(): cannot tell
                    }
                }
            } else {
                return true;
            }

            // A file rule validates the upload on its own key. On another key it only counts when the upload's
            // field name cannot be known (allFiles(), file($field)): `['avatar' => 'image']` does not validate `doc`.
            if (
                array_intersect($names, ['file', 'image', 'mimes', 'mimetypes', 'dimensions', 'extensions']) !== []
                && ($isUploadKey || $context['openFields'])
            ) {
                return true;
            }

            // On the upload's own key, any constraint (max, size, a custom rule) counts; "required" alone does not.
            if ($isUploadKey && array_diff($names, self::NON_FILE_RULES) !== []) {
                return true;
            }
        }

        return false;
    }

    /** @return string[] rule names from "required|mimes:pdf,png|max:2048" => [required, mimes, max] */
    private function ruleNames(string $rules): array
    {
        return array_values(array_filter(array_map(
            fn (string $rule) => strtolower(trim(explode(':', $rule, 2)[0])),
            explode('|', $rules)
        )));
    }

    /** abort_if($validator->fails(), 422) / abort_unless($validator->passes(), 422), and the throw_* equivalents. */
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

        // *_if stops when the condition holds, so the condition must mean "invalid"; *_unless is the reverse.
        return $guard === str_ends_with($name, '_if');
    }

    /**
     * What a condition says about a validator: true if the condition being true means validation FAILED
     * ($v->fails(), !$v->passes()), false if it being true means it PASSED ($v->passes(), !$v->fails()),
     * null if the condition has nothing to do with a validator.
     */
    private function validatorGuard(Node $cond, array $context): ?bool
    {
        if ($cond instanceof Node\Expr\BooleanNot) {
            $inner = $this->validatorGuard($cond->expr, $context);

            return $inner === null ? null : !$inner;
        }

        // `$v->fails() || $x`: when it is false, $v did not fail. `$v->passes() && $x`: when it is true, $v passed.
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

    /** Validator::make(...), validator(...), or a variable assigned from one (through any method chain). */
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

    /**
     * Class names in a parameter type, unwrapping ?Foo, Foo|Bar and Foo&Bar.
     *
     * @return string[]
     */
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
        // The cache is cleared for every file (see run()): the answer depends on that file's `use` imports.
        return $this->formRequestCache[$typeName] ??= $this->resolveIsFormRequest($typeName, $fileContent);
    }

    private function resolveIsFormRequest(string $typeName, string $fileContent): bool
    {
        $short = basename(str_replace('\\', '/', $typeName));

        if ($short === 'Request') {
            return false;
        }

        // This file declares it as a FormRequest.
        if (preg_match('/\bclass\s+' . preg_quote($short, '/') . '\s+extends\s+[\w\\\\]*FormRequest\b/', $fileContent) === 1) {
            return true;
        }

        $fqcn = $this->resolveFqcn($fileContent, $typeName);
        $conventional = str_ends_with($short, 'Request') || str_contains((string) $fqcn, '\\Requests\\');

        // `User $user`, `OrderService $service`: nothing that is worth autoloading during a static scan.
        if (!$conventional) {
            return false;
        }

        try {
            if ($fqcn !== null && class_exists($fqcn)) {
                return is_subclass_of($fqcn, \Illuminate\Foundation\Http\FormRequest::class);
            }
        } catch (\Throwable) {
            // Autoloading failed (e.g. a parent class from an uninstalled package): use the name below.
        }

        // The class cannot be loaded: a FormRequest if it lives in a conventional Requests namespace
        // (App\Http\Requests\StoreFooRequest); a DTO or PSR type that merely ends in "Request" is not.
        return str_contains((string) $fqcn, '\\Requests\\');
    }

    /**
     * Names of variables that hold an uploaded file (or files), including copies, loop items and array elements.
     *
     * @return string[]
     */
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

            // collect($files)->each(fn ($f) => ...), array_map(fn ($f) => ..., $request->file('docs')):
            // the closure's first parameter is one of the uploads.
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
            // $_FILES is raw upload data.
            return is_string($expr->name) && ($expr->name === '_FILES' || in_array($expr->name, $context['files'], true));
        }

        // $files[0], $_FILES['f']['tmp_name']
        if ($expr instanceof ArrayDimFetch) {
            return $this->isUploadedFile($expr->var, $context);
        }

        // $request->photo: Laravel's dynamic input property is the uploaded file for a file input. Generic
        // method names like store()/move() make this risky, so require evidence that "photo" is a file input
        // in this function, i.e. a hasFile('photo') or file('photo') call.
        if (($expr instanceof PropertyFetch || $expr instanceof NullsafePropertyFetch) && $expr->name instanceof Node\Identifier) {
            return in_array($expr->name->toString(), $context['fields'], true)
                && $this->isRequestLike($expr->var, $context['request']);
        }

        return $this->isFileSource($expr, $context['request']);
    }

    /** $request->file('x'), request()->file('x'), Request::file('x'), $request->allFiles() */
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

    /** $request, $this->request, request(): the HTTP request, not e.g. a zip archive or a disk. */
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
