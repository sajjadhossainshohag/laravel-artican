<?php

namespace Fixtures\FileUpload;

use App\Http\Requests\{StoreGroupedRequest, UpdateGroupedRequest as UpdateRequest};
use App\Models\File;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Validator as V;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

class StoreAvatarRequest extends FormRequest
{
}

class FileUploadClean
{
    public function validated(Request $request)
    {
        $request->validate(['avatar' => 'required|image|max:2048']);
        $request->file('avatar')->store('avatars');
    }

    public function formRequest(StoreAvatarRequest $request)
    {
        $request->file('avatar')->store('avatars');
    }

    public function validatorFacade(Request $request)
    {
        Validator::make($request->all(), ['doc' => 'file|mimes:pdf'])->validate();
        $file = $request->file('doc');
        $file->move(public_path('docs'), 'doc.pdf');
    }

    public function validatedByHelper(Request $request)
    {
        $this->validateUpload($request);
        Storage::putFile('docs', $request->file('doc'));
    }

    public function controllerHelperNamedFile()
    {
        // $this->file() is a local helper, not the request.
        $this->file('x')->store('x');
    }

    public function notAnUpload($report, $model, $content)
    {
        $report->store('reports');
        $model->move('a', 'b');
        Storage::put('x', $content);
        Storage::putFile('x', new \Illuminate\Http\File(__FILE__));
    }

    public function controllerValidate(Request $request)
    {
        $this->validate($request, ['doc' => 'file|mimes:pdf']);
        $request->file('doc')->store('docs');
    }

    public function notTheRequest($archive, $order)
    {
        // Only the HTTP request carries uploads; a zip archive or a disk does not.
        $archive->file('inner.txt')->move('a');
        $this->zip->file('x')->store('x');
        $order->validate();
    }

    public function nullableFormRequest(?StoreAvatarRequest $request)
    {
        $request?->file('avatar')->store('avatars');
    }

    public function unionFormRequest(StoreAvatarRequest|Request $request)
    {
        $request->file('avatar')->store('avatars');
    }

    public function nestedClosureValidatesItself()
    {
        return function (Request $req) {
            $req->validate(['f' => 'file']);
            return $req->file('f')->store('x');
        };
    }

    public function missingParentClass(\App\Http\Requests\StoreMissingParentRequest $request)
    {
        // The class cannot be autoloaded, so it is assumed to be a FormRequest by name.
        $request->file('f')->store('x');
    }

    public function closureInheritsValidationThatRanFirst(Request $request, array $ids)
    {
        $request->validate(['f' => 'file|mimes:png']);

        collect($ids)->each(function ($id) use ($request) {
            $request->file('f')->store('x');
        });
    }

    public function validationInsideTryBody(Request $request)
    {
        try {
            $request->validate(['f' => 'file|mimes:png']);
        } catch (\Exception $e) {
            return;
        }

        $request->file('f')->store('x');
    }

    public function validatedDynamicProperty(Request $request)
    {
        $request->validate(['photo' => 'image']);
        $request->photo->store('photos');
    }

    public function validationAndWriteInTheSameBranch(Request $request)
    {
        if ($request->hasFile('avatar')) {
            $request->validate(['avatar' => 'image']);
            $request->file('avatar')->store('avatars');
        }

        foreach ($request->allFiles() as $upload) {
            $request->validate(['f' => 'file']);
            $upload->store('docs');
        }

        switch ($request->input('kind')) {
            case 'doc':
                $request->validate(['doc' => 'file']);
                $request->file('doc')->store('docs');
                break;
        }
    }

    public function validationInTheConditionItself(Request $request, array $rules)
    {
        if (Validator::make($request->all(), $rules)->fails()) {
            return back();
        }

        $request->file('doc')->store('docs');
    }

    public function everyBranchValidates(Request $request, $strict)
    {
        if ($strict) {
            $request->validate(['x' => 'file|mimes:png']);
        } else {
            $request->validate(['x' => 'file']);
        }

        $request->file('x')->store('a');
    }

    public function earlyReturnGuard(Request $request)
    {
        if (!$request->hasFile('f')) {
            return;
        }

        $request->validate(['f' => 'file']);
        $request->file('f')->store('x');
    }

    public function dynamicPropertyWithoutFileEvidence(Request $request)
    {
        // "order" is never used as a file input here, so ->store() is an ordinary model call.
        $request->order->store($request->all());
        $request->payload->move('a', 'b');
    }

    public function abortBranchDoesNotWeakenValidation(Request $request)
    {
        if (!$request->user()) {
            abort(403);
        } else {
            $request->validate(['x' => 'file']);
        }

        $request->file('x')->store('p');

        if (!$request->hasFile('y')) {
            exit;
        } else {
            $request->validate(['y' => 'file']);
        }

        $request->file('y')->store('p');
    }

    public function tryCatchThatRethrows(Request $request)
    {
        try {
            $request->validate(['doc' => 'file']);
        } catch (\Throwable $e) {
            throw $e;
        }

        $request->file('doc')->store('docs');
    }

    public function switchWhereEveryCaseValidates(Request $request, $kind)
    {
        switch ($kind) {
            case 'a':
                $request->validate(['a' => 'file']);
                break;
            default:
                $request->validate(['a' => 'file|mimes:png']);
        }

        $request->file('a')->store('docs');
    }

    public function validatorThatIsActuallyChecked(Request $request, array $rules)
    {
        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return back();
        }

        $request->file('doc')->store('docs');
    }

    public function rulesThatCoverTheUploadByNameOrByRule(Request $request)
    {
        $request->validate(['name' => 'required', 'photo' => ['image', 'max:2048']]);
        $request->file('photo')->store('photos');

        $request->validate(['attachments.*' => 'required']);
        $request->file('attachments')->store('docs');

        $request->validate(['upload' => 'required|mimes:pdf']);
        $request->file('upload')->store('docs');
    }

    public function rulesInAVariableWithCustomMessages(Request $request, array $rules)
    {
        $request->validate($rules, ['photo.required' => 'Please choose a photo']);
        $request->file('photo')->store('photos');

        $this->validate($request, $rules, ['photo.required' => 'Please choose a photo']);
        $request->file('photo')->store('photos');
    }

    public function compoundGuards(Request $request, array $rules, $other)
    {
        $v = Validator::make($request->all(), $rules);

        if ($v->fails() || $other) {
            return back();
        }

        $request->file('doc')->store('docs');

        if ($v->passes() && $other) {
            $request->file('doc')->store('more');
        }
    }

    public function notTheHttpRequest($guzzleRequest, $archiveRequest)
    {
        // Only $request / $req (or a Request-typed parameter) is the HTTP request.
        $guzzleRequest->file('a')->store('x');
        $archiveRequest->file('b')->move('y');
    }

    public function unrelatedTypedParametersAreNotAutoloaded(\App\Models\User $user, \App\Services\OrderService $service, Request $request)
    {
        $request->validate(['doc' => 'required|file']);
        $request->file('doc')->store('docs');
    }

    public function uploadMentionedOnlyByItsMetadata(Request $request, $logPath, $template, $dir)
    {
        $file = $request->file('f');
        file_put_contents($logPath, 'uploaded ' . $file->getClientOriginalName(), FILE_APPEND);
        copy($template, $dir . '/' . $file->getClientOriginalName());
    }

    public function everyBranchOfAnElseifChainValidates(Request $request, $flag, array $rules)
    {
        $v = Validator::make($request->all(), $rules);

        if ($flag) {
            $request->validate(['f' => 'required|file']);
        } elseif ($v->fails()) {
            abort(422);
        } else {
            $request->validate(['f' => 'required|file']);
        }

        $request->file('f')->store('x');
    }

    public function aliasedValidatorFacade(Request $request, array $rules)
    {
        $v = V::make($request->all(), ['doc' => 'required|file|mimes:pdf']);

        if ($v->fails()) {
            return back();
        }

        $request->file('doc')->store('x');
    }

    public function validatorMakeWithFileRules(Request $request)
    {
        Validator::make($request->all(), ['doc' => 'required|mimes:pdf'])->validate();
        $request->file('doc')->store('x');
    }

    public function objectsThatOnlyLookLikeDisks(Request $request, $storageManager, $dest)
    {
        // A model called File, and a "storage manager" service, are not the filesystem.
        File::copy($request->file('x'), $dest);
        $storageManager->put('k', $request->file('a'));
    }

    public function staticHelperGivenTheRequest(Request $request)
    {
        self::validateUpload($request);
        $request->file('f')->store('x');
    }

    public function helperHandedTheUpload(Request $request)
    {
        $this->validateImage($request->file('f'));
        $request->file('f')->store('x');
    }

    public function fileRuleWhenTheFieldNameIsNotKnown(Request $request, string $field)
    {
        $request->validate(['anything' => 'file|mimes:pdf']);
        $request->file($field)->store('x');
    }

    public function groupedImportOfAFormRequest(StoreGroupedRequest $request)
    {
        $request->file('doc')->store('docs');
    }

    public function aliasedGroupedImportOfAFormRequest(UpdateRequest $request)
    {
        $request->file('doc')->store('docs');
    }

    public function helperOnAnInjectedValidator(Request $request)
    {
        $this->uploadValidator->validateUpload($request);
        $request->file('doc')->store('docs');
    }

    public function staticValidatorValidate(Request $request, array $rules)
    {
        Validator::validate($request->all(), $rules);
        $request->file('doc')->store('docs');
    }

    public function abortIfTheValidatorFails(Request $request, array $rules)
    {
        $v = Validator::make($request->all(), $rules);
        abort_if($v->fails(), 422);
        $request->file('doc')->store('docs');
    }

    public function abortUnlessTheValidatorPasses(Request $request, array $rules)
    {
        $v = Validator::make($request->all(), $rules);
        abort_unless($v->passes(), 422);
        $request->file('doc')->store('docs');
    }

    public function customHelperGivenTheRequest(Request $request)
    {
        $this->validateUpload($request);
        $request->file('doc')->store('docs');
    }

    public function negatedPassesThatAborts(Request $request, array $rules)
    {
        $v = Validator::make($request->all(), $rules);

        if (!$v->passes()) {
            abort(422);
        }

        $request->file('doc')->store('docs');
    }

    public function writeInsideTheBranchThatPassed(Request $request, array $rules)
    {
        $v = Validator::make($request->all(), $rules);

        if ($v->passes()) {
            $request->file('doc')->store('docs');
        }
    }

    public function writeInsideTheElseOfFails(Request $request, array $rules)
    {
        $v = Validator::make($request->all(), $rules);

        if ($v->fails()) {
            return back()->withErrors($v);
        } else {
            $request->file('doc')->store('docs');
        }
    }

    public function switchWithEmptyFallThroughCases(Request $request, $type)
    {
        switch ($type) {
            case 'a':
            case 'b':
                $request->validate(['f' => 'file']);
                break;
            default:
                $request->validate(['f' => 'file|image']);
        }

        $request->file('f')->store('docs');
    }

    public function validatorFromHelperAndValidate(Request $request, array $rules)
    {
        validator($request->all(), $rules)->validate();
        $request->file('doc')->store('docs');
    }

    public function storageWritesThatAreNotUploads(Request $request, $content)
    {
        Storage::put('logs/app.log', $content);
        Storage::disk('local')->put('notes.txt', 'plain text');
        $cache = app('cache');
        $cache->put('key', $request->file('doc'));
    }

    public function unrelatedFileWrites(Request $request, $source)
    {
        file_put_contents(storage_path('app/log.txt'), 'plain text');
        copy($source, storage_path('app/copy.txt'));
        rename('a.txt', 'b.txt');
    }

    public function onlyChecksPresence(Request $request)
    {
        return $request->hasFile('avatar');
    }

    private function file(string $name)
    {
        return new \stdClass();
    }
}
