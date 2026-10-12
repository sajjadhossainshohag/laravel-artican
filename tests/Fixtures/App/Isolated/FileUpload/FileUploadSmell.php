<?php

namespace Fixtures\FileUpload;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Storage as Disk;

class FileUploadSmell
{
    public function chained(Request $request)
    {
        $request->file('avatar')->store('avatars');                          // 1
    }

    public function viaVariable(Request $request)
    {
        $file = $request->file('doc');
        $file->move(public_path('uploads'), $file->getClientOriginalName()); // 2
    }

    public function viaStorage(Request $request)
    {
        Storage::putFile('docs', $request->file('doc'));                     // 3
    }

    public function loop(Request $request)
    {
        foreach ($request->allFiles() as $upload) {
            $upload->storeAs('files', $upload->getClientOriginalName());     // 4
        }
    }

    public function helper()
    {
        request()->file('photo')->storePublicly('photos');                   // 5
    }

    public function nullsafe(Request $request)
    {
        $request->file('photo')?->store('photos');                           // 6
    }

    public function disk(Request $request)
    {
        $file = $request->file('report');
        Storage::disk('s3')->putFileAs('reports', $file, 'report.pdf');     // 7
    }

    public function inClosure(Request $request)
    {
        return collect([1])->map(function () use ($request) {
            return $request->file('x')->store('x');                          // 8
        });
    }

    public function multiple(Request $request)
    {
        $files = $request->allFiles();
        foreach ($files as $f) {
            $f->store('docs');                                               // 10
        }
    }

    public function unrelatedValidate(Request $request, $order)
    {
        $order->validate();
        $request->file('x')->store('a');                                     // 11
    }

    public function validatedTooLate(Request $request)
    {
        $request->file('x')->store('a');                                     // 12
        $request->validate(['x' => 'file']);
    }

    public function indexed(Request $request)
    {
        $docs = $request->file('docs');
        $docs[0]->store('d');                                                // 13
    }
}

function standaloneUpload($request)
{
    $request->file('a')->store('a');                                         // 9
}

$arrow = fn (Request $r) => $r->file('f')->store('x');                       // 14

class DynamicAndConditional
{
    public function dynamicProperty(Request $request)
    {
        if ($request->hasFile('photo')) {
            $request->photo->store('photos');                                // 16
        }
    }

    public function conditionalValidation(Request $request)
    {
        if ($request->has('strict')) {
            $request->validate(['x' => 'file']);
        }

        $request->file('x')->store('a');                                     // 17
    }

    public function validationOnlyInsideAClosure(Request $request, $items)
    {
        $items->map(fn () => $this->validateFoo());
        $request->file('x')->store('a');                                     // 18
    }

    public function onlyReadsValidatedData(Request $request)
    {
        $request->validated();
        $request->file('x')->store('a');                                     // 19
    }

    public function validatedInOneBranchOnly(Request $request, $strict)
    {
        if ($strict) {
            $request->validate(['x' => 'file']);
        } else {
            logger('skipped validation');
        }

        $request->file('x')->store('a');                                     // 20
    }

    public function validatedOnlyInsideALoop(Request $request, array $rules)
    {
        foreach ($rules as $rule) {
            $request->validate([$rule => 'file']);
        }

        $request->file('x')->store('a');                                     // 21
    }
}

class TryCatchAndSwitch
{
    public function catchSwallowsTheFailure(Request $request)
    {
        try {
            $request->validate(['doc' => 'file']);
        } catch (\Throwable $e) {
            logger()->warning($e->getMessage());
        }

        $request->file('doc')->store('docs');                                // 26
    }

    public function switchWithoutDefault(Request $request, $kind)
    {
        switch ($kind) {
            case 'a':
                $request->validate(['a' => 'file']);
                break;
            case 'b':
                $request->validate(['b' => 'file']);
                break;
        }

        $request->file('a')->store('docs');                                  // 27
    }
}

class ValidatorsAndDisks
{
    public function validatorBuiltForOtherData(Request $request, $other, $rules)
    {
        $v = Validator::make($other, $rules);
        $request->file('doc')->store('docs');                                // 28
    }

    public function validatorNeverRun(Request $request, $rules)
    {
        validator($request->all(), $rules);
        $request->file('doc')->store('docs');                                // 29
    }

    public function failsButDoesNotStop(Request $request, $rules)
    {
        $v = Validator::make($request->all(), $rules);

        if ($v->fails()) {
            $errors = $v->errors();
        }

        $request->file('doc')->store('docs');                                // 32
    }

    public function unrelatedValidateHelper(Request $request, $order)
    {
        $this->validateOwnership($order);
        $request->file('doc')->store('docs');                                // 33
    }

    public function validateOnAnUnrelatedObject(Request $request, $requestLog)
    {
        $requestLog->validateSomething();
        $request->file('doc')->store('docs');                                // 34
    }

    public function writeInAMatchArmCondition(Request $request)
    {
        return match (true) {
            $request->file('f')->store('x') => 1,                            // 35
            default => 0,
        };
    }

    public function writeInAForLoopUpdate(Request $request)
    {
        for ($i = 0; $i < 2; $i++, $request->file('f')->store('x')) {        // 36
        }
    }

    public function validatesOtherFieldsOnly(Request $request)
    {
        $request->validate(['name' => 'required|string']);
        $request->file('doc')->store('docs');                                // 37
    }

    public function emptyRulesValidateNothing(Request $request)
    {
        $request->validate([]);
        $request->file('doc')->store('docs');                                // 40
    }

    public function filePutFacade(Request $request, $name)
    {
        File::put(public_path('u/' . $name), file_get_contents($request->file('f'))); // 41
    }

    public function propertyDisk(Request $request, $path)
    {
        $this->disk->put($path, $request->file('f'));                        // 42
    }

    public function unrelatedHelperGivenTheRequest(Request $request)
    {
        $this->validateQuota($request);
        $request->file('doc')->store('docs');                                // 43
    }

    public function typeThatMerelyEndsInRequest(\GuzzleHttp\Psr7\ServerRequest $request)
    {
        $request->file('doc')->store('docs');                                // 44
    }

    public function requiredIsNotAFileConstraint(Request $request)
    {
        $request->validate(['doc' => 'required']);
        $request->file('doc')->store('docs');                                // 45
    }

    public function fileRuleOnAnotherField(Request $request)
    {
        $request->validate(['avatar' => 'image', 'doc' => 'required']);
        $request->file('doc')->store('docs');                                // 46
    }

    public function emptyDefaultCase(Request $request, $type)
    {
        switch ($type) {
            case 1:
                $request->validate(['f' => 'required|file']);
                break;
            default:
        }

        $request->file('f')->store('x');                                     // 47
    }

    public function aliasedStorageFacade(Request $request)
    {
        $f = $request->file('f');
        Disk::put('p/' . $f->getClientOriginalName(), file_get_contents($f)); // 48
    }

    public function filesystemProperty(Request $request, $path)
    {
        $this->files->put($path, $request->file('f'));                       // 49
    }

    public function untypedRequestParameter($r)
    {
        $r->file('f')->store('x');                                           // 50
    }

    public function plainTypeRuleIsNotAFileConstraint(Request $request)
    {
        $request->validate(['photo' => 'required|string']);
        $request->file('photo')->store('x');                                 // 51
    }

    public function validatorForOtherFieldsOnly(Request $request)
    {
        Validator::make($request->all(), ['name' => 'required'])->validate();
        $request->file('doc')->store('x');                                   // 52
    }

    public function twoWritesOnOneLine(Request $request)
    {
        $request->file('a')->store('x'); $request->file('b')->store('y');    // 38, 38
    }

    public function storagePutWithUploadName(Request $request)
    {
        $file = $request->file('doc');
        Storage::disk('public')->put('x/' . $file->getClientOriginalName(), file_get_contents($file)); // 30
    }

    public function storagePutOfTheUpload(Request $request)
    {
        Storage::put('docs/a.pdf', $request->file('doc'));                   // 31
    }
}

class OtherWaysToPersist
{
    public function filePutContents(Request $request)
    {
        $file = $request->file('x');
        file_put_contents(storage_path($file->getClientOriginalName()), $file->get()); // 22
    }

    public function rawFilesSuperglobal()
    {
        move_uploaded_file($_FILES['f']['tmp_name'], '/var/www/uploads/' . $_FILES['f']['name']); // 23
    }

    public function closureOverCollection(Request $request)
    {
        collect($request->file('docs'))->each(fn ($doc) => $doc->store('d')); // 24
    }

    public function closureOverArrayMap(Request $request)
    {
        return array_map(fn ($f) => $f->storeAs('d', $f->getClientOriginalName()), $request->allFiles()); // 25
    }
}

class NullableTypes
{
    public function nestedOwnRequest(?Request $request)
    {
        return function (Request $req) {
            return $req->file('f')->store('x');                              // 15
        };
    }
}
