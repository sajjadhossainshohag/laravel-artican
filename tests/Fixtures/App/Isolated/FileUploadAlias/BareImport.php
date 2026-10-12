<?php

namespace Fixtures\FileUploadAlias;

use Illuminate\Http\Request;
use Storage;

class BareImport
{
    public function store(Request $request)
    {
        $f = $request->file('f');
        Storage::put('p/' . $f->getClientOriginalName(), file_get_contents($f));
    }
}
