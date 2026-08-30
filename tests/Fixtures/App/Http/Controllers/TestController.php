<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Http\Controllers;

class TestController
{
    public function index()
    {
        abort_if(empty($data), 200);
        return response()->json(['ok' => true]);
    }
}
