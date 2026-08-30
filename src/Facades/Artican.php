<?php

namespace SajjadHossain\Artican\Facades;

use Illuminate\Support\Facades\Facade;

class Artican extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \SajjadHossain\Artican\CheckRegistry::class;
    }
}
