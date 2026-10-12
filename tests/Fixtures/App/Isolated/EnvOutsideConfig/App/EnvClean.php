<?php

namespace Fixtures\EnvOutsideConfig;

use Illuminate\Support\Env;

class EnvClean
{
    public function key(): string
    {
        return config('services.stripe.key');
    }

    public function method(): string
    {
        // env('IN_A_COMMENT') is not a call
        return $this->env('NOT_THE_HELPER');
    }

    public function facade(): mixed
    {
        return Env::get('NOT_THE_HELPER');
    }

    private function env(string $key): string
    {
        return $key;
    }
}
