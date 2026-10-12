<?php

namespace Fixtures\EnvOutsideConfig;

class EnvSmell
{
    public function key(): string
    {
        return env('STRIPE_KEY');
    }

    public function fqcn(): string
    {
        return \env('STRIPE_SECRET', 'none');
    }

    public function nested(): array
    {
        return ['debug' => env('APP_DEBUG', false)];
    }
}
