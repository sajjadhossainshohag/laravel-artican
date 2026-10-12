<?php

namespace Fixtures\CsrfDisabled;

class VerifyCsrfToken
{
    protected $except = [
        'stripe/webhook',
        '*',
    ];
}
