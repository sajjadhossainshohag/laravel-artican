<?php

namespace Fixtures\CsrfDisabled;

class VerifyCsrfToken
{
    protected $except = [
        'stripe/webhook',
        'api/*',
    ];

    protected $other = ['*'];
}

class EncryptCookies
{
    // A wildcard $except outside CSRF middleware is unrelated to CSRF.
    protected $except = ['*'];
}
