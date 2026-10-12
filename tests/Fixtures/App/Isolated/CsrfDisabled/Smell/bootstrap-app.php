<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(except: ['*']);
    })
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(['/*']);
    })
    ->booted(function () {
        \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::except(['*']);
    })
    ->create();
