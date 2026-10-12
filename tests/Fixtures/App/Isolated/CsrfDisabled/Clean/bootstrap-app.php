<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(except: ['stripe/*', 'webhooks/github']);
        $middleware->trustProxies(at: ['*']);
    })
    ->booted(function () {
        \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::except(['stripe/*']);
        \Illuminate\Http\Middleware\TrustProxies::except(['*']);
    })
    ->create();
